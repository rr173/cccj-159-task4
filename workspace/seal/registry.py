"""签名者注册表：签名者身份、签名密钥登记/轮换/撤权。

事件全部 append-only 写入 registry/events.log，每条由**当前服务私钥**
对事件体签名。进程恢复时逐条重放构造当前视图并验签；任一条签名/摘要
被篡改即整体拒绝（raise VerifyFailed），服务只读降级。

“撤权后的历史验真”语义：
- 密钥有 status: ACTIVE/ROTATED/REVOKED 及对应的时间点；
- 验真一条签名时看其 signed_at：密钥在该时刻有效（已登记且未撤权/未轮换）
  即历史有效 `then_valid:true`；
- 撤权后再用旧密钥提交的新签名以 SIGNER_KEY_REVOKED 拒收。
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from . import crypto
from .errors import Conflict, Forbidden, NotFound, VerifyFailed
from .util import append_fsync, canon, digest_json, file_lock, utcnow


@dataclass
class KeyView:
    kid: str
    signer_id: str
    public_key: str
    alg: str
    status: str            # ACTIVE / ROTATED / REVOKED
    registered_at: str
    rotated_at: str | None
    revoked_at: str | None
    replaced_by: str | None
    label: str

    def valid_at(self, ts: str) -> bool:
        if ts < self.registered_at:
            return False
        if self.status == "REVOKED" and self.revoked_at and ts >= self.revoked_at:
            return False
        if self.status == "ROTATED" and self.rotated_at and ts >= self.rotated_at:
            return False
        return True


class Registry:
    EVENTS_PATH = "events.log"
    SNAPSHOT_PATH = "snapshot.json"

    def __init__(self, store):
        self.s = store
        self.path = store.registry / self.EVENTS_PATH
        self.events: list[dict] = []
        self.signers: dict[str, dict] = {}
        self.keys: dict[str, KeyView] = {}

    # ------------------------------------------------------------ 重放
    def load(self):
        self.events = []
        self.signers = {}
        self.keys = {}
        history = {k["kid"]: k["public_key"]
                   for k in self.s.service_history()["keys"]}
        prev = None
        if self.path.exists():
            with open(self.path, "r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    body = {k: v for k, v in rec.items() if k not in
                            ("event_hash", "service_kid", "service_sig")}
                    problems = []
                    if rec.get("prev_hash") != prev:
                        problems.append({"code": "REGISTRY_CHAIN_BROKEN",
                                         "at": lineno})
                    if rec.get("event_hash") != digest_json(body):
                        problems.append({"code": "REGISTRY_EVENT_TAMPERED",
                                         "at": lineno})
                    pub = history.get(rec.get("service_kid"))
                    if not pub or not crypto.verify(
                            pub, canon(body), rec.get("service_sig", "")):
                        problems.append({"code": "REGISTRY_SIG_INVALID",
                                         "at": lineno,
                                         "kid": rec.get("service_kid")})
                    if problems:
                        raise VerifyFailed(problems)
                    prev = rec["event_hash"]
                    self.events.append(rec)
                    self._apply(rec)
        return self

    def _apply(self, rec: dict):
        t = rec["type"]
        if t == "signer.register":
            self.signers[rec["signer_id"]] = {
                "signer_id": rec["signer_id"], "name": rec["name"],
                "org": rec.get("org", ""), "status": "ACTIVE",
                "registered_at": rec["ts"], "deactivated_at": None,
                "label": rec.get("label", rec["name"])}
        elif t == "signer.deactivate":
            v = self.signers[rec["signer_id"]]
            v["status"] = "DEACTIVATED"
            v["deactivated_at"] = rec["ts"]
        elif t == "key.register":
            self.keys[rec["kid"]] = KeyView(
                kid=rec["kid"], signer_id=rec["signer_id"],
                public_key=rec["public_key"], alg=rec.get("alg", "Ed25519"),
                status="ACTIVE", registered_at=rec["ts"],
                rotated_at=None, revoked_at=None, replaced_by=None,
                label=rec.get("label", ""))
        elif t == "key.rotate":
            old = self.keys[rec["kid"]]
            old.status = "ROTATED"
            old.rotated_at = rec["ts"]
            old.replaced_by = rec["new_kid"]
            self.keys[rec["new_kid"]] = KeyView(
                kid=rec["new_kid"], signer_id=old.signer_id,
                public_key=rec["new_public_key"], alg="Ed25519",
                status="ACTIVE", registered_at=rec["ts"],
                rotated_at=None, revoked_at=None, replaced_by=None,
                label=rec.get("label", "轮换密钥"))
        elif t == "key.revoke":
            kv = self.keys[rec["kid"]]
            kv.status = "REVOKED"
            kv.revoked_at = rec["ts"]

    # ------------------------------------------------------------ 追加
    def _emit(self, etype: str, actor: str, fields: dict) -> dict:
        with file_lock(self.s.lock_path("registry")):
            prev = self.events[-1]["event_hash"] if self.events else None
            body = {"type": etype, "ts": utcnow(), "actor": actor,
                    "prev_hash": prev, **fields}
            rec = dict(body)
            rec["event_hash"] = digest_json(body)
            svc = self.s.service_public()
            rec["service_kid"] = svc["kid"]
            rec["service_sig"] = crypto.sign(self.s.service_priv, canon(body))
            append_fsync(self.path, (json.dumps(
                rec, ensure_ascii=False, sort_keys=True) + "\n").encode())
            self.events.append(rec)
            self._apply(rec)
            self._write_snapshot()
            return rec

    def _write_snapshot(self):
        snap = self.snapshot()
        from .util import write_json
        write_json(self.s.registry / self.SNAPSHOT_PATH, snap)

    # ------------------------------------------------------------ 操作
    def register_signer(self, signer_id: str, name: str, public_key: str,
                        actor: str = "admin", org: str = "",
                        label: str = "", kid: str | None = None) -> dict:
        with file_lock(self.s.lock_path("registry")):
            if signer_id in self.signers:
                raise Conflict("SIGNER_EXISTS",
                               f"签名者 {signer_id} 已存在",
                               {"signer_id": signer_id})
            kid = kid or f"key_{signer_id}_0"
            if kid in self.keys:
                raise Conflict("KEY_EXISTS", f"密钥 {kid} 已存在")
            self._emit("signer.register", actor,
                       {"signer_id": signer_id, "name": name, "org": org,
                        "label": label or name})
            self._emit("key.register", actor,
                       {"kid": kid, "signer_id": signer_id,
                        "public_key": public_key, "label": label or name})
            return {"signer_id": signer_id, "kid": kid,
                    "public_key": public_key}

    def deactivate_signer(self, signer_id: str, actor: str = "admin",
                          reason: str = ""):
        self._require_signer(signer_id)
        return self._emit("signer.deactivate", actor,
                          {"signer_id": signer_id, "reason": reason})

    def register_key(self, signer_id: str, public_key: str,
                     kid: str | None = None, actor: str = "admin",
                     label: str = "") -> str:
        self._require_signer(signer_id)
        kid = kid or f"key_{signer_id}_{len([1 for k in self.keys.values() if k.signer_id==signer_id])}"
        if kid in self.keys:
            raise Conflict("KEY_EXISTS", f"密钥 {kid} 已存在")
        self._emit("key.register", actor,
                   {"kid": kid, "signer_id": signer_id,
                    "public_key": public_key, "label": label})
        return kid

    def rotate_key(self, kid: str, new_public_key: str,
                   new_kid: str | None = None, actor: str = "admin",
                   label: str = "") -> str:
        kv = self._require_key(kid)
        if kv.status != "ACTIVE":
            raise Conflict("KEY_NOT_ACTIVE",
                           f"密钥 {kid} 当前状态 {kv.status}，不可轮换",
                           {"kid": kid, "status": kv.status})
        new_kid = new_kid or f"{kid}_r{sum(1 for k in self.keys if k.startswith(kid))+1}"
        if new_kid in self.keys:
            raise Conflict("KEY_EXISTS", f"新密钥 {new_kid} 已存在")
        self._emit("key.rotate", actor,
                   {"kid": kid, "new_kid": new_kid,
                    "new_public_key": new_public_key, "label": label})
        return new_kid

    def revoke_key(self, kid: str, actor: str = "admin", reason: str = ""):
        self._require_key(kid)
        return self._emit("key.revoke", actor,
                          {"kid": kid, "reason": reason})

    # ------------------------------------------------------------ 查询
    def _require_signer(self, signer_id: str) -> dict:
        v = self.signers.get(signer_id)
        if not v:
            raise NotFound("SIGNER_NOT_FOUND", f"签名者 {signer_id} 不存在")
        return v

    def _require_key(self, kid: str) -> KeyView:
        kv = self.keys.get(kid)
        if not kv:
            raise NotFound("KEY_NOT_FOUND", f"密钥 {kid} 不存在")
        return kv

    def key_for_signing(self, kid: str) -> KeyView:
        """签名提交时校验：密钥必须当前 ACTIVE（撤权/轮换后拒收新签名）。"""
        kv = self._require_key(kid)
        if kv.status == "REVOKED":
            raise Forbidden("SIGNER_KEY_REVOKED",
                            f"密钥 {kid} 已撤权（{kv.revoked_at}），"
                            "撤权后的新签名一律拒绝",
                            {"kid": kid, "revoked_at": kv.revoked_at})
        if kv.status == "ROTATED":
            raise Forbidden("SIGNER_KEY_ROTATED",
                            f"密钥 {kid} 已轮换（{kv.rotated_at}），"
                            "请使用新密钥签名",
                            {"kid": kid, "rotated_at": kv.rotated_at,
                             "replaced_by": kv.replaced_by})
        signer = self.signers[kv.signer_id]
        if signer["status"] != "ACTIVE":
            raise Forbidden("SIGNER_DEACTIVATED",
                            f"签名者 {kv.signer_id} 已停用")
        return kv

    def signer_summary(self) -> list[dict]:
        out = []
        for sid, v in sorted(self.signers.items()):
            keys = [self._key_dict(k) for k in self.keys.values()
                    if k.signer_id == sid]
            d = dict(v)
            d["keys"] = sorted(keys, key=lambda x: x["kid"])
            out.append(d)
        return out

    @staticmethod
    def _key_dict(k: KeyView) -> dict:
        return {"kid": k.kid, "signer_id": k.signer_id,
                "public_key": k.public_key, "alg": k.alg, "status": k.status,
                "registered_at": k.registered_at,
                "rotated_at": k.rotated_at, "revoked_at": k.revoked_at,
                "replaced_by": k.replaced_by, "label": k.label}

    def snapshot(self) -> dict:
        return {"schema": "signer-registry-snapshot/1",
                "generated_at": utcnow(),
                "signers": self.signer_summary(),
                "events": self.events}

    def find_key(self, kid: str) -> KeyView | None:
        return self.keys.get(kid)

    def snapshot_digest(self) -> str:
        return digest_json({"schema": "signer-registry-snapshot/1",
                            "signers": self.signer_summary(),
                            "events": self.events})

    def verify_signature_at(self, signer_id: str, kid: str, signed_at: str):
        """验真时的历史有效性判定（撤权不影响撤权前的历史签名）。"""
        signer = self.signers.get(signer_id)
        kv = self.keys.get(kid)
        if not signer or not kv or kv.signer_id != signer_id:
            return False, "UNKNOWN_SIGNER_OR_KEY", None
        key_dict = self._key_dict(kv)
        if not kv.valid_at(signed_at):
            if kv.status == "REVOKED":
                return False, "KEY_WAS_REVOKED_AT_SIGN_TIME", key_dict
            if kv.status == "ROTATED":
                return False, "KEY_WAS_ROTATED_AT_SIGN_TIME", key_dict
            return False, "KEY_NOT_YET_VALID_AT_SIGN_TIME", key_dict
        return True, None, key_dict
