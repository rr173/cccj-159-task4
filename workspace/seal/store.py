"""落盘存储层：目录布局、初始化、服务密钥、append-only 审计链。

目录布局（根 STORE）：
    config.json             存储级配置（模式/创建时间，不可变）
    service/private.pem     当前服务私钥（hex seed；0600）
    service/history.json    服务公钥轮换链（append-only，新密钥自签衔接）
    registry/events.log     签名者/签名密钥事件（append-only，服务密钥签名）
    audit/log.jsonl         审计链（prev_hash 串接，记录级 SHA-256）
    journal/journal.log     崩溃恢复日志（seal/publish 的 INTENT/DONE）
    locks/                  fcntl 锁文件
    cas/<aa>/<64hex>        内容寻址 blob（artifact）
    chunks/<aa>/<64hex>     分块 blob（PUT 时校验摘要）
    uploads/<sid>.json      分块上传会话（每块落盘后原子写）
    assemblies/<aid>/       组装中状态
    envelopes/<eid>/        已封装信封（seal 后目录冻结）
    names/<release_name>    发布名指针（指向 publication.json）

不变量：
- 所有状态变更先写审计/事件 append 记录并 fsync，再做目录改名；
- envelope 目录名即内容 id（manifest 规范摘要），sealed 目录一次 rename 到位；
- 审计链断裂/篡改时由 Service 检测并只读降级启动。
"""
from __future__ import annotations

import json
import os
import secrets
import tempfile
from pathlib import Path

from . import crypto
from .errors import BadRequest
from .util import (append_fsync, canon, file_lock, read_json, sha256_hex,
                   sha256_file, utcnow, write_json)

SERVICE_KEY_ID = "service-genesis"


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(10)}"


class Store:
    def __init__(self, root: str):
        self.root = Path(root).resolve()
        self.blobs = self.root / "cas"
        self.chunks = self.root / "chunks"
        self.uploads = self.root / "uploads"
        self.assemblies = self.root / "assemblies"
        self.envelopes = self.root / "envelopes"
        self.names = self.root / "names"
        self.locks = self.root / "locks"
        self.svc_dir = self.root / "service"
        self.registry = self.root / "registry"
        self.audit_dir = self.root / "audit"
        self.journal_dir = self.root / "journal"
        self._sk = None  # 当前服务私钥（进程内缓存）

    def ensure_dirs(self):
        for p in (self.blobs, self.chunks, self.uploads, self.assemblies,
                  self.envelopes, self.names, self.locks, self.svc_dir,
                  self.registry, self.audit_dir, self.journal_dir):
            p.mkdir(parents=True, exist_ok=True)

    def blob_path(self, digest_hex: str) -> Path:
        return self.blobs / digest_hex[:2] / digest_hex

    def chunk_path(self, digest_hex: str) -> Path:
        return self.chunks / digest_hex[:2] / digest_hex

    def assembly_path(self, aid: str) -> Path:
        return self.assemblies / aid

    def envelope_path(self, eid: str) -> Path:
        return self.envelopes / eid

    def name_path(self, name: str) -> Path:
        return self.names / name

    def upload_path(self, sid: str) -> Path:
        return self.uploads / f"{sid}.json"

    def lock_path(self, key: str) -> Path:
        return self.locks / f"{key}.lock"

    # ---------------------------------------------------------------- blob
    def put_blob_data(self, data: bytes, expect_digest: str | None = None) -> str:
        dg = sha256_hex(data)
        self._check_digest(dg, expect_digest)
        self._write_cas(self.blob_path(dg), data)
        return dg

    def put_blob_file(self, src, expect_digest: str | None = None) -> str:
        dg = sha256_file(src)
        self._check_digest(dg, expect_digest)
        dst = self.blob_path(dg)
        if not dst.exists():
            self._stream_to_cas(src, dst)
        return dg

    @staticmethod
    def _check_digest(actual: str, expected: str | None):
        if expected and actual != expected:
            raise BadRequest("DIGEST_MISMATCH",
                             f"内容摘要 {actual} 与声明 {expected} 不符",
                             {"actual": actual, "expected": expected})

    @staticmethod
    def _write_cas(path: Path, data: bytes):
        if path.exists():
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            _silent_unlink(tmp)
            raise

    @staticmethod
    def _stream_to_cas(src, dst: Path):
        dst.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=dst.parent)
        try:
            with open(src, "rb") as fi, os.fdopen(fd, "wb") as fo:
                while True:
                    b = fi.read(1 << 20)
                    if not b:
                        break
                    fo.write(b)
                fo.flush()
                os.fsync(fo.fileno())
            os.replace(tmp, dst)
        except BaseException:
            _silent_unlink(tmp)
            raise

    # ------------------------------------------------------------ 服务密钥
    def init_store(self) -> bool:
        """初始化存储（幂等）。首次写入创世服务密钥与配置，返回是否新建。"""
        self.ensure_dirs()
        cfg = self.root / "config.json"
        if cfg.exists():
            self._load_service_key()
            return False
        priv, pub = crypto.generate_keypair()
        write_json(self.svc_dir / "private.pem",
                   {"kid": SERVICE_KEY_ID, "priv_hex": priv})
        os.chmod(self.svc_dir / "private.pem", 0o600)
        write_json(self.svc_dir / "history.json", {
            "schema": "service-trust-chain/1",
            "keys": [{"kid": SERVICE_KEY_ID, "public_key": pub,
                      "rotated_at": None, "created_at": utcnow(),
                      "note": "创世服务密钥"}],
        })
        write_json(cfg, {"schema": "design-sign-store/1",
                         "created_at": utcnow()})
        self._sk = priv
        return True

    def _load_service_key(self):
        rec = read_json(self.svc_dir / "private.pem")
        self._sk = rec["priv_hex"]
        return rec

    @property
    def service_priv(self) -> str:
        if self._sk is None:
            self._load_service_key()
        return self._sk

    def service_public(self) -> dict:
        return self.service_history()["keys"][-1]

    def service_history(self) -> dict:
        return read_json(self.svc_dir / "history.json")

    def rotate_service_key(self, note: str = "") -> dict:
        """轮换服务密钥：新私钥落盘，history 追加由新密钥自签的衔接记录。

        离线验证者持有任意一代公钥即可沿自签链接纳后续公钥（轮换链本身
        也要与 envelope 上的 kid 匹配，被篡改的公钥记录验签失败）。
        """
        with file_lock(self.lock_path("service-key")):
            history = self.service_history()
            old = history["keys"][-1]
            priv, pub = crypto.generate_keypair()
            kid = f"service-rot-{len(history['keys'])}"
            ts = utcnow()
            body = {"kid": kid, "public_key": pub, "rotated_at": ts,
                    "created_at": ts, "note": note or "服务密钥轮换",
                    "prev_kid": old["kid"],
                    "prev_public_key": old["public_key"]}
            body["self_signature"] = crypto.sign(priv, canon({
                "kid": kid, "public_key": pub,
                "prev_kid": body["prev_kid"],
                "prev_public_key": body["prev_public_key"],
                "rotated_at": ts}))
            history["keys"].append(body)
            write_json(self.svc_dir / "history.json", history)
            write_json(self.svc_dir / "private.pem",
                       {"kid": kid, "priv_hex": priv})
            os.chmod(self.svc_dir / "private.pem", 0o600)
            self._sk = priv
            return body

    # ------------------------------------------------------------ 审计链
    def append_audit(self, action: str, detail: dict | None = None,
                     actor: str = "system", result: str = "OK",
                     reason: str | None = None) -> dict:
        """追加一条审计记录（prev_hash 链），fsync 后返回记录。"""
        path = self.audit_dir / "log.jsonl"
        entries = self.audit_entries()
        prev = entries[-1]["hash"] if entries else None
        rec = {"id": len(entries) + 1, "ts": utcnow(), "actor": actor,
               "action": action, "result": result, "reason": reason,
               "detail": detail or {}}
        rec["prev_hash"] = prev
        rec["hash"] = sha256_hex(canon({k: v for k, v in rec.items()
                                         if k != "hash"}))
        append_fsync(path, (json.dumps(rec, ensure_ascii=False,
                                       sort_keys=True) + "\n").encode())
        return rec

    def _iter_audit(self):
        path = self.audit_dir / "log.jsonl"
        if not path.exists():
            return
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def audit_entries(self) -> list[dict]:
        return list(self._iter_audit())

    def verify_audit_chain(self) -> dict:
        """校验审计链完整性。返回 {ok, broken_at, total}。"""
        prev = None
        total = 0
        for total, rec in enumerate(self.audit_entries(), start=1):
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("prev_hash") != prev or \
                    rec.get("hash") != sha256_hex(canon(body)):
                return {"ok": False, "broken_at": total, "total": total}
            prev = rec["hash"]
        return {"ok": True, "broken_at": None, "total": total}

    # ------------------------------------------------------------ journal
    def journal_append(self, kind: str, payload: dict) -> dict:
        rec = {"ts": utcnow(), "kind": kind, "payload": payload}
        append_fsync(self.journal_dir / "journal.log",
                     (json.dumps(rec, ensure_ascii=False) + "\n").encode())
        return rec

    def journal_entries(self) -> list[dict]:
        path = self.journal_dir / "journal.log"
        if not path.exists():
            return []
        out = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def journal_clear(self):
        p = self.journal_dir / "journal.log"
        if p.exists():
            p.unlink()


def _silent_unlink(p):
    try:
        os.unlink(p)
    except FileNotFoundError:
        pass
