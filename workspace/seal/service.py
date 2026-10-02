"""领域核心：内容寻址发布信封的组装、封装、多方签名与原子发布。

关键不变量：
1. 同一内容（规范 manifest）→ 同一 envelope id（SHA-256），并发封装在
   全局锁 + 目录存在性检查下收敛为唯一一个信封（绝不产生两个有效信封）。
2. seal 是“临时目录组装 → 一次性 rename”的原子动作；崩溃后由 recover()
   依据 journal 幂等收尾，半成品 temp 目录被清理。
3. publish 两阶段：INTENT 落盘 fsync → 原子写 publication.json 与名字指针
   → DONE；进程恢复幂等续做。同名不同内容以 NAME_CONFLICT 拒收。
4. 撤权/轮换只影响新签名；历史签名按 signed_at 判定 then_valid。
5. 任何摘要、签名、分块、Merkle 证明被篡改 → verify 返回失败并写审计，
   服务自身操作（seal/sign/publish）在内部一致性校验失败时拒绝并留痕。
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from . import crypto, merkle
from .errors import BadRequest, Conflict, Forbidden, NotFound, SealError
from .registry import Registry
from .store import Store, new_id
from .util import (canon, digest_json, file_lock, read_json,
                   sha256_hex, sha256_file, utcnow, write_bytes, write_json)

ARTIFACT_KINDS = ("netlist", "constraint", "module", "signoff")
ASSEMBLY_STATES = ("OPEN", "SEALING", "SEALED", "FAILED")
ENVELOPE_STATES = ("SEALED", "PUBLISHED")


class SealService:
    def __init__(self, root: str):
        self.s = Store(root)
        self.s.init_store()
        self.registry = Registry(self.s).load()
        self.read_only = False
        self.boot_issues: list[dict] = []
        self._startup_checks()

    # ================================================================ 启动
    def _startup_checks(self):
        chain = self.s.verify_audit_chain()
        if not chain["ok"]:
            self.read_only = True
            self.boot_issues.append(
                {"code": "AUDIT_CHAIN_BROKEN", "at": chain["broken_at"]})
        try:
            self.recover()
        except SealError as e:
            self.read_only = True
            self.boot_issues.append({"code": e.code, "message": e.message})

    def _writable(self):
        if self.read_only:
            raise Forbidden("SERVICE_READ_ONLY",
                            "存储完整性校验未通过（审计链/恢复异常），"
                            "服务已只读降级", {"issues": self.boot_issues})

    def health(self) -> dict:
        return {"read_only": self.read_only, "boot_issues": self.boot_issues,
                "audit": self.s.verify_audit_chain(),
                "service_kid": self.s.service_public()["kid"]}

    # ================================================================ 审计
    def audit(self, action, detail=None, actor="system", result="OK",
              reason=None) -> dict:
        return self.s.append_audit(action, detail, actor, result, reason)

    # ================================================================ 组装
    def create_assembly(self, release_name: str, created_by: str,
                        project: str = "", note: str = "",
                        parent_envelope: str | None = None,
                        required_signers: list[str] | None = None,
                        idempotency_key: str | None = None) -> dict:
        """创建组装（待发布变更的网表/约束/模块清单/签核记录的容器）。"""
        self._writable()
        with file_lock(self.s.lock_path("assemblies")):
            if idempotency_key:
                for p in self.s.assemblies.glob("*/state.json"):
                    st = read_json(p)
                    if st.get("idempotency_key") == idempotency_key:
                        st["replayed"] = True
                        return st
            if parent_envelope and not self.s.envelope_path(
                    parent_envelope).is_dir():
                raise NotFound("PARENT_ENVELOPE_NOT_FOUND",
                               f"父信封 {parent_envelope} 不存在")
            aid = new_id("asm")
            d = self.s.assembly_path(aid)
            d.mkdir(parents=True)
            state = {
                "assembly_id": aid, "schema": "assembly-state/1",
                "release_name": release_name, "project": project,
                "note": note, "created_by": created_by,
                "created_at": utcnow(), "state": "OPEN",
                "parent_envelope": parent_envelope,
                "required_signers": required_signers or [],
                "artifacts": [], "chunked_files": [],
                "idempotency_key": idempotency_key,
                "envelope_id": None}
            self._save_state(state)
            self.audit("assembly.create", {"assembly_id": aid,
                                           "release_name": release_name},
                       created_by)
            return state

    def _state_path(self, aid) -> Path:
        return self.s.assembly_path(aid) / "state.json"

    def _load_assembly(self, aid) -> dict:
        p = self._state_path(aid)
        if not p.exists():
            raise NotFound("ASSEMBLY_NOT_FOUND", f"组装 {aid} 不存在",
                           {"assembly_id": aid})
        return read_json(p)

    def _save_state(self, state: dict):
        write_json(self._state_path(state["assembly_id"]), state)

    def add_artifact_inline(self, aid: str, kind: str, name: str,
                            content: bytes | str | dict,
                            content_type: str = "application/octet-stream",
                            by: str = "") -> dict:
        """登记小体积制品（直接内容入库，如 JSON 约束/模块清单/签核记录）。"""
        self._writable()
        if kind not in ARTIFACT_KINDS:
            raise BadRequest("BAD_ARTIFACT_KIND",
                             f"kind 必须是 {ARTIFACT_KINDS} 之一")
        if isinstance(content, (dict, list)):
            data = canon(content)
            content_type = "application/json"
        elif isinstance(content, str):
            data = content.encode("utf-8")
        else:
            data = content
        with file_lock(self.s.lock_path(f"asm:{aid}")):
            state = self._load_assembly(aid)
            self._require_open(state)
            self._require_unique_name(state, name)
            dg = self.s.put_blob_data(data)
            art = {"kind": kind, "name": name, "digest": dg,
                   "size": len(data), "content_type": content_type,
                   "storage": "inline", "added_at": utcnow(), "added_by": by}
            state["artifacts"].append(art)
            self._save_state(state)
            self.audit("assembly.artifact.add",
                       {"assembly_id": aid, "name": name, "digest": dg}, by)
            return art

    @staticmethod
    def _require_open(state):
        if state["state"] != "OPEN":
            raise Conflict("ASSEMBLY_NOT_OPEN",
                           f"组装当前状态 {state['state']}，不可修改",
                           {"state": state["state"]})

    @staticmethod
    def _require_unique_name(state, name):
        names = {a["name"] for a in state["artifacts"]} | \
                {f["name"] for f in state.get("chunked_files", [])}
        if name in names:
            raise Conflict("ARTIFACT_NAME_EXISTS",
                           f"制品名 {name} 在该组装中已存在", {"name": name})

    # ================================================================ 分块上传
    def start_upload(self, aid: str, kind: str, name: str, size: int,
                     chunk_size: int = 1 << 20,
                     content_type: str = "application/octet-stream",
                     by: str = "", idempotency_key: str | None = None) -> dict:
        """开启分块上传会话。元数据立即落盘，后续每块落盘后更新索引。"""
        self._writable()
        if kind not in ARTIFACT_KINDS:
            raise BadRequest("BAD_ARTIFACT_KIND",
                             f"kind 必须是 {ARTIFACT_KINDS} 之一")
        if not isinstance(size, int) or size <= 0:
            raise BadRequest("BAD_SIZE", "size 必须为正整数（字节）")
        if chunk_size < 4096 or chunk_size > 64 << 20:
            raise BadRequest("BAD_CHUNK_SIZE", "chunk_size 范围 4096~64MiB")
        with file_lock(self.s.lock_path(f"asm:{aid}")):
            state = self._load_assembly(aid)
            self._require_open(state)
            self._require_unique_name(state, name)
            sid = new_id("upl")
            total = (size + chunk_size - 1) // chunk_size
            sess = {
                "session_id": sid, "assembly_id": aid, "kind": kind,
                "name": name, "size": size, "chunk_size": chunk_size,
                "content_type": content_type, "by": by,
                "created_at": utcnow(), "updated_at": utcnow(),
                "status": "OPEN", "idempotency_key": idempotency_key,
                "total_chunks": total,
                "chunks": [{"seq": i, "size": min(chunk_size,
                         size - i * chunk_size), "digest": None,
                         "received": False} for i in range(total)]}
            self._save_upload(sess)
            self.audit("upload.start", {"session_id": sid, "assembly_id": aid,
                                        "name": name, "size": size}, by)
            return self._upload_public(sess)

    def _save_upload(self, sess: dict):
        sess["updated_at"] = utcnow()
        write_json(self.s.upload_path(sess["session_id"]), sess)

    def _load_upload(self, sid) -> dict:
        p = self.s.upload_path(sid)
        if not p.exists():
            raise NotFound("UPLOAD_NOT_FOUND", f"上传会话 {sid} 不存在",
                           {"session_id": sid})
        return read_json(p)

    @staticmethod
    def _upload_public(sess: dict) -> dict:
        return {k: v for k, v in sess.items()}

    def upload_status(self, sid: str) -> dict:
        return self._upload_public(self._load_upload(sid))

    def put_chunk(self, sid: str, seq: int, data: bytes,
                  digest: str | None = None) -> dict:
        """写入单个分块。

        - 摘要不符/大小不符/越界 → 拒绝并审计（分块被篡改）；
        - 同一 seq 以相同摘要重传 → 幂等（断点续传）；
        - 同一 seq 以不同摘要重传 → CHUNK_CONFLICT（防同一槽位被换内容）。
        """
        self._writable()
        with file_lock(self.s.lock_path(f"upl:{sid}")):
            sess = self._load_upload(sid)
            if sess["status"] != "OPEN":
                raise Conflict("UPLOAD_NOT_OPEN",
                               f"上传会话状态 {sess['status']}")
            if not isinstance(seq, int) or seq < 0 or \
                    seq >= sess["total_chunks"]:
                raise BadRequest("BAD_CHUNK_SEQ",
                                 f"seq 越界（0..{sess['total_chunks']-1}）",
                                 {"seq": seq})
            want = sess["chunks"][seq]
            if len(data) != want["size"]:
                self._reject_chunk(sess, seq, "CHUNK_SIZE_MISMATCH",
                                   {"expected": want["size"],
                                    "actual": len(data)})
            actual = sha256_hex(data)
            if digest and actual != digest:
                self._reject_chunk(sess, seq, "CHUNK_DIGEST_MISMATCH",
                                   {"declared": digest, "actual": actual})
            if want["received"]:
                if want["digest"] == actual:
                    return {"seq": seq, "digest": actual, "replayed": True,
                            "received": True}
                self._reject_chunk(sess, seq, "CHUNK_CONFLICT",
                                   {"stored": want["digest"],
                                    "actual": actual})
            # 落 CAS（chunks 区），再更新索引
            cp = self.s.chunk_path(actual)
            if not cp.exists():
                cp.parent.mkdir(parents=True, exist_ok=True)
                write_bytes(cp, data)
            want["digest"] = actual
            want["received"] = True
            self._save_upload(sess)
            return {"seq": seq, "digest": actual, "received": True,
                    "remaining": sum(1 for c in sess["chunks"]
                                     if not c["received"])}

    def _reject_chunk(self, sess, seq, code, detail):
        self.audit("upload.chunk.rejected",
                   {"session_id": sess["session_id"], "seq": seq,
                    **detail}, sess.get("by", "system"), "REJECT", code)
        raise BadRequest(code, f"分块 {seq} 校验失败：{code}", detail)

    def abort_upload(self, sid: str, by: str = "") -> dict:
        with file_lock(self.s.lock_path(f"upl:{sid}")):
            sess = self._load_upload(sid)
            if sess["status"] == "OPEN":
                sess["status"] = "ABORTED"
                self._save_upload(sess)
                self.audit("upload.abort", {"session_id": sid}, by)
            return self._upload_public(sess)

    def complete_upload(self, sid: str) -> dict:
        """全部分块到齐后：逐块重算摘要（防块在盘上被改），登记制品索引。"""
        self._writable()
        with file_lock(self.s.lock_path(f"upl:{sid}")):
            sess = self._load_upload(sid)
            if sess["status"] == "COMPLETED":
                return self._upload_public(sess)
            missing = [c["seq"] for c in sess["chunks"] if not c["received"]]
            if missing:
                raise Conflict("UPLOAD_INCOMPLETE",
                               f"尚有 {len(missing)} 个分块未到齐",
                               {"missing": missing[:100]})
            # 逐块回读重算摘要：任一在盘上被篡改/丢失即拒绝并留痕
            for c in sess["chunks"]:
                cp = self.s.chunk_path(c["digest"])
                if not cp.exists():
                    self.audit("verify.chunk.failed",
                               {"session_id": sid, "seq": c["seq"],
                                "digest": c["digest"]},
                               sess.get("by", "system"), "REJECT",
                               "CHUNK_MISSING")
                    raise Conflict("CHUNK_MISSING",
                                   f"分块 {c['seq']} 的 blob 丢失",
                                   {"seq": c["seq"]})
                actual = sha256_file(cp)
                if actual != c["digest"]:
                    self.audit("verify.chunk.failed",
                               {"session_id": sid, "seq": c["seq"],
                                "expected": c["digest"], "actual": actual},
                               sess.get("by", "system"), "REJECT",
                               "CHUNK_TAMPERED")
                    raise Conflict("CHUNK_TAMPERED",
                                   f"分块 {c['seq']} 摘要不符（疑似被篡改）",
                                   {"seq": c["seq"], "expected": c["digest"],
                                    "actual": actual})
            aid = sess["assembly_id"]
            with file_lock(self.s.lock_path(f"asm:{aid}")):
                state = self._load_assembly(aid)
                self._require_open(state)
                names = {a["name"] for a in state["artifacts"]} | \
                        {f["name"] for f in state.get("chunked_files", [])}
                if sess["name"] in names:
                    raise Conflict("ARTIFACT_NAME_EXISTS",
                                   f"制品名 {sess['name']} 已存在")
                # 分块全部通过后，把完整文件落 CAS，artifact.digest 与内联
                # 制品口径一致（整文件内容摘要）；chunk_index 用于逐块定位
                full = self.s.blob_path("__reassemble_tmp__")
                import os, tempfile as _tf
                fd, tmp = _tf.mkstemp(prefix=".reassemble-",
                                      dir=self.s.blobs)
                total_seen = 0
                with os.fdopen(fd, "wb") as fo:
                    for c in sess["chunks"]:
                        with open(self.s.chunk_path(c["digest"]), "rb") as fi:
                            while True:
                                b = fi.read(1 << 20)
                                if not b:
                                    break
                                fo.write(b)
                                total_seen += len(b)
                if total_seen != sess["size"]:
                    os.unlink(tmp)
                    raise Conflict("REASSEMBLE_SIZE_MISMATCH",
                                   "重组文件大小与声明不符",
                                   {"expected": sess["size"],
                                    "actual": total_seen})
                file_digest = sha256_file(tmp)
                target = self.s.blob_path(file_digest)
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    os.unlink(tmp)
                else:
                    os.replace(tmp, target)
                entry = {"kind": sess["kind"], "name": sess["name"],
                         "digest": file_digest, "size": sess["size"],
                         "content_type": sess["content_type"],
                         "storage": "chunked", "session_id": sid,
                         "chunk_size": sess["chunk_size"],
                         "chunks": [{"seq": c["seq"], "size": c["size"],
                                     "digest": c["digest"]}
                                    for c in sess["chunks"]],
                         "added_at": utcnow(), "added_by": sess.get("by", "")}
                state["artifacts"].append(entry)
                state.setdefault("chunked_files", []).append(
                    {"name": sess["name"], "session_id": sid})
                self._save_state(state)
            sess["status"] = "COMPLETED"
            self._save_upload(sess)
            self.audit("upload.complete",
                       {"session_id": sid, "assembly_id": aid,
                        "name": sess["name"], "digest": file_digest},
                       sess.get("by", "system"))
            return self._upload_public(sess)

    def get_assembly(self, aid: str) -> dict:
        state = self._load_assembly(aid)
        state["uploads"] = [
            self._upload_public(read_json(p))
            for p in sorted(self.s.uploads.glob("*.json"))
            if read_json(p).get("assembly_id") == aid]
        return state

    def list_assemblies(self) -> list[dict]:
        out = []
        for p in sorted(self.s.assemblies.glob("*/state.json")):
            out.append(read_json(p))
        return out

    # ================================================================ 封装
    def seal(self, aid: str, by: str = "") -> dict:
        """把组装内容封装成内容寻址信封（原子；并发同内容收敛为同一信封）。"""
        self._writable()
        with file_lock(self.s.lock_path("seal")):
            state = self._load_assembly(aid)
            if state["state"] == "SEALED":
                env = self._load_envelope(state["envelope_id"])
                env["replayed"] = True
                return env
            self._require_open(state)
            if not state["artifacts"]:
                raise Conflict("EMPTY_ASSEMBLY", "组装不含任何制品，不可封装")
            # 未完成的分块上传不允许封装
            for p in self.s.uploads.glob("*.json"):
                u = read_json(p)
                if u.get("assembly_id") == aid and u["status"] == "OPEN":
                    raise Conflict("UPLOAD_STILL_OPEN",
                                   f"分块上传 {u['session_id']} 尚未完成",
                                   {"session_id": u["session_id"]})
            state["state"] = "SEALING"
            self._save_state(state)

            manifest = self._build_manifest(state)
            eid = digest_json(manifest["content"])  # 内容寻址：只由内容块决定
            env_dir = self.s.envelope_path(eid)
            if env_dir.is_dir():
                # 并发封装同一内容：复用既有信封，绝不新建第二个
                state["state"] = "SEALED"
                state["envelope_id"] = eid
                self._save_state(state)
                self.audit("seal.dedup",
                           {"assembly_id": aid, "envelope_id": eid}, by)
                env = self._load_envelope(eid)
                env["replayed"] = True
                return env

            tmp = self.s.envelopes / f".tmp-{aid}-{new_id('t')}"
            tmp.mkdir(parents=True)
            try:
                self.s.journal_append("SEAL_INTENT",
                                      {"assembly_id": aid,
                                       "envelope_id": eid, "tmp": str(tmp)})
                self._materialize_envelope(tmp, manifest, state, eid)
                # 内部一致性自检（摘要/Merkle）后再原子改名
                self._verify_dir_integrity(tmp, manifest,
                                           audit_on_fail=False, eid=eid)
                tmp.rename(env_dir)  # 同目录原子 rename
            except BaseException:
                shutil.rmtree(tmp, ignore_errors=True)
                state["state"] = "OPEN"
                self._save_state(state)
                raise
            state["state"] = "SEALED"
            state["envelope_id"] = eid
            self._save_state(state)
            self.s.journal_append("SEAL_DONE",
                                  {"assembly_id": aid, "envelope_id": eid})
            self.audit("seal", {"assembly_id": aid, "envelope_id": eid}, by)
            return self._load_envelope(eid)

    def _build_manifest(self, state: dict) -> dict:
        artifacts = []
        for a in sorted(state["artifacts"], key=lambda x: (x["kind"],
                                                          x["name"])):
            art = {k: a[k] for k in ("kind", "name", "digest", "size",
                                     "content_type", "storage")}
            if a["storage"] == "chunked":
                art["chunk_index"] = {"chunk_size": a["chunk_size"],
                                      "chunks": a["chunks"]}
            artifacts.append(art)
        reg_body = {"schema": "signer-registry-snapshot/1",
                    "signers": self.registry.signer_summary()}
        registry_digest = digest_json(reg_body)  # 只依赖签名者数据（稳定）
        svc = self.s.service_public()
        reg_snap = {**reg_body, "generated_at": utcnow(),
                    "registry_digest": registry_digest,
                    "service_kid": svc["kid"]}
        reg_snap["service_sig"] = crypto.sign(
            self.s.service_priv,
            canon({**reg_body, "registry_digest": registry_digest}))
        leaf_inputs = [bytes.fromhex(a["digest"]) for a in artifacts]
        tree = merkle.build(leaf_inputs)
        # 内容块只包含“发布了什么”，与谁/何时/用哪个组装装配无关：
        # 同一发布内容（含发布名、谱系父代、签名要求、制品、Merkle 根以及
        # 注册表快照摘要）在任何时刻、由任何人封装都得到同一 envelope id。
        content = {
            "schema": "envelope-content/1",
            "release_name": state["release_name"],
            "project": state.get("project", ""),
            "parent_envelope": state.get("parent_envelope"),
            "required_signers": sorted(state.get("required_signers", [])),
            "registry_digest": registry_digest,
            "artifacts": artifacts,
            "merkle": {"root": tree["root"],
                       "leaf_order": [a["name"] for a in artifacts]}}
        provenance = {"assembly_id": state["assembly_id"],
                      "created_by": state["created_by"],
                      "created_at": state["created_at"],
                      "sealed_at": utcnow(), "note": state.get("note", "")}
        return {
            "schema": "design-sign-envelope/1",
            "content": content,
            "provenance": provenance,
            "registry_snapshot": reg_snap}

    @staticmethod
    def _content_block(manifest: dict) -> dict:
        return manifest["content"]

    def _materialize_envelope(self, d: Path, manifest: dict, state: dict,
                              eid: str):
        write_json(d / "manifest.json", manifest)
        write_json(d / "signatures.json",
                   {"schema": "envelope-signatures/1",
                    "envelope_id": eid,
                    "signatures": []})
        write_json(d / "status.json",
                   {"state": "SEALED",
                    "sealed_at": manifest["provenance"]["sealed_at"]})
        art_dir = d / "artifacts"
        ordered = sorted(state["artifacts"], key=lambda x: (x["kind"],
                                                            x["name"]))
        for a in ordered:
            # 无论内联还是分块，完整文件都已按内容摘要落入 CAS（分块文件在
            # complete_upload 时重组入库），信封内以硬链接固化同一份字节。
            src = self.s.blob_path(a["digest"])
            target = art_dir / a["kind"] / a["name"]
            target.parent.mkdir(parents=True, exist_ok=True)
            if not src.exists():
                raise SealError("BLOB_MISSING",
                                f"制品 {a['name']} 的 CAS blob 缺失")
            self._link(src, target)
        # Merkle 证明（每制品一份）；叶输入=制品摘要原始字节
        leaf_inputs = [bytes.fromhex(a["digest"]) for a in ordered]
        names = [a["name"] for a in ordered]
        tree = merkle.build(leaf_inputs)
        proofs = {name: tree["proofs"][i] for i, name in enumerate(names)}
        write_json(d / "merkle_proofs.json",
                   {"root": tree["root"], "proofs": proofs})
        # 分块 blob 也固化进信封（自包含：离线 bundle 可逐块验真）
        for a in ordered:
            if a["storage"] == "chunked":
                for c in a["chunks"]:
                    csrc = self.s.chunk_path(c["digest"])
                    if not csrc.exists():
                        raise SealError("CHUNK_MISSING",
                                        f"分块 {c['seq']} blob 缺失")
                    self._link(csrc, d / "chunks" / c["digest"][:2] /
                               c["digest"])
        # 服务信任链（公钥轮换史），离线验真用
        write_json(d / "service_history.json", self.s.service_history())

    @staticmethod
    def _link(src, dst):
        dst.parent.mkdir(parents=True, exist_ok=True)
        import os
        try:
            os.link(src, dst)
        except FileExistsError:
            pass
        except OSError:
            shutil.copy2(src, dst)

    # ================================================================ 签名
    def _manifest_bytes(self, eid: str) -> tuple[dict, Path]:
        d = self.s.envelope_path(eid)
        mp = d / "manifest.json"
        if not mp.exists():
            raise NotFound("ENVELOPE_NOT_FOUND", f"信封 {eid} 不存在",
                           {"envelope_id": eid})
        manifest = read_json(mp)
        # 内容寻址校验：目录名必须等于内容块的规范摘要；同时内容块中固定的
        # registry_digest 必须与内嵌注册表快照一致（换快照即内容不符）。
        id_ok = digest_json(manifest.get("content", {})) == eid
        snap_ok = manifest.get("registry_snapshot", {}).get("registry_digest") \
            == manifest.get("content", {}).get("registry_digest")
        if not id_ok or not snap_ok:
            self.audit("verify.envelope.failed",
                       {"envelope_id": eid, "id_ok": id_ok,
                        "snapshot_pinned": snap_ok}, "system", "REJECT",
                       "MANIFEST_ID_MISMATCH" if not id_ok
                       else "REGISTRY_DIGEST_PIN_MISMATCH")
            raise SealError("MANIFEST_TAMPERED",
                            "内容块摘要与信封 id 不符，或注册表快照未被内容"
                            "钉住（疑似篡改）", 400)
        return manifest, d

    SIGN_SKEW_SECONDS = 300

    @staticmethod
    def _parse_ts(s: str):
        from datetime import datetime, timezone
        txt = s[:-1] + "+00:00" if s.endswith("Z") else s
        dt = datetime.fromisoformat(txt)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    def _check_signed_at_window(self, signed_at: str, server_now: str, kv):
        """外部签名时刻校验：不早于密钥登记，不超出 ±5 分钟漂移窗。"""
        from datetime import timedelta
        if not signed_at:
            raise BadRequest("SIGNED_AT_REQUIRED",
                             "外部签名必须提供 signed_at")
        try:
            ts = self._parse_ts(signed_at)
        except ValueError:
            raise BadRequest("BAD_SIGNED_AT", "signed_at 不是合法 ISO-8601")
        now = self._parse_ts(server_now)
        if ts < self._parse_ts(kv.registered_at):
            raise Forbidden("SIGNED_AT_BEFORE_KEY_REGISTERED",
                            "签名时刻早于密钥登记时间（禁止回填）")
        if ts > now + timedelta(seconds=self.SIGN_SKEW_SECONDS):
            raise Forbidden("SIGNED_AT_IN_FUTURE",
                            "签名时刻超出允许的时钟漂移窗（+300s）")
        if ts < now - timedelta(seconds=self.SIGN_SKEW_SECONDS):
            raise Forbidden("SIGNED_AT_TOO_OLD",
                            "签名时刻早于当前时间超过 300s；"
                            "历史签名请在撤权前提交，或先核对时钟")

    @staticmethod
    def _signing_claim(eid: str, signer_id: str, kid: str,
                       signed_at: str) -> dict:
        """签名声明：Ed25519 实际签名内容，绑定信封+签名者+密钥+时刻。

        只签 manifest 无法绑定 signed_at（可回填撤权前时间）或签名者身份，
        因此签名内容必须覆盖全部字段。
        """
        return {"alg": "Ed25519", "claim": "design-envelope-signature/1",
                "envelope_id": eid, "signer_id": signer_id, "kid": kid,
                "signed_at": signed_at}

    @staticmethod
    def _roster_digest(eid: str, signatures: list[dict]) -> str:
        """最终签名清单摘要（发布时由服务密钥作证，防封签后注入）。"""
        roster = [{"signer_id": r["signer_id"], "kid": r["kid"],
                   "public_key": r["public_key"], "signed_at": r["signed_at"],
                   "alg": r["alg"], "signature": r["signature"]}
                  for r in signatures]
        return digest_json({"claim": "envelope-signer-roster/1",
                            "envelope_id": eid, "signatures": roster})

    def sign_envelope(self, eid: str, signer_id: str, kid: str,
                      signature: str | None = None, priv_hex: str | None = None,
                      signed_at: str | None = None) -> dict:
        """对信封追加多方签名之一。

        可直接携带外部离线签名 signature（Ed25519，签名内容为
        _signing_claim 的规范 JSON），或在受信本地用 priv_hex 代签
        （CLI/演示）。撤权/轮换后的密钥提交新签名一律拒绝；已发布信封
        不可变，拒绝再签名。
        """
        self._writable()
        server_now = utcnow()
        if signature is None:
            # 服务端代签：时刻以服务器为准（不信任客户端时钟）
            signed_at = server_now
        # 外部签名的时间窗校验在锁内、取得密钥登记时间后进行（见下）
        with file_lock(self.s.lock_path(f"env:{eid}")):
            manifest, d = self._manifest_bytes(eid)
            if read_json(d / "status.json")["state"] == "PUBLISHED":
                raise Conflict("ENVELOPE_IMMUTABLE",
                               "信封已发布，签名清单冻结，不可追加签名",
                               {"state": "PUBLISHED"})
            problems = self._verify_dir_integrity(d, manifest, eid=eid)
            if problems:
                self.audit("sign.rejected", {"envelope_id": eid,
                                             "problems": problems},
                           signer_id, "REJECT", problems[0]["code"])
                raise Forbidden(problems[0]["code"],
                                "信封完整性校验失败，拒绝签名",
                                {"problems": problems})
            kv = self.registry.key_for_signing(kid)
            if kv.signer_id != signer_id:
                raise Forbidden("KEY_SIGNER_MISMATCH",
                                "密钥不属于该签名者",
                                {"kid": kid, "signer_id": signer_id})
            if signature is not None:
                self._check_signed_at_window(signed_at, server_now, kv)
            sigs = read_json(d / "signatures.json")
            existing = {(x["signer_id"], x["kid"]) for x in sigs["signatures"]}
            if (signer_id, kid) in existing:
                raise Conflict("ALREADY_SIGNED",
                               f"{signer_id} 已用 {kid} 签过该信封")
            claim = self._signing_claim(eid, signer_id, kid, signed_at)
            msg = canon(claim)
            if signature is None:
                if not priv_hex:
                    raise BadRequest("NO_SIGNATURE",
                                     "需提供 signature 或 priv_hex")
                if crypto.derive_pubkey(priv_hex) != kv.public_key:
                    raise Forbidden("PRIVKEY_PUBKEY_MISMATCH",
                                    "私钥导出公钥与登记公钥不符")
                signature = crypto.sign(priv_hex, msg)
            else:
                if not crypto.verify(kv.public_key, msg, signature):
                    self.audit("sign.rejected", {"envelope_id": eid},
                               signer_id, "REJECT", "BAD_SIGNATURE")
                    raise Forbidden("BAD_SIGNATURE",
                                    "外部签名验签未通过（内容/密钥/时刻不符）")
            rec = {"signer_id": signer_id, "kid": kid,
                   "public_key": kv.public_key, "signed_at": signed_at,
                   "alg": "Ed25519", "signature": signature,
                   "signed_claim_digest": digest_json(claim),
                   "registry_status_at_sign": kv.status}
            # 服务在签名落账时为“签名者↔密钥↔信封↔时刻”做绑定作证：
            # 这样封装后才轮换/登记的新密钥也能离线验证（快照里可能尚无该
            # 密钥），且伪造绑定需服务私钥。
            svc_key = self.s.service_public()
            binding = {"claim": "signer-key-binding/1",
                       "envelope_id": eid, "signer_id": signer_id,
                       "kid": kid, "public_key": kv.public_key,
                       "signed_at": signed_at, "service_kid": svc_key["kid"]}
            binding["service_sig"] = crypto.sign(self.s.service_priv,
                                                 canon(binding))
            rec["key_binding"] = binding
            sigs["signatures"].append(rec)
            write_json(d / "signatures.json", sigs)
            self.audit("envelope.sign", {"envelope_id": eid,
                                         "signer_id": signer_id, "kid": kid},
                       signer_id)
            return rec

    # ================================================================ 发布
    def publish(self, eid: str, by: str = "system",
                require_quorum: bool = True) -> dict:
        """两阶段原子发布。封装完成（签名齐备）前拒绝。"""
        self._writable()
        with file_lock(self.s.lock_path("publish")):
            manifest, d = self._manifest_bytes(eid)
            status = read_json(d / "status.json")
            if status["state"] == "PUBLISHED":
                pub = read_json(d / "publication.json")
                pub["replayed"] = True
                return pub
            problems = self._verify_dir_integrity(d, manifest, eid=eid)
            if problems:
                self.audit("publish.rejected", {"envelope_id": eid,
                                                "problems": problems},
                           by, "REJECT", problems[0]["code"])
                raise Conflict(problems[0]["code"],
                               "信封完整性校验失败，拒绝发布",
                               {"problems": problems})
            sigcheck = self.verify_signatures(manifest, d, audit_fail=False)
            if require_quorum and not sigcheck["quorum_met"]:
                raise Conflict("QUORUM_NOT_MET",
                               f"签名不足：需要 {sigcheck['required']}，"
                               f"有效 {sigcheck['valid_count']}",
                               sigcheck)
            name = manifest["content"]["release_name"]
            np = self.s.name_path(name)
            if np.exists():
                current = read_json(np)["envelope_id"]
                if current != eid:
                    self.audit("publish.rejected",
                               {"envelope_id": eid, "name": name,
                                "current": current}, by, "REJECT",
                                "NAME_CONFLICT")
                    raise Conflict("NAME_CONFLICT",
                                   f"发布名 {name} 已指向不同内容 "
                                   f"{current[:16]}…；同名不同内容必须更换"
                                   "发布名或显式续版",
                                   {"name": name, "current": current,
                                    "attempt": eid})
            publication = {"schema": "envelope-publication/1",
                           "envelope_id": eid, "release_name": name,
                           "published_at": utcnow(), "published_by": by,
                           "manifest_digest": eid,
                           "signature_count": len(
                               read_json(d / "signatures.json")[
                                   "signatures"])}
            self.s.journal_append("PUBLISH_INTENT",
                                  {"envelope_id": eid, "name": name,
                                   "dir": str(d)})
            # 阶段二（同一把发布锁内顺序原子落盘）：
            # 2a) 服务密钥对最终签名清单作证（封签后再注入签名必被验真拒绝）
            self._attest_roster(d, eid, publication["published_at"])
            # 2b) publication 与名字指针各自原子写
            write_json(d / "publication.json", publication)
            write_json(np, publication)
            write_json(d / "status.json", {"state": "PUBLISHED",
                                           "sealed_at": status["sealed_at"],
                                           "published_at":
                                               publication["published_at"]})
            self.s.journal_append("PUBLISH_DONE", {"envelope_id": eid})
            self.audit("publish", {"envelope_id": eid, "release_name": name},
                       by)
            return publication

    def _attest_roster(self, d: Path, eid: str, published_at: str) -> dict:
        """用当前服务私钥对最终签名清单作证，写回 signatures.json（原子）。"""
        sigs = read_json(d / "signatures.json")
        roster_digest = self._roster_digest(eid, sigs["signatures"])
        svc = self.s.service_public()
        body = {"claim": "envelope-signer-roster/1", "envelope_id": eid,
                "roster_digest": roster_digest,
                "published_at": published_at, "service_kid": svc["kid"]}
        att = dict(body)
        att["service_sig"] = crypto.sign(self.s.service_priv, canon(body))
        sigs["roster_attestation"] = att
        write_json(d / "signatures.json", sigs)
        return att

    # ================================================================ 恢复
    def recover(self) -> dict:
        """进程恢复：清理半成品 temp、续做 journal 中未完成的 seal/publish。

        幂等；由信封内容 id 决定目标位置，任何阶段崩溃都不会产生两个有效
        信封或两个同名指针。
        """
        result = {"sealed": [], "published": [], "cleaned": [],
                  "reset_assemblies": []}
        # 1) 清理孤儿 temp 目录（rename 之前崩溃）
        for tmp in self.s.envelopes.glob(".tmp-*"):
            shutil.rmtree(tmp, ignore_errors=True)
            result["cleaned"].append(str(tmp))
        # 2) 扫描 SEALING 组装：若信封已在则收敛为 SEALED，否则回退 OPEN
        for p in self.s.assemblies.glob("*/state.json"):
            st = read_json(p)
            if st.get("state") == "SEALING":
                eid = st.get("envelope_id")
                if eid and self.s.envelope_path(eid).is_dir():
                    st["state"] = "SEALED"
                    write_json(p, st)
                    result["sealed"].append(eid)
                else:
                    st["state"] = "OPEN"
                    write_json(p, st)
                    result["reset_assemblies"].append(st["assembly_id"])
        # 3) journal 续做：取每条 INTENT 的最后状态
        entries = self.s.journal_entries()
        done_seal = {e["payload"].get("envelope_id") for e in entries
                     if e["kind"] == "SEAL_DONE"}
        done_pub = {e["payload"].get("envelope_id") for e in entries
                    if e["kind"] == "PUBLISH_DONE"}
        for e in entries:
            if e["kind"] == "PUBLISH_INTENT":
                eid = e["payload"]["envelope_id"]
                if eid not in done_pub and self.s.envelope_path(eid).is_dir():
                    self._resume_publish(eid, result)
        # 已完成的意图清理 journal
        if entries:
            pending = self._pending_journal(entries)
            if not pending:
                self.s.journal_clear()
            else:
                write_bytes(self.s.journal_dir / "journal.log",
                            b"".join((json.dumps(x, ensure_ascii=False) +
                                      "\n").encode() for x in pending))
        return result

    def _resume_publish(self, eid: str, result: dict):
        d = self.s.envelope_path(eid)
        manifest = read_json(d / "manifest.json")
        pubp = d / "publication.json"
        name = manifest["content"]["release_name"]
        np = self.s.name_path(name)
        if pubp.exists() and np.exists() and \
                read_json(np).get("envelope_id") == eid:
            # roster 作证可能恰在崩溃前未落盘：缺则按当前清单补齐
            sigs_doc = read_json(d / "signatures.json")
            if not sigs_doc.get("roster_attestation"):
                self._attest_roster(d, eid, read_json(pubp)["published_at"])
            write_json(d / "status.json",
                       {"state": "PUBLISHED",
                        "sealed_at": manifest["provenance"]["sealed_at"],
                        "published_at": read_json(pubp)["published_at"]})
        else:
            # 阶段二未完成：按既有意图补齐（不重新裁决 quorum——意图已记录）
            sig_n = len(read_json(d / "signatures.json")["signatures"])
            ts = utcnow()
            publication = {"schema": "envelope-publication/1",
                           "envelope_id": eid, "release_name": name,
                           "published_at": ts,
                           "published_by": "recovery",
                           "manifest_digest": eid,
                           "signature_count": sig_n, "recovered": True}
            self._attest_roster(d, eid, ts)
            write_json(pubp, publication)
            if not np.exists():
                write_json(np, publication)
            elif read_json(np).get("envelope_id") != eid:
                # 名字已被别的内容占用且不是自己：发布失败，留痕不覆盖
                self.audit("recover.publish.conflict",
                           {"envelope_id": eid, "name": name,
                            "current": read_json(np)["envelope_id"]},
                           "recovery", "REJECT", "NAME_CONFLICT")
                return
            write_json(d / "status.json",
                       {"state": "PUBLISHED",
                        "sealed_at": manifest["provenance"]["sealed_at"],
                        "published_at": publication["published_at"]})
        self.s.journal_append("PUBLISH_DONE", {"envelope_id": eid})
        self.audit("recover.publish", {"envelope_id": eid}, "recovery")
        result["published"].append(eid)

    @staticmethod
    def _pending_journal(entries):
        done_pub = {e["payload"].get("envelope_id") for e in entries
                    if e["kind"] == "PUBLISH_DONE"}
        keep = []
        for e in entries:
            if e["kind"] == "PUBLISH_INTENT" and \
                    e["payload"]["envelope_id"] in done_pub:
                continue
            if e["kind"] in ("SEAL_INTENT", "SEAL_DONE"):
                continue
            keep.append(e)
        return keep

    # ================================================================ 验真
    def _verify_dir_integrity(self, d: Path, manifest: dict,
                              audit_on_fail: bool = True,
                              eid: str | None = None) -> list[dict]:
        """重算制品摘要/分块索引/Merkle 根与证明；返回问题列表（空=通过）。"""
        problems: list[dict] = []
        root = manifest["content"]["merkle"]["root"]
        ordered = sorted(manifest["content"]["artifacts"],
                         key=lambda x: (x["kind"], x["name"]))
        leaf_inputs: list[bytes] = []
        proofs_data = read_json(d / "merkle_proofs.json") \
            if (d / "merkle_proofs.json").exists() else None
        if proofs_data and proofs_data.get("root") != root:
            problems.append({"code": "MERKLE_ROOT_MISMATCH"})
        for a in ordered:
            p = d / "artifacts" / a["kind"] / a["name"]
            if not p.exists():
                problems.append({"code": "ARTIFACT_MISSING",
                                 "name": a["name"]})
                leaf_inputs.append(bytes.fromhex(a["digest"]))
                continue
            if p.stat().st_size != a["size"]:
                problems.append({"code": "ARTIFACT_SIZE_MISMATCH",
                                 "name": a["name"],
                                 "expected": a["size"],
                                 "actual": p.stat().st_size})
            dg = sha256_file(p)
            if dg != a["digest"]:
                problems.append({"code": "ARTIFACT_DIGEST_MISMATCH",
                                 "name": a["name"], "expected": a["digest"],
                                 "actual": dg})
            # 分块文件：逐块重算，定位被篡改/丢失的具体分块（优先信封内）
            if a["storage"] == "chunked":
                for c in a["chunk_index"]["chunks"]:
                    local = d / "chunks" / c["digest"][:2] / c["digest"]
                    cp = local if local.exists() else \
                        self.s.chunk_path(c["digest"])
                    if not cp.exists():
                        problems.append({"code": "CHUNK_MISSING",
                                         "name": a["name"], "seq": c["seq"]})
                    elif sha256_file(cp) != c["digest"]:
                        problems.append({"code": "CHUNK_TAMPERED",
                                         "name": a["name"], "seq": c["seq"]})
            leaf_inputs.append(bytes.fromhex(a["digest"]))
            if proofs_data and not merkle.verify_proof(
                    root, bytes.fromhex(a["digest"]),
                    proofs_data["proofs"].get(a["name"], [])):
                problems.append({"code": "MERKLE_PROOF_INVALID",
                                 "name": a["name"]})
        rebuilt = merkle.build(leaf_inputs)
        if leaf_inputs and rebuilt["root"] != root and \
                not any(x["code"] == "MERKLE_ROOT_MISMATCH" for x in problems):
            problems.append({"code": "MERKLE_ROOT_MISMATCH",
                             "expected": root, "actual": rebuilt["root"]})
        if proofs_data and set(proofs_data["proofs"]) != \
                {a["name"] for a in ordered}:
            problems.append({"code": "MERKLE_PROOF_SET_MISMATCH"})
        if audit_on_fail and problems:
            self.audit("verify.integrity.failed",
                       {"envelope_id": eid or d.name,
                        "problems": problems}, "system", "REJECT",
                       problems[0]["code"])
        return problems

    def verify_signatures(self, manifest: dict, d: Path,
                          audit_fail: bool = True,
                          require_attestation: bool | None = None) -> dict:
        """校验多方签名清单。

        - 逐条按签名声明（envelope_id+签名者+kid+signed_at）Ed25519 验签；
        - 历史有效性按信封内嵌、经服务签名的注册表快照判定（撤权不影响
          撤权前的历史签名）；同时参考实时注册表补充当前状态；
        - quorum：required_signers 均有有效签名；
        - 已发布信封校验 roster_attestation（最终清单被服务作证，注入即失败）。
        """
        eid = d.name  # 信封 id 即内容寻址的目录名
        snap = manifest["registry_snapshot"]
        snap_problems = self._verify_registry_snapshot(snap)
        sigs_doc = read_json(d / "signatures.json")
        sigs = sigs_doc["signatures"]
        results = []
        valid = 0
        for r in sigs:
            item = {"signer_id": r["signer_id"], "kid": r["kid"],
                    "signed_at": r["signed_at"], "valid": False,
                    "then_valid": False, "current_status": None,
                    "reasons": []}
            signer = next((x for x in snap["signers"]
                           if x["signer_id"] == r["signer_id"]), None)
            key = None
            if signer:
                key = next((k for k in signer["keys"]
                            if k["kid"] == r["kid"]), None)
            binding_ok = False
            if not key:
                # 密钥在封装快照之后才登记/轮换：回退到每条签名内嵌的
                # 服务密钥绑定作证（离线可验，防伪造公钥）。
                b = r.get("key_binding")
                bind_pub = self._binding_service_pubkey(b)
                if not b or not bind_pub or not crypto.verify(
                        bind_pub,
                        canon({k: b[k] for k in
                               ("claim", "envelope_id", "signer_id", "kid",
                                "public_key", "signed_at", "service_kid")}),
                        b.get("service_sig", "")):
                    item["reasons"].append("UNKNOWN_SIGNER_OR_KEY")
                elif b["signer_id"] != r["signer_id"] or \
                        b["kid"] != r["kid"] or \
                        b["envelope_id"] != eid or \
                        b["public_key"] != r["public_key"] or \
                        b["signed_at"] != r["signed_at"]:
                    item["reasons"].append("KEY_BINDING_MISMATCH")
                else:
                    key = {"public_key": r["public_key"],
                           "registered_at": b["signed_at"]}
                    binding_ok = True
            if not item["reasons"] and key["public_key"] != r["public_key"]:
                item["reasons"].append("PUBLIC_KEY_MISMATCH")
            if not item["reasons"]:
                # 签名声明必须绑定本信封/签名者/密钥/时刻
                claim = self._signing_claim(eid, r["signer_id"], r["kid"],
                                            r["signed_at"])
                if r.get("signed_claim_digest") and \
                        r["signed_claim_digest"] != digest_json(claim):
                    item["reasons"].append("SIGNING_CLAIM_MISMATCH")
                if not crypto.verify(key["public_key"], canon(claim),
                                     r["signature"]):
                    item["reasons"].append("BAD_SIGNATURE")
                # 历史有效性：快照密钥看 registered_at；绑定作证在签名落账
                # 时已由服务校验 ACTIVE，故其自身时刻即有效
                if not binding_ok and r["signed_at"] < key["registered_at"]:
                    item["reasons"].append("KEY_NOT_YET_VALID_AT_SIGN_TIME")
                else:
                    item["then_valid"] = True
                item["via_binding"] = binding_ok
                # 实时注册表给出密钥当前状态（仅供展示/强在线策略）
                live = self.registry.find_key(r["kid"])
                if live:
                    item["current_status"] = live.status
                    if live.status == "REVOKED":
                        item["revoked_at"] = live.revoked_at
            if not item["reasons"]:
                item["valid"] = True
                valid += 1
            results.append(item)
        required = sorted(manifest["content"].get("required_signers", []))
        signed_ids = {x["signer_id"] for x in results if x["valid"]}
        missing = [s for s in required if s not in signed_ids]
        quorum = (not required) or not missing
        # roster 作证：已发布信封的清单必须被服务密钥作证且未被改动
        published = (d / "publication.json").exists()
        if require_attestation is None:
            require_attestation = published
        attest_problems = self._verify_roster_attestation(
            eid, sigs_doc, require_attestation)
        out = {"envelope_id": eid, "snapshot_ok": not snap_problems,
               "snapshot_problems": snap_problems,
               "attestation_ok": not attest_problems,
               "attestation_problems": attest_problems,
               "published": published,
               "required": required, "valid_count": valid,
               "missing_signers": missing, "quorum_met": quorum,
               "signatures": results}
        if audit_fail and (snap_problems or attest_problems or
                           any(not x["valid"] for x in results)):
            self.audit("verify.signatures.failed",
                       {"envelope_id": eid, "snapshot_problems":
                        snap_problems, "attestation_problems":
                        attest_problems, "invalid":
                        [x for x in results if not x["valid"]]},
                       "system", "REJECT", "SIGNATURE_VERIFY_FAILED")
        return out

    def _binding_service_pubkey(self, b: dict | None):
        """按绑定作证里的 service_kid 在服务信任链中找公钥（支持轮换）。"""
        if not b:
            return None
        return next((k["public_key"]
                     for k in self.s.service_history()["keys"]
                     if k["kid"] == b.get("service_kid")), None)

    def _verify_roster_attestation(self, eid: str, sigs_doc: dict,
                                   required: bool) -> list[dict]:
        """校验服务密钥对最终签名清单的作证。

        - 已发布信封：必须存在作证，且 roster_digest、服务签名、kid 有效；
        - 未发布信封：不应有作证（有则视为异常状态）。
        """
        problems: list[dict] = []
        att = sigs_doc.get("roster_attestation")
        if not required:
            if att:
                problems.append({"code": "ROSTER_ATTEST_UNEXPECTED"})
            return problems
        if not att:
            return [{"code": "ROSTER_ATTEST_MISSING"}]
        want_digest = self._roster_digest(eid, sigs_doc["signatures"])
        if att.get("roster_digest") != want_digest:
            problems.append({"code": "ROSTER_DIGEST_MISMATCH"})
        history = self.s.service_history()
        pub = next((k for k in history["keys"]
                    if k["kid"] == att.get("service_kid")), None)
        if not pub:
            problems.append({"code": "SERVICE_KID_UNKNOWN"})
        elif not crypto.verify(
                pub["public_key"],
                canon({"claim": "envelope-signer-roster/1",
                       "envelope_id": eid,
                       "roster_digest": att.get("roster_digest"),
                       "published_at": att.get("published_at"),
                       "service_kid": att.get("service_kid")}),
                att.get("service_sig", "")):
            problems.append({"code": "ROSTER_ATTEST_SIG_INVALID"})
        return problems

    def _verify_registry_snapshot(self, snap: dict) -> list[dict]:
        problems = []
        body = {"schema": snap["schema"], "signers": snap["signers"]}
        if digest_json(body) != snap.get("registry_digest"):
            problems.append({"code": "REGISTRY_SNAPSHOT_DIGEST_MISMATCH"})
        history = self.s.service_history()
        pub = next((k for k in history["keys"]
                    if k["kid"] == snap.get("service_kid")), None)
        if not pub:
            problems.append({"code": "SERVICE_KID_UNKNOWN"})
        elif not crypto.verify(pub["public_key"],
                               canon({**body,
                                      "registry_digest":
                                          snap.get("registry_digest")}),
                               snap.get("service_sig", "")):
            problems.append({"code": "REGISTRY_SNAPSHOT_SIG_INVALID"})
        return problems

    def verify_envelope(self, eid: str) -> dict:
        """完整在线/离线口径验真：manifest→制品→分块→Merkle→签名→发布。"""
        manifest, d = self._manifest_bytes(eid)
        problems = self._verify_dir_integrity(d, manifest)
        sigcheck = self.verify_signatures(manifest, d, audit_fail=False)
        if sigcheck["snapshot_problems"]:
            problems.extend(sigcheck["snapshot_problems"])
        if sigcheck["attestation_problems"]:
            problems.extend(sigcheck["attestation_problems"])
        for x in sigcheck["signatures"]:
            if not x["valid"]:
                problems.append({"code": "SIGNATURE_INVALID",
                                 "signer_id": x["signer_id"],
                                 "reasons": x["reasons"]})
        status = read_json(d / "status.json")
        publication = None
        if (d / "publication.json").exists():
            publication = read_json(d / "publication.json")
            if publication.get("envelope_id") != eid:
                problems.append({"code": "PUBLICATION_ID_MISMATCH"})
        result = {"envelope_id": eid, "ok": not problems,
                  "state": status["state"],
                  "release_name": manifest["content"]["release_name"],
                  "manifest_digest": eid,
                  "merkle_root": manifest["content"]["merkle"]["root"],
                  "artifacts_checked": len(manifest["content"]["artifacts"]),
                  "signatures": sigcheck, "publication": publication,
                  "problems": problems, "verified_at": utcnow()}
        self.audit("verify.envelope",
                   {"envelope_id": eid, "ok": result["ok"],
                    "problems": problems}, "system",
                   "OK" if result["ok"] else "REJECT",
                   None if result["ok"] else problems[0]["code"])
        return result

    # ================================================================ 查询
    def _load_envelope(self, eid: str) -> dict:
        manifest, d = self._manifest_bytes(eid)
        return {"envelope_id": eid,
                "release_name": manifest["content"]["release_name"],
                "project": manifest["content"].get("project", ""),
                "sealed_at": manifest["provenance"]["sealed_at"],
                "state": read_json(d / "status.json")["state"],
                "parent_envelope": manifest["content"].get("parent_envelope"),
                "required_signers": manifest["content"].get("required_signers", []),
                "artifacts": manifest["content"]["artifacts"],
                "merkle_root": manifest["content"]["merkle"]["root"],
                "signatures": read_json(d / "signatures.json")["signatures"],
                "publication": read_json(d / "publication.json")
                if (d / "publication.json").exists() else None}

    def list_envelopes(self) -> list[dict]:
        out = []
        for mp in sorted(self.s.envelopes.glob("*/manifest.json")):
            try:
                m = read_json(mp)
                d = mp.parent
                out.append({"envelope_id": d.name,
                            "release_name": m["content"]["release_name"],
                            "project": m["content"].get("project", ""),
                            "sealed_at": m["provenance"]["sealed_at"],
                            "state": read_json(d / "status.json")["state"],
                            "parent_envelope":
                                m["content"].get("parent_envelope"),
                            "signature_count": len(
                                read_json(d / "signatures.json")[
                                    "signatures"])})
            except (KeyError, FileNotFoundError):
                continue
        return out

    def lineage(self, eid: str) -> dict:
        """信封谱系：沿 parent_envelope 前向链（含签名状态摘要）。"""
        chain = []
        cur = eid
        seen = set()
        while cur and cur not in seen:
            seen.add(cur)
            if not self.s.envelope_path(cur).is_dir():
                raise NotFound("ENVELOPE_NOT_FOUND", f"信封 {cur} 不存在")
            env = self._load_envelope(cur)
            chain.append({"envelope_id": cur,
                          "release_name": env["release_name"],
                          "sealed_at": env["sealed_at"], "state": env["state"],
                          "signature_count": len(env["signatures"]),
                          "artifact_count": len(env["artifacts"])})
            cur = env["parent_envelope"]
        return {"envelope_id": eid, "ancestors": list(reversed(chain)),
                "depth": len(chain)}

    def artifact_bytes(self, eid: str, name: str) -> tuple[bytes, dict]:
        manifest, d = self._manifest_bytes(eid)
        a = next((x for x in manifest["content"]["artifacts"] if x["name"] == name), None)
        if not a:
            raise NotFound("ARTIFACT_NOT_FOUND", f"制品 {name} 不存在")
        p = d / "artifacts" / a["kind"] / a["name"]
        return p.read_bytes(), a

    def inclusion_proof(self, eid: str, name: str) -> dict:
        manifest, d = self._manifest_bytes(eid)
        a = next((x for x in manifest["content"]["artifacts"] if x["name"] == name), None)
        if not a:
            raise NotFound("ARTIFACT_NOT_FOUND", f"制品 {name} 不存在")
        proofs = read_json(d / "merkle_proofs.json")
        return {"envelope_id": eid, "name": name, "digest": a["digest"],
                "merkle_root": manifest["content"]["merkle"]["root"],
                "proof": proofs["proofs"][name]}

    # ================================================================ 导出
    def export_bundle(self, eid: str, out_path: str) -> str:
        """导出可离线验真的自包含 bundle（.tar，无压缩以利逐字节核对）。"""
        import tarfile
        manifest, d = self._manifest_bytes(eid)
        with tarfile.open(out_path, "w") as tar:
            for p in sorted(d.rglob("*")):
                if p.is_file():
                    tar.add(p, arcname=str(Path(eid) / p.relative_to(d)))
        return out_path

    def verify_bundle(self, path: str, trust_pub: str | None = None) -> dict:
        """离线验真导出包：解到临时目录后交给纯离线验证器（不依赖本服务）。"""
        import tarfile
        import tempfile
        from .offline import verify_dir
        with tempfile.TemporaryDirectory() as td:
            with tarfile.open(path, "r") as tar:
                tar.extractall(td)
            roots = [x for x in Path(td).iterdir() if x.is_dir()]
            if len(roots) != 1:
                raise BadRequest("BAD_BUNDLE", "bundle 顶层目录不唯一")
            result = verify_dir(roots[0], trust_pub=trust_pub)
            result["bundle"] = path
            self.audit("verify.bundle",
                       {"bundle": path, "envelope_id": result["envelope_id"],
                        "ok": result["ok"], "problems": result["problems"]},
                       "system", "OK" if result["ok"] else "REJECT",
                       None if result["ok"] else result["problems"][0]["code"])
            return result
