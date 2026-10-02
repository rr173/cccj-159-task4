"""纯离线验真器：不依赖运行中的服务与存储，只需一个信封目录或导出包。

验真链（任一环失败即拒绝，返回全部问题码）：
  目录名 == SHA256(canon(manifest.content))，且 content.registry_digest
           与内嵌注册表快照一致
    → 每制品重算 SHA-256（分块文件再逐块核对 chunks/ 内 blob）
    → 每制品 Merkle 包含证明 → Merkle 根
    → 注册表快照：registry_digest + 服务密钥签名（信任根来自 service_history）
    → 每条签名：签名声明（信封+签名者+kid+时刻）Ed25519 验签，密钥取自快照
    → 已发布信封：服务密钥对最终签名清单的 roster 作证（防封签后注入）
    → 可选：信任根公钥必须等于创世服务公钥
"""
from __future__ import annotations

from pathlib import Path

from . import crypto, merkle
from .util import canon, digest_json, read_json, sha256_file, utcnow


def verify_dir(d: Path, trust_pub: str | None = None) -> dict:
    problems: list[dict] = []
    d = Path(d)
    eid = d.name
    manifest = read_json(d / "manifest.json")
    content = manifest.get("content", {})
    if digest_json(content) != eid:
        problems.append({"code": "MANIFEST_ID_MISMATCH"})

    # 制品 + 分块
    for a in content["artifacts"]:
        p = d / "artifacts" / a["kind"] / a["name"]
        if not p.exists():
            problems.append({"code": "ARTIFACT_MISSING", "name": a["name"]})
            continue
        if p.stat().st_size != a["size"]:
            problems.append({"code": "ARTIFACT_SIZE_MISMATCH",
                             "name": a["name"]})
        if sha256_file(p) != a["digest"]:
            problems.append({"code": "ARTIFACT_DIGEST_MISMATCH",
                             "name": a["name"]})
        if a["storage"] == "chunked":
            for c in a["chunk_index"]["chunks"]:
                cp = d / "chunks" / c["digest"][:2] / c["digest"]
                if not cp.exists():
                    problems.append({"code": "CHUNK_MISSING",
                                     "name": a["name"], "seq": c["seq"]})
                elif sha256_file(cp) != c["digest"]:
                    problems.append({"code": "CHUNK_TAMPERED",
                                     "name": a["name"], "seq": c["seq"]})

    # Merkle 包含证明
    proofs = read_json(d / "merkle_proofs.json")
    root = content["merkle"]["root"]
    if proofs.get("root") != root:
        problems.append({"code": "MERKLE_ROOT_MISMATCH"})
    leaf_inputs = []
    for a in content["artifacts"]:
        leaf_inputs.append(bytes.fromhex(a["digest"]))
        if not merkle.verify_proof(root, bytes.fromhex(a["digest"]),
                                   proofs["proofs"].get(a["name"], [])):
            problems.append({"code": "MERKLE_PROOF_INVALID",
                             "name": a["name"]})
    if leaf_inputs and merkle.build(leaf_inputs)["root"] != root:
        problems.append({"code": "MERKLE_ROOT_REBUILD_MISMATCH"})

    # 注册表快照（服务密钥签名）；其稳定摘要必须被内容块钉住
    history = read_json(d / "service_history.json")
    snap = manifest["registry_snapshot"]
    snap_body = {"schema": snap["schema"], "signers": snap["signers"]}
    snap_ok = digest_json(snap_body) == snap.get("registry_digest")
    if snap.get("registry_digest") != content.get("registry_digest"):
        problems.append({"code": "REGISTRY_DIGEST_PIN_MISMATCH"})
    svc_key = next((k for k in history["keys"]
                    if k["kid"] == snap.get("service_kid")), None)
    if not snap_ok:
        problems.append({"code": "REGISTRY_SNAPSHOT_DIGEST_MISMATCH"})
    if not svc_key:
        problems.append({"code": "SERVICE_KID_UNKNOWN",
                         "kid": snap.get("service_kid")})
    elif not crypto.verify(
            svc_key["public_key"],
            canon({**snap_body, "registry_digest": snap["registry_digest"]}),
            snap.get("service_sig", "")):
        problems.append({"code": "REGISTRY_SNAPSHOT_SIG_INVALID"})

    if trust_pub is not None and history["keys"][0]["public_key"] != trust_pub:
        problems.append({"code": "TRUST_ROOT_MISMATCH"})

    # 签名声明
    sigs_doc = read_json(d / "signatures.json")
    sig_results = []
    for r in sigs_doc["signatures"]:
        reasons = []
        signer = next((x for x in snap["signers"]
                       if x["signer_id"] == r["signer_id"]), None)
        key = next((k for k in (signer or {"keys": []})["keys"]
                    if k["kid"] == r["kid"]), None)
        via_binding = False
        if not key:
            # 封装后才登记/轮换的密钥：校验每条签名内嵌的服务绑定作证
            b = r.get("key_binding")
            bind_pub = next((k["public_key"] for k in history["keys"]
                             if k["kid"] == (b or {}).get("service_kid")),
                            None)
            bind_body = {k: (b or {}).get(k) for k in
                         ("claim", "envelope_id", "signer_id", "kid",
                          "public_key", "signed_at", "service_kid")}
            if not b or not bind_pub or not crypto.verify(
                    bind_pub, canon(bind_body), b.get("service_sig", "")):
                reasons.append("UNKNOWN_SIGNER_OR_KEY")
            elif b["signer_id"] != r["signer_id"] or b["kid"] != r["kid"] or \
                    b["envelope_id"] != eid or \
                    b["public_key"] != r["public_key"] or \
                    b["signed_at"] != r["signed_at"]:
                reasons.append("KEY_BINDING_MISMATCH")
            else:
                key = {"public_key": r["public_key"],
                       "registered_at": b["signed_at"]}
                via_binding = True
        if key and key["public_key"] != r["public_key"]:
            reasons.append("PUBLIC_KEY_MISMATCH")
        if key and not reasons:
            claim = {"alg": "Ed25519",
                     "claim": "design-envelope-signature/1",
                     "envelope_id": eid, "signer_id": r["signer_id"],
                     "kid": r["kid"], "signed_at": r["signed_at"]}
            if not crypto.verify(key["public_key"], canon(claim),
                                 r["signature"]):
                reasons.append("BAD_SIGNATURE")
            if not via_binding and r["signed_at"] < key["registered_at"]:
                reasons.append("KEY_NOT_YET_VALID_AT_SIGN_TIME")
        ok = not reasons
        sig_results.append({"signer_id": r["signer_id"], "kid": r["kid"],
                            "signed_at": r["signed_at"], "valid": ok,
                            "via_binding": via_binding, "reasons": reasons})
        if not ok:
            problems.append({"code": "SIGNATURE_INVALID",
                             "signer_id": r["signer_id"], "reasons": reasons})

    # roster 作证（仅发布过的信封要求）
    published = (d / "publication.json").exists()
    att = sigs_doc.get("roster_attestation")
    if published:
        if not att:
            problems.append({"code": "ROSTER_ATTEST_MISSING"})
        else:
            roster = [{"signer_id": r["signer_id"], "kid": r["kid"],
                       "public_key": r["public_key"],
                       "signed_at": r["signed_at"], "alg": r["alg"],
                       "signature": r["signature"]}
                      for r in sigs_doc["signatures"]]
            want = digest_json({"claim": "envelope-signer-roster/1",
                                "envelope_id": eid, "signatures": roster})
            att_key = next((k for k in history["keys"]
                            if k["kid"] == att.get("service_kid")), None)
            if att.get("roster_digest") != want:
                problems.append({"code": "ROSTER_DIGEST_MISMATCH"})
            if not att_key:
                problems.append({"code": "SERVICE_KID_UNKNOWN"})
            elif not crypto.verify(
                    att_key["public_key"],
                    canon({"claim": "envelope-signer-roster/1",
                           "envelope_id": eid,
                           "roster_digest": att.get("roster_digest"),
                           "published_at": att.get("published_at"),
                           "service_kid": att.get("service_kid")}),
                    att.get("service_sig", "")):
                problems.append({"code": "ROSTER_ATTEST_SIG_INVALID"})
    elif att:
        problems.append({"code": "ROSTER_ATTEST_UNEXPECTED"})

    required = sorted(content.get("required_signers", []))
    signed = {r["signer_id"] for r in sig_results if r["valid"]}
    missing = [s for s in required if s not in signed]
    quorum = not required or not missing
    if not quorum:
        problems.append({"code": "QUORUM_NOT_MET", "missing": missing})

    return {"envelope_id": eid, "ok": not problems, "problems": problems,
            "snapshot_ok": snap_ok, "quorum_met": quorum,
            "missing_signers": missing, "signatures": sig_results,
            "published": published, "verified_at": utcnow(),
            "offline": True}
