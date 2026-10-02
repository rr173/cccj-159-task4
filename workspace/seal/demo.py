"""端到端多场景演示（临时存储，跑完即弃；也可用 --store 保留）。

演示：
  A. 双签发布：网表/约束/模块清单/签核记录 → 封装 → 多方签名 → 原子发布 → 验真
  B. 分块上传中断续传（乱序、幂等重传、完成后逐块重组）
  C. 签名者撤权：撤权前的历史信封仍可离线验真（then_valid），
     撤权后再用旧密钥签新信封被拒绝
  D. 密钥轮换 / 服务密钥轮换不影响历史验真
  E. 同名不同内容冲突（NAME_CONFLICT）
  F. 并发封装同一内容 → 恰好一个有效信封
  G. 篡改（制品/签名/分块）→ 拒绝验真并写审计

运行: python3 -m seal.demo [--store /tmp/seal-demo] [--keep]
"""
from __future__ import annotations

import argparse
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from seal import crypto
from seal.service import SealService
from seal.util import read_json, write_json


def line(t=""):
    print(t)


def step(n, t):
    line(f"\n── {n}  {t} " + "─" * max(4, 64 - len(t)))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default=None)
    ap.add_argument("--keep", action="store_true", help="保留存储目录")
    args = ap.parse_args(argv)
    root = args.store or tempfile.mkdtemp(prefix="seal-demo-")
    keep = args.keep or bool(args.store)
    line(f"存储目录: {root}")
    svc = SealService(root)

    # 固定演示密钥（仅为可复现；生产中私钥绝不落服务端）
    def key(seed: str):
        seedhex = (seed * 64).encode().hex()[:64]
        priv = bytes.fromhex(seedhex)
        return priv.hex(), crypto.derive_pubkey(priv.hex())

    sk_a, pk_a = key("alice")
    sk_b, pk_b = key("bobbbb")
    svc.registry.register_signer("alice", "Alice（时序负责人）", pk_a,
                                 kid="key_alice_0")
    svc.registry.register_signer("bob", "Bob（方法学负责人）", pk_b,
                                 kid="key_bob_0")

    # ── A 双签发布 ────────────────────────────────────────────────
    step("A", "组装待发布变更并双签发布")
    asm = svc.create_assembly(
        "chip-top-R1", "ci-bot", project="chip-top",
        note="ECO: UART 时序修复", required_signers=["alice", "bob"])
    aid = asm["assembly_id"]
    svc.add_artifact_inline(aid, "netlist", "netlist/top.v",
                            b"module top; uart u0(...); endmodule")
    svc.add_artifact_inline(aid, "constraint", "sdc/top.sdc.json",
                            {"create_clock": {"clk": 2.0}, "uncertainty": 0.05})
    svc.add_artifact_inline(aid, "module", "modules.json",
                            ["top", "uart", "apb_bus"])
    svc.add_artifact_inline(aid, "signoff", "signoffs.json",
                            {"sta": "PASS", "power": "PASS", "formal": "PASS",
                             "drc": "PASS"})
    env = svc.seal(aid, by="ci-bot")
    eid = env["envelope_id"]
    line(f"信封 id = {eid}")
    line(f"Merkle 根 = {env['merkle_root']}")
    svc.sign_envelope(eid, "alice", "key_alice_0", priv_hex=sk_a)
    line("alice 已签名；此时发布应被仲裁门禁拒绝：")
    try:
        svc.publish(eid)
    except Exception as e:
        line(f"  → 拒绝 {e.code}: {e.message}")
    svc.sign_envelope(eid, "bob", "key_bob_0", priv_hex=sk_b)
    svc.publish(eid)
    r = svc.verify_envelope(eid)
    line(f"bob 已签名 → 发布完成；验真 ok={r['ok']} "
         f"有效签名={r['signatures']['valid_count']}")

    # ── B 分块续传 ────────────────────────────────────────────────
    step("B", "大网表分块上传（乱序、缺块拒绝、补齐完成）")
    asm2 = svc.create_assembly("chip-top-R2", "ci-bot",
                               project="chip-top",
                               required_signers=["alice"],
                               parent_envelope=eid)
    aid2 = asm2["assembly_id"]
    data = bytes((i * 13 + 7) % 256 for i in range(70000))
    u = svc.start_upload(aid2, "netlist", "netlist/route_top.v",
                         len(data), chunk_size=32768)
    sid = u["session_id"]
    svc.put_chunk(sid, 0, data[0:32768])
    svc.put_chunk(sid, 2, data[65536:])     # 乱序（最后一块 4464 字节）
    line(f"已乱序传 0、2 块（共 {u['total_chunks']} 块）")
    try:
        svc.complete_upload(sid)
    except Exception as e:
        line(f"  → 缺块完成被拒绝 {e.code}")
    svc.put_chunk(sid, 0, data[0:32768])  # 幂等重传
    svc.put_chunk(sid, 1, data[32768:65536])
    svc.complete_upload(sid)
    eid2 = svc.seal(aid2)["envelope_id"]
    got, _ = svc.artifact_bytes(eid2, "netlist/route_top.v")
    line(f"补齐完成并封装；重组字节一致 = {got == data}")
    svc.sign_envelope(eid2, "alice", "key_alice_0", priv_hex=sk_a)
    svc.publish(eid2)
    line(f"谱系深度 = {svc.lineage(eid2)['depth']}（R1 → R2）")

    # ── C 撤权历史验真 ────────────────────────────────────────────
    step("C", "alice 撤权：历史信封仍有效，新签名被拒")
    import time as _t
    _t.sleep(0.002)
    svc.registry.revoke_key("key_alice_0", reason="硬件令牌丢失")
    r1 = svc.verify_envelope(eid)
    line(f"撤权后验真 R1: ok={r1['ok']} "
         f"then_valid={r1['signatures']['signatures'][0]['then_valid']} "
         f"current={r1['signatures']['signatures'][0]['current_status']}")
    asm3 = svc.create_assembly("chip-top-R3", "ci-bot",
                               project="chip-top", required_signers=["alice"])
    svc.add_artifact_inline(asm3["assembly_id"], "netlist", "x.v", b"x")
    eid3 = svc.seal(asm3["assembly_id"])["envelope_id"]
    try:
        svc.sign_envelope(eid3, "alice", "key_alice_0", priv_hex=sk_a)
    except Exception as e:
        line(f"  → 撤权密钥签新信封被拒绝 {e.code}")

    # ── D 轮换 ────────────────────────────────────────────────────
    step("D", "签名者密钥与服务密钥轮换")
    sk_a2, pk_a2 = key("alice-new")
    svc.registry.register_key("alice", pk_a2, kid="key_alice_1",
                              label="轮换令牌")
    svc.sign_envelope(eid3, "alice", "key_alice_1", priv_hex=sk_a2)
    svc.publish(eid3)
    r3 = svc.verify_envelope(eid3)
    line("alice 用新密钥 key_alice_1 签 R3 并发布；该密钥不在 R3 封装时"
         "的快照里，验真经服务 key_binding 作证通过 = "
         f"{r3['ok']}（via_binding="
         f"{r3['signatures']['signatures'][0].get('via_binding')}）")
    svc.s.rotate_service_key("季度轮换")
    line(f"服务密钥轮换 → {svc.s.service_public()['kid']}，"
         f"R1 验真仍 ok={svc.verify_envelope(eid)['ok']}，"
         f"R3 仍 ok={svc.verify_envelope(eid3)['ok']}")

    # ── E 同名不同内容冲突 ────────────────────────────────────────
    step("E", "同名不同内容冲突")
    asm4 = svc.create_assembly("chip-top-R1", "ci-bot",
                               project="chip-top",
                               required_signers=["alice"])
    svc.add_artifact_inline(asm4["assembly_id"], "netlist", "evil.v",
                            b"completely different content")
    eid4 = svc.seal(asm4["assembly_id"])["envelope_id"]
    svc.sign_envelope(eid4, "alice", "key_alice_1", priv_hex=sk_a2)
    try:
        svc.publish(eid4)
    except Exception as e:
        line(f"  → {e.code}: {e.message}")

    # ── F 并发同内容唯一信封 ──────────────────────────────────────
    step("F", "6 线程并发封装同一内容")
    for _ in range(6):
        a5 = svc.create_assembly("parallel-x", "ci-bot",
                                 project="P", required_signers=[])
        svc.add_artifact_inline(a5["assembly_id"], "netlist", "p.v",
                                b"parallel identical content")
    asm_ids = [x for x in svc.list_assemblies()
               if x["release_name"] == "parallel-x"]
    with ThreadPoolExecutor(max_workers=6) as ex:
        ids = list(ex.map(
            lambda s: svc.seal(s["assembly_id"])["envelope_id"], asm_ids))
    dirs = [p for p in svc.s.envelopes.iterdir() if p.is_dir()]
    line(f"6 个组装得到的信封 id 去重后 = {len(set(ids))}；"
         f"信封目录总数 = {len(dirs)}（含历史信封）")
    assert len(set(ids)) == 1

    # ── G 篡改拒绝 + 审计 ─────────────────────────────────────────
    step("G", "篡改制品/签名 → 拒绝并留痕")
    a_art = svc._load_envelope(eid)["artifacts"][0]  # noqa: SLF001
    p_art = (svc.s.envelope_path(eid) / "artifacts" / a_art["kind"]
             / a_art["name"])
    orig = p_art.read_bytes()
    p_art.write_bytes(orig[::-1])  # 等长翻转，绕过大小检查
    r = svc.verify_envelope(eid)
    line(f"篡改网表后验真 ok={r['ok']}，"
         f"问题码={[x['code'] for x in r['problems']]}")
    p_art.write_bytes(orig)  # 还原
    sp = svc.s.envelope_path(eid2) / "signatures.json"
    orig_doc = sp.read_bytes()
    doc = read_json(sp)
    doc["signatures"][0]["signature"] = "00" * 64
    write_json(sp, doc)
    r = svc.verify_envelope(eid2)
    line(f"篡改签名后问题码 = {sorted({x['code'] for x in r['problems']})}")
    sp.write_bytes(orig_doc)  # 还原

    rejects = [x for x in svc.s.audit_entries() if x["result"] == "REJECT"]
    line(f"审计链共 {len(svc.s.audit_entries())} 条，其中 REJECT "
         f"{len(rejects)} 条；链完整性 ok={svc.s.verify_audit_chain()['ok']}")

    bundle = str(Path(root) / "R1.tar")
    svc.export_bundle(eid, bundle)
    line(f"离线验真包导出: {bundle}")
    line(f"离线验真（不依赖服务） ok={svc.verify_bundle(bundle)['ok']}")

    line("\n演示完成。" + ("" if keep else "（临时存储将被清理）"))
    if not keep:
        shutil.rmtree(root, ignore_errors=True)
    else:
        line(f"存储保留于 {root}，可用 "
             f"`python3 -m seal.cli --store {root} envelopes` 查看")


if __name__ == "__main__":
    main()
