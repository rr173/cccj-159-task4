"""封装服务领域不变量测试。"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from seal import crypto, merkle
from seal.errors import Conflict, Forbidden, NotFound, SealError
from seal.offline import verify_dir
from seal.service import SealService
from seal.util import digest_json, read_json, write_json


class SealCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.svc = SealService(self.root)
        self.keys = {}

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def signer(self, sid, name=None, kid=None):
        sk, pk = crypto.generate_keypair()
        kid = kid or f"k_{sid}"
        self.svc.registry.register_signer(sid, name or sid.title(), pk,
                                          kid=kid)
        self.keys[sid] = (sk, pk, kid)
        return sk, pk, kid

    def new_assembly(self, name="R1", need=None, parent=None,
                     project="P", by="ci"):
        return self.svc.create_assembly(
            name, by, project=project, required_signers=need or [],
            parent_envelope=parent)

    def add_four(self, aid):
        self.svc.add_artifact_inline(aid, "netlist", "top.v",
                                     b"module top; endmodule")
        self.svc.add_artifact_inline(aid, "constraint", "sdc.json",
                                     {"clock": 2.0})
        self.svc.add_artifact_inline(aid, "module", "modules.json",
                                     ["top", "u_alu"])
        self.svc.add_artifact_inline(aid, "signoff", "signoffs.json",
                                     {"sta": "PASS", "drc": "PASS"})

    def ready(self, name="R1", need=None, parent=None):
        a = self.new_assembly(name, need=need, parent=parent)
        self.add_four(a["assembly_id"])
        return a["assembly_id"]

    def sign_and_publish(self, eid, signers):
        for sid in signers:
            sk, _pk, kid = self.keys[sid]
            self.svc.sign_envelope(eid, sid, kid, priv_hex=sk)
        return self.svc.publish(eid)


class ContentAddressingTest(SealCase):
    def test_same_content_same_id_regardless_of_assembly(self):
        a1 = self.ready("R1")
        a2 = self.ready("R1")
        e1 = self.svc.seal(a1)["envelope_id"]
        e2 = self.svc.seal(a2)["envelope_id"]
        self.assertEqual(e1, e2)

    def test_different_content_different_id(self):
        a1 = self.ready("R1")
        e1 = self.svc.seal(a1)["envelope_id"]
        a2 = self.new_assembly("R1")
        self.svc.add_artifact_inline(a2["assembly_id"], "netlist", "top.v",
                                     b"DIFFERENT")
        e2 = self.svc.seal(a2["assembly_id"])["envelope_id"]
        self.assertNotEqual(e1, e2)

    def test_seal_idempotent_same_assembly(self):
        aid = self.ready("R1")
        e1 = self.svc.seal(aid)["envelope_id"]
        e2 = self.svc.seal(aid)
        self.assertTrue(e2.get("replayed"))
        self.assertEqual(e2["envelope_id"], e1)

    def test_concurrent_seal_single_envelope(self):
        aids = [self.ready("R1") for _ in range(8)]

        def do(aid):
            return self.svc.seal(aid)["envelope_id"]
        with ThreadPoolExecutor(max_workers=8) as ex:
            eids = list(ex.map(do, aids))
        self.assertEqual(len(set(eids)), 1)
        envs = [p for p in self.svc.s.envelopes.iterdir() if p.is_dir()]
        self.assertEqual(len(envs), 1)

    def test_assembly_idempotency_key(self):
        a1 = self.svc.create_assembly("R1", "ci", idempotency_key="abc")
        a2 = self.svc.create_assembly("R1", "ci", idempotency_key="abc")
        self.assertEqual(a1["assembly_id"], a2["assembly_id"])
        self.assertTrue(a2.get("replayed"))

    def test_empty_assembly_cannot_seal(self):
        a = self.new_assembly("R1")
        with self.assertRaises(Conflict) as c:
            self.svc.seal(a["assembly_id"])
        self.assertEqual(c.exception.code, "EMPTY_ASSEMBLY")

    def test_artifact_name_unique_within_assembly(self):
        a = self.new_assembly("R1")
        self.svc.add_artifact_inline(a["assembly_id"], "netlist", "x.v",
                                     b"a")
        with self.assertRaises(Conflict) as c:
            self.svc.add_artifact_inline(a["assembly_id"], "netlist", "x.v",
                                         b"b")
        self.assertEqual(c.exception.code, "ARTIFACT_NAME_EXISTS")


class SigningAndPublishTest(SealCase):
    def test_quorum_blocks_then_passes(self):
        self.signer("alice")
        self.signer("bob")
        aid = self.ready("R2", need=["alice", "bob"])
        eid = self.svc.seal(aid)["envelope_id"]
        self.svc.sign_envelope(eid, "alice", self.keys["alice"][2],
                               priv_hex=self.keys["alice"][0])
        with self.assertRaises(Conflict) as c:
            self.svc.publish(eid)
        self.assertEqual(c.exception.code, "QUORUM_NOT_MET")
        self.svc.sign_envelope(eid, "bob", self.keys["bob"][2],
                               priv_hex=self.keys["bob"][0])
        pub = self.svc.publish(eid)
        self.assertEqual(pub["release_name"], "R2")
        self.assertTrue(self.svc.verify_envelope(eid)["ok"])

    def test_duplicate_signature_rejected(self):
        self.signer("alice")
        aid = self.ready("R3", need=["alice"])
        eid = self.svc.seal(aid)["envelope_id"]
        self.svc.sign_envelope(eid, "alice", "k_alice",
                               priv_hex=self.keys["alice"][0])
        with self.assertRaises(Conflict) as c:
            self.svc.sign_envelope(eid, "alice", "k_alice",
                                   priv_hex=self.keys["alice"][0])
        self.assertEqual(c.exception.code, "ALREADY_SIGNED")

    def test_published_envelope_immutable(self):
        self.signer("alice")
        aid = self.ready("R4", need=["alice"])
        eid = self.svc.seal(aid)["envelope_id"]
        self.sign_and_publish(eid, ["alice"])
        self.signer("carol")
        with self.assertRaises(Conflict) as c:
            self.svc.sign_envelope(eid, "carol", "k_carol",
                                   priv_hex=self.keys["carol"][0])
        self.assertEqual(c.exception.code, "ENVELOPE_IMMUTABLE")

    def test_publish_idempotent(self):
        self.signer("alice")
        aid = self.ready("R5", need=["alice"])
        eid = self.svc.seal(aid)["envelope_id"]
        self.sign_and_publish(eid, ["alice"])
        again = self.svc.publish(eid)
        self.assertTrue(again.get("replayed"))

    def test_same_name_different_content_conflict(self):
        self.signer("alice")
        a1 = self.ready("R6", need=["alice"])
        e1 = self.svc.seal(a1)["envelope_id"]
        self.sign_and_publish(e1, ["alice"])
        a2 = self.new_assembly("R6", need=["alice"])
        self.svc.add_artifact_inline(a2["assembly_id"], "netlist", "x.v",
                                     b"different bytes")
        e2 = self.svc.seal(a2["assembly_id"])["envelope_id"]
        self.svc.sign_envelope(e2, "alice", "k_alice",
                               priv_hex=self.keys["alice"][0])
        with self.assertRaises(Conflict) as c:
            self.svc.publish(e2)
        self.assertEqual(c.exception.code, "NAME_CONFLICT")

    def test_lineage(self):
        self.signer("alice")
        a1 = self.ready("base", need=["alice"])
        e1 = self.svc.seal(a1)["envelope_id"]
        self.sign_and_publish(e1, ["alice"])
        a2 = self.ready("child", need=["alice"], parent=e1)
        e2 = self.svc.seal(a2)["envelope_id"]
        self.sign_and_publish(e2, ["alice"])
        lin = self.svc.lineage(e2)
        self.assertEqual(lin["depth"], 2)
        self.assertEqual([x["release_name"] for x in lin["ancestors"]],
                         ["base", "child"])

    def test_external_offline_signature(self):
        # 签名者在外部用私钥对签名声明签名，再把签名提交给服务
        self.signer("alice")
        aid = self.ready("R7", need=["alice"])
        eid = self.svc.seal(aid)["envelope_id"]
        sk, _pk, _kid = self.keys["alice"]
        from seal.service import SealService as SS
        from seal.util import utcnow
        ts = utcnow()
        claim = SS._signing_claim(eid, "alice", "k_alice", ts)
        from seal.util import canon
        sig = crypto.sign(sk, canon(claim))
        self.svc.sign_envelope(eid, "alice", "k_alice", signature=sig,
                               signed_at=ts)
        self.assertTrue(self.svc.verify_envelope(eid)["ok"])

    def test_external_bad_signature_rejected(self):
        self.signer("alice")
        aid = self.ready("R8", need=["alice"])
        eid = self.svc.seal(aid)["envelope_id"]
        with self.assertRaises(Forbidden) as c:
            self.svc.sign_envelope(eid, "alice", "k_alice",
                                   signature="00" * 64,
                                   signed_at=__import__("seal.util",
                                                       fromlist=["utcnow"])
                                   .utcnow())
        self.assertEqual(c.exception.code, "BAD_SIGNATURE")

    def test_backdated_external_signature_rejected(self):
        # 撤权后试图把 signed_at 回填到撤权前：时间窗校验拒绝
        self.signer("alice")
        aid = self.ready("R8b", need=["alice"])
        eid = self.svc.seal(aid)["envelope_id"]
        sk, _pk, _kid = self.keys["alice"]
        old_ts = "2000-01-01T00:00:00.000000Z"
        claim = SealService._signing_claim(eid, "alice", "k_alice", old_ts)
        from seal.util import canon
        sig = crypto.sign(sk, canon(claim))
        with self.assertRaises(Forbidden) as c:
            self.svc.sign_envelope(eid, "alice", "k_alice",
                                   signature=sig, signed_at=old_ts)
        self.assertIn(c.exception.code,
                      ("SIGNED_AT_BEFORE_KEY_REGISTERED", "SIGNED_AT_TOO_OLD"))

    def test_wrong_key_for_signer_rejected(self):
        self.signer("alice")
        self.signer("bob")
        aid = self.ready("R9", need=["bob"])
        eid = self.svc.seal(aid)["envelope_id"]
        with self.assertRaises(Forbidden) as c:
            self.svc.sign_envelope(eid, "bob", "k_alice",
                                   priv_hex=self.keys["alice"][0])
        self.assertEqual(c.exception.code, "KEY_SIGNER_MISMATCH")


class RevocationRotationTest(SealCase):
    def _published(self, name="RR"):
        self.signer("alice")
        aid = self.ready(name, need=["alice"])
        eid = self.svc.seal(aid)["envelope_id"]
        self.sign_and_publish(eid, ["alice"])
        return eid

    def test_revocation_keeps_historical_validity(self):
        eid = self._published()
        time.sleep(0.002)
        self.svc.registry.revoke_key("k_alice", reason="left")
        r = self.svc.verify_envelope(eid)
        self.assertTrue(r["ok"], r["problems"])
        sig = r["signatures"]["signatures"][0]
        self.assertTrue(sig["then_valid"])
        self.assertEqual(sig["current_status"], "REVOKED")

    def test_revoked_key_cannot_sign_new(self):
        eid = self._published()
        self.svc.registry.revoke_key("k_alice")
        a = self.new_assembly("RR-new", need=["alice"])
        self.svc.add_artifact_inline(a["assembly_id"], "netlist", "n.v",
                                     b"new")
        e2 = self.svc.seal(a["assembly_id"])["envelope_id"]
        with self.assertRaises(Forbidden) as c:
            self.svc.sign_envelope(e2, "alice", "k_alice",
                                   priv_hex=self.keys["alice"][0])
        self.assertEqual(c.exception.code, "SIGNER_KEY_REVOKED")

    def test_rotated_key_flow(self):
        self.signer("alice")
        self.svc.registry.revoke_key("k_alice", reason="compromise")
        sk2, pk2 = crypto.generate_keypair()
        self.svc.registry.register_key("alice", pk2, kid="k_alice_1")
        a = self.new_assembly("RR2", need=["alice"])
        self.svc.add_artifact_inline(a["assembly_id"], "netlist", "n.v",
                                     b"new")
        eid = self.svc.seal(a["assembly_id"])["envelope_id"]
        with self.assertRaises(Forbidden):
            self.svc.sign_envelope(eid, "alice", "k_alice",
                                   priv_hex=self.keys["alice"][0])
        self.svc.sign_envelope(eid, "alice", "k_alice_1", priv_hex=sk2)

    def test_service_key_rotation_preserves_verification(self):
        eid = self._published()
        self.svc.s.rotate_service_key("routine")
        self.assertTrue(self.svc.verify_envelope(eid)["ok"])

    def test_key_registered_after_seal_verifies_via_binding(self):
        # 封装时快照里没有的新密钥，签名后经服务 key_binding 作证仍可验
        # （在线与离线 bundle 都成立），伪造绑定则失败
        self.signer("alice")
        a = self.ready("RR3", need=[])
        eid = self.svc.seal(a)["envelope_id"]
        sk2, pk2 = crypto.generate_keypair()
        self.svc.registry.register_key("alice", pk2, kid="k_alice_new")
        self.svc.sign_envelope(eid, "alice", "k_alice_new", priv_hex=sk2)
        self.svc.publish(eid, require_quorum=False)
        r = self.svc.verify_envelope(eid)
        self.assertTrue(r["ok"], r["problems"])
        self.assertTrue(r["signatures"]["signatures"][0]["via_binding"])
        out = os.path.join(self.root, "b.tar")
        self.svc.export_bundle(eid, out)
        self.assertTrue(self.svc.verify_bundle(out)["ok"])
        # 篡改绑定作证的公钥 → 离线拒绝
        sp = self.svc.s.envelope_path(eid) / "signatures.json"
        doc = read_json(sp)
        _sk3, pk3 = crypto.generate_keypair()
        doc["signatures"][0]["key_binding"]["public_key"] = pk3
        write_json(sp, doc)
        r = self.svc.verify_envelope(eid)
        self.assertFalse(r["ok"])


class ChunkUploadTest(SealCase):
    def _data(self, n=100_000):
        return bytes((i * 13 + 7) % 256 for i in range(n))

    def test_resume_out_of_order(self):
        self.signer("alice")
        a = self.new_assembly("CH", need=["alice"])
        data = self._data()
        cs = 32768
        u = self.svc.start_upload(a["assembly_id"], "netlist", "big.bin",
                                  len(data), chunk_size=cs)
        sid = u["session_id"]
        self.assertEqual(u["total_chunks"], 4)
        self.svc.put_chunk(sid, 0, data[0:cs])
        self.svc.put_chunk(sid, 2, data[2 * cs:3 * cs])
        with self.assertRaises(Conflict) as c:
            self.svc.complete_upload(sid)
        self.assertEqual(c.exception.code, "UPLOAD_INCOMPLETE")
        self.svc.put_chunk(sid, 1, data[cs:2 * cs])
        self.svc.put_chunk(sid, 3, data[3 * cs:])
        self.svc.complete_upload(sid)
        eid = self.svc.seal(a["assembly_id"])["envelope_id"]
        got, _ = self.svc.artifact_bytes(eid, "big.bin")
        self.assertEqual(got, data)
        self.sign_and_publish(eid, ["alice"])
        self.assertTrue(self.svc.verify_envelope(eid)["ok"])

    def test_chunk_replay_idempotent(self):
        a = self.new_assembly("CH2")
        data = self._data(50_000)
        u = self.svc.start_upload(a["assembly_id"], "netlist", "b.bin",
                                  len(data), chunk_size=20000)
        sid = u["session_id"]
        self.svc.put_chunk(sid, 0, data[0:20000])
        r = self.svc.put_chunk(sid, 0, data[0:20000])
        self.assertTrue(r.get("replayed"))

    def test_chunk_conflict_on_different_content(self):
        a = self.new_assembly("CH3")
        data = self._data(50_000)
        u = self.svc.start_upload(a["assembly_id"], "netlist", "b.bin",
                                  len(data), chunk_size=20000)
        sid = u["session_id"]
        self.svc.put_chunk(sid, 0, data[0:20000])
        from seal.errors import BadRequest
        with self.assertRaises(BadRequest) as c:
            self.svc.put_chunk(sid, 0, b"X" * 20000)
        self.assertEqual(c.exception.code, "CHUNK_CONFLICT")

    def test_chunk_size_mismatch_rejected(self):
        a = self.new_assembly("CH4")
        u = self.svc.start_upload(a["assembly_id"], "netlist", "b.bin",
                                  10000, chunk_size=4096)
        from seal.errors import BadRequest
        with self.assertRaises(BadRequest) as c:
            self.svc.put_chunk(u["session_id"], 0, b"short")
        self.assertEqual(c.exception.code, "CHUNK_SIZE_MISMATCH")

    def test_chunk_digest_header_checked(self):
        a = self.new_assembly("CH5")
        u = self.svc.start_upload(a["assembly_id"], "netlist", "b.bin",
                                  10000, chunk_size=4096)
        from seal.errors import BadRequest
        with self.assertRaises(BadRequest) as c:
            self.svc.put_chunk(u["session_id"], 0, b"x" * 4096,
                               digest="aa" * 32)
        self.assertEqual(c.exception.code, "CHUNK_DIGEST_MISMATCH")

    def test_abort_then_complete_rejected(self):
        a = self.new_assembly("CH6")
        u = self.svc.start_upload(a["assembly_id"], "netlist", "b.bin",
                                  10000, chunk_size=4096)
        self.svc.abort_upload(u["session_id"])
        with self.assertRaises(Conflict) as c:
            self.svc.put_chunk(u["session_id"], 0, b"x" * 4096)
        self.assertEqual(c.exception.code, "UPLOAD_NOT_OPEN")


class TamperTest(SealCase):
    def _env(self, content=b"module top;", name="R1"):
        self.signer("alice")
        a = self.new_assembly(name, need=["alice"])
        self.svc.add_artifact_inline(a["assembly_id"], "netlist", "top.v",
                                     content)
        eid = self.svc.seal(a["assembly_id"])["envelope_id"]
        self.sign_and_publish(eid, ["alice"])
        return eid

    def test_artifact_tamper_rejected_and_audited(self):
        eid = self._env(b"same-length-content")
        p = self.svc.s.envelope_path(eid) / "artifacts/netlist/top.v"
        p.write_bytes(b"EVIL-CONTENT-HERE00")  # 等长 19 字节
        r = self.svc.verify_envelope(eid)
        self.assertFalse(r["ok"])
        self.assertIn("ARTIFACT_DIGEST_MISMATCH",
                      [x["code"] for x in r["problems"]])
        rejects = [x for x in self.svc.s.audit_entries()
                   if x["result"] == "REJECT"]
        self.assertTrue(any(x["reason"] == "ARTIFACT_DIGEST_MISMATCH"
                            for x in rejects))

    def test_signature_tamper_rejected(self):
        eid = self._env()
        sp = self.svc.s.envelope_path(eid) / "signatures.json"
        doc = read_json(sp)
        doc["signatures"][0]["signature"] = "00" * 64
        write_json(sp, doc)
        r = self.svc.verify_envelope(eid)
        codes = {x["code"] for x in r["problems"]}
        self.assertIn("SIGNATURE_INVALID", codes)
        self.assertIn("ROSTER_DIGEST_MISMATCH", codes)

    def test_injected_signature_rejected(self):
        eid = self._env()
        sp = self.svc.s.envelope_path(eid) / "signatures.json"
        doc = read_json(sp)
        _sk, pk = crypto.generate_keypair()
        doc["signatures"].append({
            "signer_id": "eve", "kid": "k_eve", "public_key": pk,
            "signed_at": doc["signatures"][0]["signed_at"],
            "alg": "Ed25519", "signature": "11" * 64})
        write_json(sp, doc)
        r = self.svc.verify_envelope(eid)
        codes = {x["code"] for x in r["problems"]}
        self.assertTrue({"SIGNATURE_INVALID", "ROSTER_DIGEST_MISMATCH"}
                        <= codes)

    def test_manifest_tamper_rejected(self):
        eid = self._env()
        mp = self.svc.s.envelope_path(eid) / "manifest.json"
        m = read_json(mp)
        m["content"]["release_name"] = "HACKED"
        write_json(mp, m)
        with self.assertRaises(SealError) as c:
            self.svc.verify_envelope(eid)
        self.assertEqual(c.exception.code, "MANIFEST_TAMPERED")

    def test_chunk_tamper_rejected(self):
        self.signer("alice")
        a = self.new_assembly("CT", need=["alice"])
        data = b"".join(bytes([i % 256]) * 5000 for i in range(10))
        u = self.svc.start_upload(a["assembly_id"], "netlist", "big.bin",
                                  len(data), chunk_size=20000)
        for i in range(u["total_chunks"]):
            self.svc.put_chunk(u["session_id"], i,
                               data[i * 20000:(i + 1) * 20000])
        self.svc.complete_upload(u["session_id"])
        eid = self.svc.seal(a["assembly_id"])["envelope_id"]
        self.sign_and_publish(eid, ["alice"])
        cf = [p for p in (self.svc.s.envelope_path(eid) / "chunks").rglob("*")
              if p.is_file()][0]
        b = bytearray(cf.read_bytes())
        b[0] ^= 0xFF
        cf.write_bytes(bytes(b))
        r = self.svc.verify_envelope(eid)
        self.assertIn("CHUNK_TAMPERED", [x["code"] for x in r["problems"]])

    def test_merkle_proof_tamper_rejected(self):
        self.signer("alice")
        a = self.new_assembly("MT", need=["alice"])
        self.svc.add_artifact_inline(a["assembly_id"], "netlist", "a.v",
                                     b"aaaa")
        self.svc.add_artifact_inline(a["assembly_id"], "netlist", "b.v",
                                     b"bbbb")
        eid = self.svc.seal(a["assembly_id"])["envelope_id"]
        self.sign_and_publish(eid, ["alice"])
        pf = self.svc.s.envelope_path(eid) / "merkle_proofs.json"
        d = read_json(pf)
        k = next(iter(d["proofs"]))
        self.assertTrue(d["proofs"][k])  # 两叶时证明非空
        d["proofs"][k][0]["sibling"] = "aa" * 32
        write_json(pf, d)
        r = self.svc.verify_envelope(eid)
        self.assertIn("MERKLE_PROOF_INVALID",
                      [x["code"] for x in r["problems"]])

    def test_registry_snapshot_tamper_rejected(self):
        eid = self._env()
        mp = self.svc.s.envelope_path(eid) / "manifest.json"
        m = read_json(mp)
        m["registry_snapshot"]["signers"][0]["name"] = "ATTACKER"
        write_json(mp, m)
        r = self.svc.verify_envelope(eid)
        self.assertFalse(r["ok"])
        self.assertIn("REGISTRY_SNAPSHOT_DIGEST_MISMATCH",
                      [x["code"] for x in r["problems"]])

    def test_inclusion_proof_verifies(self):
        eid = self._env()
        env = self.svc._load_envelope(eid)
        art = env["artifacts"][0]
        pr = self.svc.inclusion_proof(eid, art["name"])
        self.assertTrue(merkle.verify_proof(
            pr["merkle_root"], bytes.fromhex(pr["digest"]), pr["proof"]))
        # 错误叶不应通过
        self.assertFalse(merkle.verify_proof(
            pr["merkle_root"], bytes.fromhex("aa" * 32), pr["proof"]))


class RecoveryTest(SealCase):
    def test_reopen_preserves_upload_session(self):
        a = self.new_assembly("RC")
        data = b"0123456789" * 1000
        u = self.svc.start_upload(a["assembly_id"], "netlist", "b.txt",
                                  len(data), chunk_size=4096)
        self.svc.put_chunk(u["session_id"], 0, data[0:4096])
        svc2 = SealService(self.root)  # 重新打开
        st = svc2.upload_status(u["session_id"])
        self.assertEqual(st["total_chunks"], 3)
        self.assertEqual([c["received"] for c in st["chunks"]],
                         [True, False, False])

    def test_recover_clears_temp_and_resets_sealing(self):
        a = self.new_assembly("RC2")
        self.svc.add_artifact_inline(a["assembly_id"], "netlist", "a.v",
                                     b"aaa")
        sp = self.svc.s.assembly_path(a["assembly_id"]) / "state.json"
        st = read_json(sp)
        st["state"] = "SEALING"
        write_json(sp, st)
        tmp = self.svc.s.envelopes / ".tmp-asm_x-junk"
        tmp.mkdir(parents=True)
        (tmp / "junk").write_text("x")
        svc2 = SealService(self.root)
        self.assertFalse(any(self.svc.s.envelopes.glob(".tmp-*")))
        self.assertEqual(read_json(sp)["state"], "OPEN")
        # 仍可正常封装，且只有一个信封
        eid = svc2.seal(a["assembly_id"])["envelope_id"]
        self.assertEqual(len([p for p in self.svc.s.envelopes.iterdir()
                              if p.is_dir()]), 1)
        self.assertTrue(svc2.verify_envelope(eid)["ok"])

    def test_recover_interrupted_publish(self):
        self.signer("bob")
        a = self.new_assembly("RC3", need=["bob"])
        self.svc.add_artifact_inline(a["assembly_id"], "netlist", "b.v",
                                     b"bbb")
        eid = self.svc.seal(a["assembly_id"])["envelope_id"]
        self.svc.sign_envelope(eid, "bob", "k_bob",
                               priv_hex=self.keys["bob"][0])
        self.svc.s.journal_append("PUBLISH_INTENT", {
            "envelope_id": eid, "name": "RC3",
            "dir": str(self.svc.s.envelope_path(eid))})
        svc2 = SealService(self.root)
        r = svc2.verify_envelope(eid)
        self.assertEqual(r["state"], "PUBLISHED")
        self.assertTrue(r["ok"])
        self.assertTrue(svc2.s.name_path("RC3").exists())
        svc3 = SealService(self.root)  # 再次恢复幂等
        self.assertEqual(read_json(svc3.s.name_path("RC3"))["envelope_id"],
                         eid)

    def test_audit_tamper_forces_readonly(self):
        log = self.svc.s.audit_dir / "log.jsonl"
        self.svc.audit("x", {"k": 1})
        lines = log.read_text().splitlines()
        rec = json.loads(lines[0])
        rec["actor"] = "attacker"
        lines[0] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
        log.write_text("\n".join(lines) + "\n")
        svc2 = SealService(self.root)
        self.assertTrue(svc2.read_only)
        with self.assertRaises(Forbidden) as c:
            svc2.create_assembly("Z", "ci")
        self.assertEqual(c.exception.code, "SERVICE_READ_ONLY")

    def test_registry_event_tamper_detected(self):
        self.signer("alice")
        p = self.svc.s.registry / "events.log"
        lines = p.read_text().splitlines()
        rec = json.loads(lines[0])
        rec["name"] = "TAMPERED"
        lines[0] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
        p.write_text("\n".join(lines) + "\n")
        from seal.errors import VerifyFailed
        with self.assertRaises(VerifyFailed):
            SealService(self.root)


class BundleTest(SealCase):
    def test_offline_bundle_roundtrip(self):
        self.signer("alice")
        self.signer("bob")
        aid = self.ready("BN", need=["alice", "bob"])
        eid = self.svc.seal(aid)["envelope_id"]
        self.sign_and_publish(eid, ["alice", "bob"])
        out = os.path.join(self.root, "e.tar")
        self.svc.export_bundle(eid, out)
        r = self.svc.verify_bundle(out)
        self.assertTrue(r["ok"], r["problems"])
        genesis = self.svc.s.service_history()["keys"][0]["public_key"]
        self.assertTrue(self.svc.verify_bundle(out, trust_pub=genesis)["ok"])
        self.assertFalse(
            self.svc.verify_bundle(out, trust_pub="aa" * 32)["ok"])

    def test_verify_dir_after_revoke_offline(self):
        # 撤权是注册表演进；已发布信封内嵌快照，离线仍有效
        self.signer("alice")
        eid = self._published()
        time.sleep(0.002)
        self.svc.registry.revoke_key("k_alice")
        r = verify_dir(self.svc.s.envelope_path(eid))
        self.assertTrue(r["ok"], r["problems"])

    def _published(self):
        aid = self.ready("BN2", need=["alice"])
        eid = self.svc.seal(aid)["envelope_id"]
        self.sign_and_publish(eid, ["alice"])
        return eid


if __name__ == "__main__":
    unittest.main()
