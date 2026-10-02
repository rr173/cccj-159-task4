"""HTTP REST 端到端测试（真实 ThreadingHTTPServer + socket 请求）。"""
from __future__ import annotations

import base64
import json
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from seal import crypto, merkle
from seal.httpapi import make_handler
from seal.service import SealService


class HttpApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        cls.svc = SealService(cls.root)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0),
                                        make_handler(cls.svc))
        cls.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.th = threading.Thread(target=cls.httpd.serve_forever,
                                  daemon=True)
        cls.th.start()
        cls.sk, cls.pk = crypto.generate_keypair()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.root, ignore_errors=True)

    def req(self, method, path, body=None, raw=None, headers=None):
        url = self.base + path
        data = None
        hdr = headers or {}
        if raw is not None:
            data = raw
            hdr.setdefault("Content-Type", "application/octet-stream")
        elif body is not None:
            data = json.dumps(body).encode()
            hdr["Content-Type"] = "application/json"
        r = urllib.request.Request(url, data=data, headers=hdr, method=method)
        try:
            with urllib.request.urlopen(r) as resp:
                payload = resp.read()
                ct = resp.headers.get("Content-Type", "")
                code = resp.status
        except urllib.error.HTTPError as e:
            payload = e.read()
            ct = e.headers.get("Content-Type", "")
            code = e.code
        if "application/json" in ct:
            return code, json.loads(payload or b"{}")
        return code, payload

    def test_01_health_and_static(self):
        code, h = self.req("GET", "/api/health")
        self.assertEqual(code, 200)
        self.assertFalse(h["read_only"])
        code, html = self.req("GET", "/")
        self.assertEqual(code, 200)
        self.assertIn(b"<!DOCTYPE html>", html)
        code, js = self.req("GET", "/static/app.js")
        self.assertEqual(code, 200)
        self.assertIn(b"loadEnvelopes", js)

    def test_02_full_flow(self):
        code, r = self.req("POST", "/api/signers",
                           {"signer_id": "alice", "name": "Alice",
                            "public_key": self.pk, "kid": "k_alice"})
        self.assertEqual(code, 201)
        code, a = self.req("POST", "/api/assemblies",
                           {"release_name": "R-http", "created_by": "ci",
                            "required_signers": ["alice"]})
        self.assertEqual(code, 201)
        aid = a["assembly_id"]
        code, _ = self.req(
            "POST", f"/api/assemblies/{aid}/artifacts",
            {"kind": "netlist", "name": "top.v",
             "content_base64":
                 base64.b64encode(b"module top; // R-http unique").decode(),
             "by": "ci"})
        self.assertEqual(code, 201)
        code, env = self.req("POST", f"/api/assemblies/{aid}/seal", {})
        self.assertEqual(code, 200)
        eid = env["envelope_id"]
        code, _ = self.req("POST", f"/api/envelopes/{eid}/sign",
                           {"signer_id": "alice", "kid": "k_alice",
                            "priv_hex": self.sk})
        self.assertEqual(code, 200)
        code, pub = self.req("POST", f"/api/envelopes/{eid}/publish", {})
        self.assertEqual(code, 200)
        self.assertEqual(pub["release_name"], "R-http")
        code, v = self.req("GET", f"/api/envelopes/{eid}/verify")
        self.assertEqual(code, 200)
        self.assertTrue(v["ok"], v["problems"])
        code, lin = self.req("GET", f"/api/envelopes/{eid}/lineage")
        self.assertEqual(lin["depth"], 1)
        code, pr = self.req(
            "GET", f"/api/envelopes/{eid}/proof?name=top.v")
        self.assertEqual(code, 200)
        self.assertTrue(merkle.verify_proof(
            pr["merkle_root"], bytes.fromhex(pr["digest"]), pr["proof"]))
        code, bundle = self.req("GET", f"/api/envelopes/{eid}/bundle")
        self.assertEqual(code, 200)
        self.assertIn(b"manifest.json", bundle)  # tar 含文件名

    def test_03_chunked_upload_resume_over_http(self):
        code, a = self.req("POST", "/api/assemblies",
                           {"release_name": "R-chunk", "created_by": "ci",
                            "required_signers": ["alice"]})
        aid = a["assembly_id"]
        data = bytes((i * 31 + 5) % 256 for i in range(70000))
        code, u = self.req(
            "POST", f"/api/assemblies/{aid}/uploads",
            {"kind": "netlist", "name": "rand.bin", "size": len(data),
             "chunk_size": 32768})
        sid = u["session_id"]
        total = u["total_chunks"]
        # 先传除最后一块外的全部
        for i in range(total - 1):
            blk = data[i * 32768:(i + 1) * 32768]
            code, _ = self.req(
                "PUT", f"/api/uploads/{sid}/chunks/{i}", raw=blk)
            self.assertEqual(code, 200)
        code, r = self.req("POST", f"/api/uploads/{sid}/complete", {})
        self.assertEqual(code, 409)
        self.assertEqual(r["error"], "UPLOAD_INCOMPLETE")
        # 续传最后一块
        blk = data[(total - 1) * 32768:]
        code, _ = self.req("PUT",
                           f"/api/uploads/{sid}/chunks/{total - 1}",
                           raw=blk)
        self.assertEqual(code, 200)
        code, _ = self.req("POST", f"/api/uploads/{sid}/complete", {})
        self.assertEqual(code, 200)
        code, env = self.req("POST", f"/api/assemblies/{aid}/seal", {})
        eid = env["envelope_id"]
        code, _ = self.req("POST", f"/api/envelopes/{eid}/sign",
                           {"signer_id": "alice", "kid": "k_alice",
                            "priv_hex": self.sk})
        code, _ = self.req("POST", f"/api/envelopes/{eid}/publish", {})
        code, v = self.req("GET", f"/api/envelopes/{eid}/verify")
        self.assertTrue(v["ok"], v["problems"])
        code, got = self.req(
            "GET", f"/api/envelopes/{eid}/artifacts/rand.bin")
        self.assertEqual(got, data)

    def test_04_chunk_digest_header_enforced(self):
        code, a = self.req("POST", "/api/assemblies",
                           {"release_name": "R-chd", "created_by": "ci"})
        aid = a["assembly_id"]
        code, u = self.req(
            "POST", f"/api/assemblies/{aid}/uploads",
            {"kind": "netlist", "name": "b.bin", "size": 8192,
             "chunk_size": 8192})
        sid = u["session_id"]
        code, r = self.req("PUT", f"/api/uploads/{sid}/chunks/0",
                           raw=b"x" * 8192,
                           headers={"X-Chunk-Digest": "aa" * 32})
        self.assertEqual(code, 400)
        self.assertEqual(r["error"], "CHUNK_DIGEST_MISMATCH")

    def test_05_name_conflict_and_error_shape(self):
        code, a = self.req("POST", "/api/assemblies",
                           {"release_name": "R-dup", "created_by": "ci",
                            "required_signers": ["alice"]})
        aid = a["assembly_id"]
        self.req("POST", f"/api/assemblies/{aid}/artifacts",
                 {"kind": "netlist", "name": "x.v",
                  "content_base64": base64.b64encode(b"one").decode()})
        code, env = self.req("POST", f"/api/assemblies/{aid}/seal", {})
        eid = env["envelope_id"]
        self.req("POST", f"/api/envelopes/{eid}/sign",
                 {"signer_id": "alice", "kid": "k_alice",
                  "priv_hex": self.sk})
        self.req("POST", f"/api/envelopes/{eid}/publish", {})
        # 同名不同内容
        code, a2 = self.req("POST", "/api/assemblies",
                            {"release_name": "R-dup", "created_by": "ci",
                             "required_signers": ["alice"]})
        self.req("POST", f"/api/assemblies/{a2['assembly_id']}/artifacts",
                 {"kind": "netlist", "name": "x.v",
                  "content_base64": base64.b64encode(b"TWO").decode()})
        code, env2 = self.req(
            "POST", f"/api/assemblies/{a2['assembly_id']}/seal", {})
        self.req("POST", f"/api/envelopes/{env2['envelope_id']}/sign",
                 {"signer_id": "alice", "kid": "k_alice",
                  "priv_hex": self.sk})
        code, r = self.req("POST",
                           f"/api/envelopes/{env2['envelope_id']}/publish",
                           {})
        self.assertEqual(code, 409)
        self.assertEqual(r["error"], "NAME_CONFLICT")
        self.assertIn("message", r)
        self.assertIn("detail", r)

    def test_06_revocation_keeps_history_and_audit(self):
        code, _ = self.req("POST", "/api/keys/k_alice/revoke",
                           {"reason": "left"})
        self.assertEqual(code, 200)
        # 已发布的 R-http 仍验真通过
        code, es = self.req("GET", "/api/envelopes")
        rhttp = next(e for e in es["envelopes"]
                     if e["release_name"] == "R-http")
        code, v = self.req("GET",
                           f"/api/envelopes/{rhttp['envelope_id']}/verify")
        self.assertTrue(v["ok"])
        code, au = self.req("GET", "/api/audit")
        self.assertEqual(code, 200)
        actions = {e["action"] for e in au["entries"]}
        self.assertIn("publish", actions)
        # 拒收（分块摘要不符）已在 test_04 触发，应留 REJECT
        rejects = [e for e in au["entries"] if e["result"] == "REJECT"]
        self.assertTrue(any(e["reason"] == "CHUNK_DIGEST_MISMATCH"
                            for e in rejects))


if __name__ == "__main__":
    unittest.main()
