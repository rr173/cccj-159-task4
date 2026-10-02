"""HTTP REST 接口（标准库 http.server，零第三方依赖）。

启动: python -m seal.httpapi --store sealdata --port 8090
页面: http://localhost:8090/  （信封谱系/签名状态/校验结果看板）

分块上传用原始字节 body：
  PUT /api/uploads/{sid}/chunks/{seq}        （Content-Type: application/octet-stream）
  可选请求头 X-Chunk-Digest 声明分块 SHA-256（不符即拒绝）。
"""
from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .errors import SealError
from .service import SealService

WEB_DIR = Path(__file__).resolve().parent / "web"
_MIME = {".html": "text/html; charset=utf-8",
         ".js": "application/javascript; charset=utf-8",
         ".css": "text/css; charset=utf-8",
         ".svg": "image/svg+xml"}


def make_handler(svc: SealService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "DesignSeal/1.0"

        def log_message(self, fmt, *args):
            pass

        # ------------------------------------------------------------ 基础
        def _send(self, code, payload, ctype="application/json"):
            if isinstance(payload, (dict, list)):
                body = json.dumps(payload, ensure_ascii=False, indent=2) \
                    .encode("utf-8")
            elif isinstance(payload, str):
                body = payload.encode("utf-8")
            else:
                body = payload
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b"{}"
            try:
                return json.loads(raw or b"{}")
            except json.JSONDecodeError:
                raise SealError("BAD_JSON", "请求体不是合法 JSON", 400)

        def _raw(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def _q(self, name, default=None):
            qs = parse_qs(urlparse(self.path).query)
            return qs[name][0] if name in qs else default

        def _err(self, e: SealError):
            self._send(e.http_status, {"error": e.code,
                                       "message": e.message,
                                       "detail": e.detail})

        def _static(self, rel: str):
            p = (WEB_DIR / rel).resolve()
            if not str(p).startswith(str(WEB_DIR.resolve())) or not p.is_file():
                self._send(404, {"error": "NOT_FOUND", "message": rel})
                return
            self._send(200, p.read_bytes(),
                       _MIME.get(p.suffix, "application/octet-stream"))

        # ------------------------------------------------------------ 路由
        def do_GET(self):
            path = urlparse(self.path).path.rstrip("/") or "/"
            try:
                if path == "/":
                    return self._static("index.html")
                if path.startswith("/static/"):
                    return self._static(path[len("/static/"):])
                m = re.fullmatch(r"/api/health", path)
                if m:
                    return self._send(200, svc.health())
                m = re.fullmatch(r"/api/signers", path)
                if m:
                    return self._send(200, {"signers":
                                            svc.registry.signer_summary()})
                m = re.fullmatch(r"/api/audit", path)
                if m:
                    return self._send(200, {"entries":
                                            svc.s.audit_entries()})
                m = re.fullmatch(r"/api/assemblies", path)
                if m:
                    return self._send(200, {"assemblies":
                                            svc.list_assemblies()})
                m = re.fullmatch(r"/api/assemblies/(asm_[A-Za-z0-9]+)", path)
                if m:
                    return self._send(200, svc.get_assembly(m.group(1)))
                m = re.fullmatch(r"/api/uploads/(upl_[A-Za-z0-9]+)", path)
                if m:
                    return self._send(200, svc.upload_status(m.group(1)))
                m = re.fullmatch(r"/api/envelopes", path)
                if m:
                    return self._send(200, {"envelopes":
                                            svc.list_envelopes()})
                m = re.fullmatch(r"/api/envelopes/([A-Fa-f0-9]{64})", path)
                if m:
                    return self._send(200, svc._load_envelope(m.group(1)))
                m = re.fullmatch(r"/api/envelopes/([A-Fa-f0-9]{64})/verify",
                                 path)
                if m:
                    return self._send(200, svc.verify_envelope(m.group(1)))
                m = re.fullmatch(r"/api/envelopes/([A-Fa-f0-9]{64})/lineage",
                                 path)
                if m:
                    return self._send(200, svc.lineage(m.group(1)))
                m = re.fullmatch(
                    r"/api/envelopes/([A-Fa-f0-9]{64})/proof", path)
                if m:
                    name = self._q("name")
                    if not name:
                        raise SealError("BAD_REQUEST",
                                        "需要 name 查询参数", 400)
                    return self._send(200,
                                      svc.inclusion_proof(m.group(1), name))
                m = re.fullmatch(
                    r"/api/envelopes/([A-Fa-f0-9]{64})/artifacts/(.+)", path)
                if m:
                    data, art = svc.artifact_bytes(m.group(1),
                                                   m.group(2))
                    self.send_response(200)
                    self.send_header("Content-Type", art.get(
                        "content_type", "application/octet-stream"))
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    return self.wfile.write(data)
                m = re.fullmatch(r"/api/envelopes/([A-Fa-f0-9]{64})/bundle",
                                 path)
                if m:
                    import tempfile
                    out = tempfile.mktemp(suffix=".tar")
                    svc.export_bundle(m.group(1), out)
                    body = Path(out).read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-tar")
                    self.send_header(
                        "Content-Disposition",
                        f'attachment; filename="{m.group(1)[:16]}.tar"')
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    Path(out).unlink(missing_ok=True)
                    return
                m = re.fullmatch(r"/api/names", path)
                if m:
                    out = {}
                    for p in sorted(svc.s.names.iterdir()):
                        if p.is_file():
                            out[p.name] = json.loads(p.read_text())
                    return self._send(200, {"names": out})
                self._send(404, {"error": "NOT_FOUND", "message": path})
            except SealError as e:
                self._err(e)

        def do_POST(self):
            path = urlparse(self.path).path.rstrip("/")
            try:
                m = re.fullmatch(r"/api/service-key/rotate", path)
                if m:
                    b = self._json()
                    return self._send(200,
                                      svc.s.rotate_service_key(
                                          b.get("note", "")))
                m = re.fullmatch(r"/api/signers", path)
                if m:
                    b = self._json()
                    return self._send(201, svc.registry.register_signer(
                        b["signer_id"], b["name"], b["public_key"],
                        kid=b.get("kid"), org=b.get("org", ""),
                        label=b.get("label", "")))
                m = re.fullmatch(
                    r"/api/signers/([A-Za-z0-9_\-]+)/deactivate", path)
                if m:
                    b = self._json()
                    return self._send(200, svc.registry.deactivate_signer(
                        m.group(1), reason=b.get("reason", "")))
                m = re.fullmatch(r"/api/keys", path)
                if m:
                    b = self._json()
                    return self._send(201, {"kid": svc.registry.register_key(
                        b["signer_id"], b["public_key"],
                        kid=b.get("kid"), label=b.get("label", ""))})
                m = re.fullmatch(r"/api/keys/([A-Za-z0-9_\-]+)/revoke", path)
                if m:
                    b = self._json()
                    return self._send(200, svc.registry.revoke_key(
                        m.group(1), reason=b.get("reason", "")))
                m = re.fullmatch(r"/api/assemblies", path)
                if m:
                    b = self._json()
                    return self._send(201, svc.create_assembly(
                        b["release_name"], b.get("created_by", "api"),
                        project=b.get("project", ""), note=b.get("note", ""),
                        parent_envelope=b.get("parent_envelope"),
                        required_signers=b.get("required_signers", []),
                        idempotency_key=b.get("idempotency_key")))
                m = re.fullmatch(
                    r"/api/assemblies/(asm_[A-Za-z0-9]+)/artifacts", path)
                if m:
                    import base64
                    b = self._json()
                    if "content_base64" in b:
                        content = base64.b64decode(b["content_base64"])
                    elif "json" in b:
                        content = b["json"]
                    elif "text" in b:
                        content = b["text"]
                    else:
                        raise SealError("BAD_REQUEST",
                                        "需提供 content_base64/json/text", 400)
                    return self._send(201, svc.add_artifact_inline(
                        m.group(1), b["kind"], b["name"], content,
                        content_type=b.get("content_type",
                                          "application/octet-stream"),
                        by=b.get("by", "api")))
                m = re.fullmatch(
                    r"/api/assemblies/(asm_[A-Za-z0-9]+)/uploads", path)
                if m:
                    b = self._json()
                    return self._send(201, svc.start_upload(
                        m.group(1), b["kind"], b["name"], int(b["size"]),
                        chunk_size=int(b.get("chunk_size", 1 << 20)),
                        content_type=b.get("content_type",
                                          "application/octet-stream"),
                        by=b.get("by", "api")))
                m = re.fullmatch(
                    r"/api/uploads/(upl_[A-Za-z0-9]+)/complete", path)
                if m:
                    return self._send(200,
                                      svc.complete_upload(m.group(1)))
                m = re.fullmatch(
                    r"/api/uploads/(upl_[A-Za-z0-9]+)/abort", path)
                if m:
                    b = self._json()
                    return self._send(200,
                                      svc.abort_upload(m.group(1),
                                                       by=b.get("by", "api")))
                m = re.fullmatch(
                    r"/api/assemblies/(asm_[A-Za-z0-9]+)/seal", path)
                if m:
                    b = self._json()
                    return self._send(200,
                                      svc.seal(m.group(1),
                                               by=b.get("by", "api")))
                m = re.fullmatch(r"/api/envelopes/([A-Fa-f0-9]{64})/sign",
                                 path)
                if m:
                    b = self._json()
                    return self._send(200, svc.sign_envelope(
                        m.group(1), b["signer_id"], b["kid"],
                        signature=b.get("signature"),
                        priv_hex=b.get("priv_hex"),
                        signed_at=b.get("signed_at")))
                m = re.fullmatch(
                    r"/api/envelopes/([A-Fa-f0-9]{64})/publish", path)
                if m:
                    b = self._json()
                    return self._send(200, svc.publish(
                        m.group(1), by=b.get("by", "api"),
                        require_quorum=not b.get("no_quorum", False)))
                m = re.fullmatch(r"/api/recover", path)
                if m:
                    return self._send(200, svc.recover())
                self._send(404, {"error": "NOT_FOUND", "message": path})
            except SealError as e:
                self._err(e)

        def do_PUT(self):
            path = urlparse(self.path).path.rstrip("/")
            try:
                m = re.fullmatch(
                    r"/api/uploads/(upl_[A-Za-z0-9]+)/chunks/(\d+)", path)
                if m:
                    sid, seq = m.group(1), int(m.group(2))
                    data = self._raw()
                    digest = self.headers.get("X-Chunk-Digest")
                    return self._send(200, svc.put_chunk(
                        sid, seq, data, digest=digest))
                self._send(404, {"error": "NOT_FOUND", "message": path})
            except SealError as e:
                self._err(e)

    return Handler


def serve(store: str, host: str, port: int):
    svc = SealService(store)
    httpd = ThreadingHTTPServer((host, port), make_handler(svc))
    print(f"设计签名封装服务监听 http://{host}:{port}  存储={Path(store).resolve()}",
          flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default="sealdata")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8090)
    a = ap.parse_args(argv)
    serve(a.store, a.host, a.port)


if __name__ == "__main__":
    main()
