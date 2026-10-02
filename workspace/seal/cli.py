"""命令行：封装、离线签名、发布、验真与管理。

典型流程：
  # 1) 初始化存储 + 生成签名者密钥（私钥自存，公钥登记）
  python -m seal.cli --store ./sealdata init
  python -m seal.cli genkey alice
  python -m seal.cli signer register alice "Alice" <pubkey>

  # 2) 组装（网表/约束/模块清单/签核记录；大文件走分块续传）
  python -m seal.cli assembly create R1 --by ci --need alice --need bob
  python -m seal.cli artifact add <aid> netlist top.v --file top.v
  python -m seal.cli upload start <aid> netlist big.v 5242880
  python -m seal.cli upload chunk <sid> 0 --file part0.bin
  python -m seal.cli upload complete <sid>

  # 3) 封装、多方签名、原子发布
  python -m seal.cli seal <aid>
  python -m seal.cli sign <eid> alice key_alice_0 --key-file alice.key
  python -m seal.cli publish <eid>

  # 4) 验真 / 谱系 / 离线包
  python -m seal.cli verify <eid>
  python -m seal.cli lineage <eid>
  python -m seal.cli bundle <eid> out.tar
  python -m seal.cli verify-bundle out.tar
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import crypto
from .errors import SealError
from .offline import verify_dir
from .service import SealService
from .util import read_json


def _j(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)


def _read_key_file(path: str) -> str:
    raw = Path(path).read_text(encoding="utf-8").strip()
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict) and "priv" in obj:
            return obj["priv"]
    except json.JSONDecodeError:
        pass
    return raw


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="seal", description="设计签名封装服务 CLI")
    p.add_argument("--store", default="sealdata", help="存储根目录")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="初始化存储（幂等）")
    sub.add_parser("serve-help", help="启动 HTTP: python -m seal.httpapi")

    gk = sub.add_parser("genkey", help="生成 Ed25519 密钥对（私钥请自行妥善保存）")
    gk.add_argument("name", help="本地标识（仅用于输出提示）")
    gk.add_argument("--out", help="把 {priv,pub} JSON 写入该文件")

    sr = sub.add_parser("signer-register", help="登记签名者及其初始公钥")
    sr.add_argument("signer_id")
    sr.add_argument("display_name")
    sr.add_argument("pubkey", help="Ed25519 公钥 hex（genkey 输出）")
    sr.add_argument("--kid", default=None)
    sr.add_argument("--org", default="")

    sl = sub.add_parser("signers", help="列出全部签名者与密钥状态")
    sub.add_parser("signer-deactivate").add_argument("signer_id")
    rk = sub.add_parser("key-register", help="为签名者登记额外公钥")
    rk.add_argument("signer_id"); rk.add_argument("pubkey"); rk.add_argument("--kid")
    rv = sub.add_parser("key-revoke", help="撤权密钥（不影响其历史签名验真）")
    rv.add_argument("kid"); rv.add_argument("--reason", default="")
    rot = sub.add_parser("service-key-rotate", help="轮换服务密钥")
    rot.add_argument("--note", default="")

    ac = sub.add_parser("assembly-create")
    ac.add_argument("release_name"); ac.add_argument("--by", required=True)
    ac.add_argument("--project", default=""); ac.add_argument("--note", default="")
    ac.add_argument("--parent", default=None)
    ac.add_argument("--need", action="append", default=[])
    ac.add_argument("--idempotency-key", default=None)
    sub.add_parser("assemblies")
    gasm = sub.add_parser("assembly-get"); gasm.add_argument("aid")

    aa = sub.add_parser("artifact-add", help="内联添加小制品")
    aa.add_argument("aid"); aa.add_argument("kind",
        choices=("netlist", "constraint", "module", "signoff"))
    aa.add_argument("name")
    aa.add_argument("--file", help="从文件读取；否则用 --json 或 --text")
    aa.add_argument("--json", default=None)
    aa.add_argument("--text", default=None)
    aa.add_argument("--by", default="cli")

    us = sub.add_parser("upload-start")
    us.add_argument("aid"); us.add_argument("kind",
        choices=("netlist", "constraint", "module", "signoff"))
    us.add_argument("name"); us.add_argument("size", type=int)
    us.add_argument("--chunk-size", type=int, default=1 << 20)
    us.add_argument("--by", default="cli")
    uc = sub.add_parser("upload-chunk", help="上传/续传单个分块（可乱序、可重传）")
    uc.add_argument("sid"); uc.add_argument("seq", type=int)
    uc.add_argument("--file", required=True)
    ust = sub.add_parser("upload-status"); ust.add_argument("sid")
    ucm = sub.add_parser("upload-complete"); ucm.add_argument("sid")
    uab = sub.add_parser("upload-abort"); uab.add_argument("sid")

    se = sub.add_parser("seal", help="把组装封装成内容寻址信封")
    se.add_argument("aid"); se.add_argument("--by", default="cli")
    sub.add_parser("envelopes")
    ge = sub.add_parser("envelope-get"); ge.add_argument("eid")
    sg = sub.add_parser("sign", help="用本地私钥对信封签名")
    sg.add_argument("eid"); sg.add_argument("signer_id"); sg.add_argument("kid")
    sg.add_argument("--key-file", required=True)
    sg.add_argument("--signed-at", default=None)
    pb = sub.add_parser("publish", help="两阶段原子发布（签名齐备前拒绝）")
    pb.add_argument("eid"); pb.add_argument("--by", default="cli")
    pb.add_argument("--no-quorum", action="store_true")
    ve = sub.add_parser("verify"); ve.add_argument("eid")
    lg = sub.add_parser("lineage"); lg.add_argument("eid")
    ip = sub.add_parser("proof", help="查看某制品的 Merkle 包含证明")
    ip.add_argument("eid"); ip.add_argument("name")
    ab = sub.add_parser("artifact-get", help="导出某制品字节")
    ab.add_argument("eid"); ab.add_argument("name"); ab.add_argument("--out")
    bu = sub.add_parser("bundle", help="导出离线验真包")
    bu.add_argument("eid"); bu.add_argument("out")
    vb = sub.add_parser("verify-bundle"); vb.add_argument("path")
    vb.add_argument("--trust-pub", default=None)
    vd = sub.add_parser("verify-dir"); vd.add_argument("path")
    sub.add_parser("audit")
    sub.add_parser("recover")
    sub.add_parser("health")
    sub.add_parser("names")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    svc = SealService(args.store)
    try:
        return _dispatch(svc, args)
    except SealError as e:
        print(json.dumps({"error": e.code, "message": e.message,
                          "detail": e.detail}, ensure_ascii=False, indent=2),
              file=sys.stderr)
        return 2


def _dispatch(svc, a) -> int:
    c = a.cmd
    if c == "init":
        created = svc.s.init_store()
        print(_j({"initialized": created, "store": str(svc.s.root),
                  "service_kid": svc.s.service_public()["kid"],
                  "service_public_key": svc.s.service_public()["public_key"]}))
    elif c == "genkey":
        priv, pub = crypto.generate_keypair()
        out = {"name": a.name, "priv": priv, "pub": pub}
        if a.out:
            Path(a.out).write_text(_j(out), encoding="utf-8")
            Path(a.out).chmod(0o600)
            print(_j({"name": a.name, "pub": pub, "key_file": a.out}))
        else:
            print(_j(out))
    elif c == "signer-register":
        print(_j(svc.registry.register_signer(
            a.signer_id, a.display_name, a.pubkey, kid=a.kid, org=a.org)))
        svc.audit("cli.signer.register", {"signer_id": a.signer_id}, "cli")
    elif c == "signers":
        print(_j(svc.registry.signer_summary()))
    elif c == "signer-deactivate":
        print(_j(svc.registry.deactivate_signer(a.signer_id)))
    elif c == "key-register":
        print(_j({"kid": svc.registry.register_key(a.signer_id, a.pubkey)}))
    elif c == "key-revoke":
        print(_j(svc.registry.revoke_key(a.kid, reason=a.reason)))
    elif c == "service-key-rotate":
        print(_j(svc.s.rotate_service_key(a.note)))
    elif c == "assembly-create":
        print(_j(svc.create_assembly(
            a.release_name, a.by, project=a.project, note=a.note,
            parent_envelope=a.parent, required_signers=a.need,
            idempotency_key=a.idempotency_key)))
    elif c == "assemblies":
        print(_j(svc.list_assemblies()))
    elif c == "assembly-get":
        print(_j(svc.get_assembly(a.aid)))
    elif c == "artifact-add":
        if a.file:
            data = Path(a.file).read_bytes()
        elif a.json is not None:
            data = json.loads(a.json)
        elif a.text is not None:
            data = a.text
        else:
            raise SystemExit("需要 --file/--json/--text 之一")
        print(_j(svc.add_artifact_inline(
            a.aid, a.kind, a.name, data, by=a.by)))
    elif c == "upload-start":
        print(_j(svc.start_upload(a.aid, a.kind, a.name, a.size,
                                  chunk_size=a.chunk_size, by=a.by)))
    elif c == "upload-chunk":
        data = Path(a.file).read_bytes()
        print(_j(svc.put_chunk(a.sid, a.seq, data)))
    elif c == "upload-status":
        print(_j(svc.upload_status(a.sid)))
    elif c == "upload-complete":
        print(_j(svc.complete_upload(a.sid)))
    elif c == "upload-abort":
        print(_j(svc.abort_upload(a.sid)))
    elif c == "seal":
        print(_j(svc.seal(a.aid, by=a.by)))
    elif c == "envelopes":
        print(_j(svc.list_envelopes()))
    elif c == "envelope-get":
        print(_j(svc._load_envelope(a.eid)))  # noqa: SLF001
    elif c == "sign":
        priv = _read_key_file(a.key_file)
        print(_j(svc.sign_envelope(
            a.eid, a.signer_id, a.kid, priv_hex=priv,
            signed_at=a.signed_at)))
    elif c == "publish":
        print(_j(svc.publish(a.eid, by=a.by, require_quorum=not a.no_quorum)))
    elif c == "verify":
        r = svc.verify_envelope(a.eid)
        print(_j(r))
        return 0 if r["ok"] else 1
    elif c == "lineage":
        print(_j(svc.lineage(a.eid)))
    elif c == "proof":
        print(_j(svc.inclusion_proof(a.eid, a.name)))
    elif c == "artifact-get":
        data, art = svc.artifact_bytes(a.eid, a.name)
        if a.out:
            Path(a.out).write_bytes(data)
            print(_j({"wrote": a.out, "artifact": art}))
        else:
            sys.stdout.buffer.write(data)
    elif c == "bundle":
        print(_j({"bundle": svc.export_bundle(a.eid, a.out)}))
    elif c == "verify-bundle":
        r = svc.verify_bundle(a.path, trust_pub=a.trust_pub)
        print(_j(r))
        return 0 if r["ok"] else 1
    elif c == "verify-dir":
        r = verify_dir(Path(a.path))
        print(_j(r))
        return 0 if r["ok"] else 1
    elif c == "audit":
        print(_j(svc.s.audit_entries()))
    elif c == "recover":
        print(_j(svc.recover()))
    elif c == "health":
        print(_j(svc.health()))
    elif c == "names":
        out = {}
        for p in sorted(svc.s.names.iterdir()):
            if p.is_file():
                out[p.name] = read_json(p)
        print(_j(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
