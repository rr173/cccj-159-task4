"""共享工具：规范 JSON、摘要、时间、文件原子写、文件锁。"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def utcnow() -> str:
    """统一的 UTC ISO-8601 时间串（微秒精度，Z 后缀）。

    微秒精度用于严格区分“签名时刻”与紧随其后的撤权/轮换时刻，
    避免同秒内半开区间边界误判历史有效性。
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canon(obj) -> bytes:
    """规范 JSON：键排序、无空白、不转义非 ASCII。内容寻址的唯一序列化。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def digest_json(obj) -> str:
    return hashlib.sha256(canon(obj)).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path, buf: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(buf)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def read_json(path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path, obj):
    write_bytes(path, canon_pretty(obj))


def canon_pretty(obj) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n").encode("utf-8")


def write_bytes(path, data: bytes, fsync: bool = True):
    """同目录临时文件 + rename 的原子写；落盘后 fsync。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            if fsync:
                os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def append_fsync(path, data: bytes):
    """追加写并 fsync（审计链 / journal 用）。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "ab") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


@contextlib.contextmanager
def file_lock(lock_path, exclusive: bool = True):
    """跨进程 fcntl 锁；同一线程内可重入（计数栈，复用同一 fd）。

    fcntl.flock 绑定 open file description：同进程用第二个 fd 重复加锁
    可能触发 EDEADLK/自阻塞，因此这里按 (线程, 锁文件) 维护重入栈。
    """
    import threading
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    key = (threading.get_ident(), str(lock_path))
    stacks = file_lock._stacks  # type: ignore[attr-defined]
    depth = stacks.get(key)
    if depth is not None:
        stacks[key] = depth + 1
        try:
            yield
        finally:
            stacks[key] -= 1
            if stacks[key] == 0:
                del stacks[key]
        return
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    stacks[key] = 1
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        try:
            if stacks[key] == 1:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            stacks.pop(key, None)
            os.close(fd)


file_lock._stacks = {}  # type: ignore[attr-defined]


def link_or_copy(src, dst):
    """优先硬链接（同卷零拷贝内容寻址），跨文件系统回退复制。"""
    src, dst = Path(src), Path(dst)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(FileExistsError):
        try:
            os.link(src, dst)
            return
        except FileExistsError:
            return
        except OSError:
            pass
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while True:
            b = fi.read(1 << 20)
            if not b:
                break
            fo.write(b)
