"""Merkle 包含证明（inclusion proof）。

口径约定（服务内统一）：
- 叶输入是“制品摘要的原始字节”(bytes.fromhex(artifact.digest))；
  叶节点 = SHA256(0x00 || 叶输入)，防二级碰撞。
- 内部节点 = SHA256(0x01 || min(L,R) || max(L,R))（按字节序排序，
  离线验证者不依赖任何原始顺序约定）。
- 奇数节点直接上提一层。
- build 接收原始叶输入列表，返回叶哈希、根与按索引的 proof；
  verify_proof 接收同一份原始叶输入。
空树根为 SHA256("")。
"""
from __future__ import annotations

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_digest(data: bytes) -> str:
    return hashlib.sha256(LEAF_PREFIX + data).hexdigest()


def node_digest(left: str, right: str) -> str:
    a, b = sorted((left, right))
    return hashlib.sha256(
        NODE_PREFIX + bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()


def empty_root() -> str:
    return hashlib.sha256(b"").hexdigest()


def build(leaf_inputs: list[bytes]) -> dict:
    """由原始叶输入列表构造 Merkle 树。

    返回 {"root","leaf_hashes","leaf_inputs","proofs":{idx:[...]}}。
    """
    if not leaf_inputs:
        return {"root": empty_root(), "leaf_hashes": [],
                "leaf_inputs": [], "proofs": {}}
    level = [leaf_digest(x) for x in leaf_inputs]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(node_digest(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
        levels.append(level)
    proofs: dict[int, list] = {}
    for idx in range(len(levels[0])):
        path = []
        pos = idx
        for lvl in range(len(levels) - 1):
            nodes = levels[lvl]
            if pos % 2 == 0:
                if pos + 1 < len(nodes):
                    path.append({"side": "right", "sibling": nodes[pos + 1]})
            else:
                path.append({"side": "left", "sibling": nodes[pos - 1]})
            pos //= 2
        proofs[idx] = path
    return {"root": levels[-1][0], "leaf_hashes": list(levels[0]),
            "leaf_inputs": list(leaf_inputs), "proofs": proofs}


def verify_proof(root: str, leaf_input: bytes, proof: list[dict]) -> bool:
    """离线验证单叶包含证明（leaf_input 为制品摘要的原始字节）。"""
    try:
        cur = leaf_digest(leaf_input)
    except (TypeError, ValueError):
        return False
    for step in proof or []:
        sib = step.get("sibling")
        if not isinstance(sib, str) or len(sib) != 64:
            return False
        try:
            bytes.fromhex(sib)
        except ValueError:
            return False
        if step.get("side") == "left":
            cur = node_digest(sib, cur)
        elif step.get("side") == "right":
            cur = node_digest(cur, sib)
        else:
            return False
    return cur == root
