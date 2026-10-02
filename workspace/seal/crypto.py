"""纯 Python Ed25519（RFC 8032）实现，零第三方依赖。

测试向量来自 RFC 8032 §7.1（tests/test_ed25519.py 覆盖全部 5 组）。
性能取向：固定基点用 radix-16 预计算表，变长基点按次预计算；
服务端签名/验签调用量小，纯 Python 速度可接受。

公开接口：
    generate_keypair() -> (priv_hex64, pub_hex32)
    derive_pubkey(priv_hex) -> pub_hex
    sign(priv_hex, msg: bytes) -> sig_hex128
    verify(pub_hex, msg: bytes, sig_hex) -> bool
    PUBLIC_KEY_BYTES / SIGNATURE_BYTES
"""
from __future__ import annotations

import hashlib
import os

# ---------------------------------------------------------------- 域参数（RFC 8032）

q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, q - 2, q)) % q
I = pow(2, (q - 1) // 4, q)


def _xrecover(y):
    xx = (y * y - 1) * pow(d * y * y + 1, q - 2, q)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


_by = 4 * pow(5, q - 2, q)
_bx = _xrecover(_by)
B = (_bx % q, _by % q, 1, (_bx * _by) % q)  # 扩展坐标 (X,Y,Z,T)
Bp = (0, 1, 1, 0)  # 单位元


def edwards_add(P, Q):
    """扩展坐标 twisted-Edwards 点加（Hisil–Wong–Carter–Dawson）。"""
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (Y1 - X1) * (Y2 - X2) % q
    B = (Y1 + X1) * (Y2 + X2) % q
    C = 2 * T1 * T2 * d % q
    Dd = 2 * Z1 * Z2 % q
    E = (B - A) % q
    F = (Dd - C) % q
    G = (Dd + C) % q
    H = (B + A) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)


def edwards_double(P):
    X1, Y1, Z1, _T1 = P
    A = X1 * X1 % q
    Bb = Y1 * Y1 % q
    C = 2 * Z1 * Z1 % q
    Dh = -A % q
    E = ((X1 + Y1) * (X1 + Y1) - A - Bb) % q
    G = (Dh + Bb) % q
    F = (G - C) % q
    H = (Dh - Bb) % q
    return (E * F % q, G * H % q, F * G % q, E * H % q)


def _make_table(P):
    """radix-16 预计算表：table[i][j] = (j+1) * 16^i * P，j=0..7。

    有符号数字表示：nibble>=8 时写成 n-16 并向高位进 1（进位在
    _scalar_table 中处理），故表需要 65 行容纳最终进位。
    """
    table = []
    base_i = P
    for _i in range(65):
        row = []
        cur = Bp
        for _j in range(8):
            cur = edwards_add(cur, base_i)  # (j+1) * base_i
            row.append(cur)
        table.append(row)
        nxt = base_i
        for _ in range(4):
            nxt = edwards_double(nxt)
        base_i = nxt
    return table


BASE_TABLE = _make_table(B)


def _signed_nibbles(k_bytes: bytes) -> list[int]:
    """小端有符号 radix-16 重编码（含进位）：值落在 [-8,7]。"""
    nibs = []
    for byte in k_bytes:
        nibs.append(byte & 0x0F)
        nibs.append((byte >> 4) & 0x0F)
    carry = 0
    out = []
    for n in nibs:
        n += carry
        carry = 0
        if n >= 8:
            n -= 16
            carry = 1
        out.append(n)
    out.append(carry)  # 最终进位（256 位标量至多为 1）
    return out


def _scalar_table(table, k_bytes: bytes) -> tuple:
    """256 位标量乘（有符号 radix-16 数字）。"""
    Q = Bp
    for i, s in enumerate(_signed_nibbles(k_bytes)):
        if s:
            P = table[i][abs(s) - 1]
            if s < 0:
                P = (q - P[0], P[1], P[2], q - P[3])
            Q = edwards_add(Q, P)
    return Q


def xscalar_base(k_bytes: bytes) -> tuple:
    return _scalar_table(BASE_TABLE, k_bytes)


def xscalar(P, k_bytes: bytes) -> tuple:
    return _scalar_table(_make_table(P), k_bytes)


def _point_eq(P, Q) -> bool:
    """扩展坐标下的点相等判定：X1/Z1==X2/Z2 且 Y1/Z1==Y2/Z2。"""
    return (P[1] * Q[2] % q == Q[1] * P[2] % q
            and P[0] * Q[2] % q == Q[0] * P[2] % q)


def _encodepoint(P) -> bytes:
    X, Y, Z, _T = P
    zi = pow(Z, q - 2, q)
    x = X * zi % q
    y = Y * zi % q
    bits = y | ((x & 1) << 255)
    return bits.to_bytes(32, "little")


def _decodepoint(s: bytes):
    if len(s) != 32:
        return None
    bits = int.from_bytes(s, "little")
    y = bits & ((1 << 255) - 1)
    sign = bits >> 255
    x = _xrecover(y)
    if (x & 1) != sign:
        x = q - x
    P = (x, y, 1, x * y % q)
    if not _on_curve(P):
        return None
    return P


def _on_curve(P) -> bool:
    X, Y, Z, _T = P
    zi = pow(Z, q - 2, q)
    x = X * zi % q
    y = Y * zi % q
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def _scalar_reduce(b: bytes) -> int:
    return int.from_bytes(b, "little") % l


def _scalar_add(a: int, b: int) -> int:
    return (a + b) % l


def _scalar_bytes(k: int) -> bytes:
    return k.to_bytes(32, "little")


# ---------------------------------------------------------------- 密钥与签名

PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64


def _clamp(h: bytes) -> int:
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def _sk_bytes(priv_hex: str) -> bytes:
    b = bytes.fromhex(priv_hex)
    if len(b) != 32:
        raise ValueError("私钥必须为 32 字节 hex")
    return b


def derive_pubkey(priv_hex: str) -> str:
    h = hashlib.sha512(_sk_bytes(priv_hex)).digest()
    a = _clamp(h)
    A = xscalar_base(_scalar_bytes(a))
    return _encodepoint(A).hex()


def generate_keypair() -> tuple[str, str]:
    seed = os.urandom(32)
    priv = seed.hex()
    return priv, derive_pubkey(priv)


def sign(priv_hex: str, msg: bytes) -> str:
    sk = _sk_bytes(priv_hex)
    h = hashlib.sha512(sk).digest()
    a = _clamp(h)
    A = _encodepoint(xscalar_base(_scalar_bytes(a)))
    r = _scalar_reduce(hashlib.sha512(h[32:] + msg).digest())
    R = _encodepoint(xscalar_base(_scalar_bytes(r)))
    k = _scalar_reduce(hashlib.sha512(R + A + msg).digest())
    S = _scalar_bytes(_scalar_add(r, k * a))
    return (R + S).hex()


def verify(pub_hex: str, msg: bytes, sig_hex: str) -> bool:
    try:
        A = _decodepoint(bytes.fromhex(pub_hex))
        sig = bytes.fromhex(sig_hex)
        if A is None or len(sig) != 64:
            return False
        R_pt = _decodepoint(sig[:32])
        S = int.from_bytes(sig[32:], "little")
        if R_pt is None or S >= l:
            return False
        k = _scalar_reduce(hashlib.sha512(sig[:32] + bytes.fromhex(pub_hex) + msg).digest())
        sB = xscalar_base(sig[32:])
        check = edwards_add(R_pt, xscalar(A, _scalar_bytes(k)))
        return _point_eq(sB, check)
    except (ValueError, OverflowError):
        return False
