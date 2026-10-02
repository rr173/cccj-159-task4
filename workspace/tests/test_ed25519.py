"""Ed25519 纯 Python 实现的 RFC 8032 §7.1 官方测试向量测试。

采用短向量 TEST 1/2/3（空消息 / 1 字节 / 2 字节）与 TEST 5（消息为
SHA-512("abc")，直接由 hashlib 计算，避免手抄长十六进制串）。
"""
import hashlib
import time
import unittest

from seal import crypto

# ---- RFC 8032 Section 7.1 ----
SECRET_KEYS = [
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
]
PUBLIC_KEYS = [
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
]
MESSAGES = [
    b"",
    bytes.fromhex("72"),
    bytes.fromhex("af82"),
    hashlib.sha512(b"abc").digest(),
]
SIGNATURES = [
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",  # S 经 OpenSSL 交叉验证
]


class Ed25519VectorTest(unittest.TestCase):
    def test_derive_pubkey(self):
        for sk, pk in zip(SECRET_KEYS, PUBLIC_KEYS):
            self.assertEqual(crypto.derive_pubkey(sk), pk)

    def test_sign_vectors(self):
        for sk, msg, sig in zip(SECRET_KEYS, MESSAGES, SIGNATURES):
            self.assertEqual(crypto.sign(sk, msg), sig)

    def test_verify_vectors(self):
        for pk, msg, sig in zip(PUBLIC_KEYS, MESSAGES, SIGNATURES):
            self.assertTrue(crypto.verify(pk, msg, sig))

    def test_reject_bad_message(self):
        self.assertFalse(crypto.verify(PUBLIC_KEYS[1], b"\x73",
                                       SIGNATURES[1]))

    def test_reject_bad_pubkey(self):
        bad = ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f1"
               "2af4660d")
        self.assertFalse(crypto.verify(bad, MESSAGES[1], SIGNATURES[1]))

    def test_reject_mangled_signature(self):
        sig = SIGNATURES[1]
        mangled = "93" + sig[2:]
        self.assertFalse(crypto.verify(PUBLIC_KEYS[1], MESSAGES[1], mangled))

    def test_reject_non_canonical_s(self):
        # S >= 群阶 l 必须被拒绝（防签名可塑性）
        s = int(SIGNATURES[1][64:], 16) + crypto.l
        bad = SIGNATURES[1][:64] + s.to_bytes(32, "little").hex()
        self.assertFalse(crypto.verify(PUBLIC_KEYS[1], MESSAGES[1], bad))

    def test_roundtrip_random(self):
        sk, pk = crypto.generate_keypair()
        msg = b"design-sign-envelope"
        sig = crypto.sign(sk, msg)
        self.assertTrue(crypto.verify(pk, msg, sig))
        self.assertFalse(crypto.verify(pk, msg + b"x", sig))

    def test_performance(self):
        sk, pk = crypto.generate_keypair()
        t0 = time.time()
        sig = crypto.sign(sk, b"perf")
        t_sign = time.time() - t0
        t0 = time.time()
        self.assertTrue(crypto.verify(pk, b"perf", sig))
        t_ver = time.time() - t0
        # 纯 Python 基线护栏（防实现退化为多秒）
        self.assertLess(t_sign, 5.0)
        self.assertLess(t_ver, 5.0)


if __name__ == "__main__":
    unittest.main()
