"""Merkle 包含证明的单元性质测试。"""
import random
import unittest

from seal import merkle


class MerkleTest(unittest.TestCase):
    def test_empty(self):
        t = merkle.build([])
        self.assertEqual(t["root"], merkle.empty_root())

    def test_single_leaf_proof_is_empty_but_valid(self):
        t = merkle.build([b"x"])
        self.assertEqual(t["root"], merkle.leaf_digest(b"x"))
        self.assertEqual(t["proofs"][0], [])
        self.assertTrue(merkle.verify_proof(t["root"], b"x", []))
        self.assertFalse(merkle.verify_proof(t["root"], b"y", []))

    def test_all_leaves_have_valid_proofs(self):
        random.seed(7)
        for n in range(1, 40):
            leaves = [random.randbytes(10) for _ in range(n)]
            t = merkle.build(leaves)
            for i, lf in enumerate(leaves):
                self.assertTrue(
                    merkle.verify_proof(t["root"], lf, t["proofs"][i]),
                    f"n={n} i={i}")

    def test_wrong_leaf_rejected(self):
        t = merkle.build([b"a", b"b", b"c", b"d"])
        self.assertFalse(merkle.verify_proof(t["root"], b"zzz",
                                             t["proofs"][0]))

    def test_wrong_root_rejected(self):
        t = merkle.build([b"a", b"b"])
        self.assertFalse(merkle.verify_proof("aa" * 32, b"a",
                                             t["proofs"][0]))

    def test_sorted_tree_is_order_independent(self):
        # 内部节点按摘要排序：[a,b] 与 [b,a] 建出同一个根。
        # 叶的“位置语义”由 manifest.merkle.leaf_order 在内容块中固定。
        t1 = merkle.build([b"a", b"b"])
        t2 = merkle.build([b"b", b"a"])
        self.assertEqual(t1["root"], t2["root"])
        # 但每片叶的证明路径方向反映其在有序树中的位置
        self.assertTrue(merkle.verify_proof(t1["root"], b"a",
                                            t1["proofs"][0]))

    def test_malformed_proof_rejected(self):
        t = merkle.build([b"a", b"b"])
        self.assertFalse(merkle.verify_proof(t["root"], b"a",
                                             [{"side": "bad",
                                               "sibling": "aa" * 32}]))
        self.assertFalse(merkle.verify_proof(t["root"], b"a",
                                             [{"side": "left",
                                               "sibling": "zz"}]))

    def test_second_preimage_resistance_prefixes(self):
        # 叶与内部节点使用不同域前缀
        self.assertNotEqual(merkle.leaf_digest(b"x"),
                            merkle.node_digest(merkle.leaf_digest(b"x"),
                                               merkle.leaf_digest(b"x")))


if __name__ == "__main__":
    unittest.main()
