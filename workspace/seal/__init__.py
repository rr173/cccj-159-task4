"""设计签名封装服务（Design Signature Envelope Service）。

独立于 ECO 签核基线服务的内容寻址发布信封系统：
把待发布变更的网表/约束/模块清单/签核记录组装成内容寻址的发布信封，
生成可离线验真的多方签名清单与包含证明（Merkle inclusion proof），
并提供命令行（seal/cli.py）、REST（seal/httpapi.py）与页面（seal/web/）
查看信封谱系、签名状态与校验结果。

零第三方依赖：仅使用 Python 3.11 标准库；Ed25519 为内置纯 Python 实现
（RFC 8032，向量测试见 tests/test_ed25519.py）。
"""

SCHEMA_ENVELOPE = "design-sign-envelope/1"
SCHEMA_SNAPSHOT = "signer-registry-snapshot/1"
SCHEMA_TRUST = "service-trust-chain/1"
SCHEMA_PUBLICATION = "envelope-publication/1"
