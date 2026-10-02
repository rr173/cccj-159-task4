# 设计签名封装服务（Design Signature Envelope Service）

独立于 ECO 签核基线服务的**内容寻址发布信封**系统：把待发布变更的
**网表 / 约束 / 模块清单 / 签核记录**组装成内容寻址信封，为每个信封生成
可离线验真的**多方签名清单**与**Merkle 包含证明**，并提供**命令行、REST、
页面**查看信封谱系、签名状态与校验结果。

**零第三方依赖**：仅 Python 3.11 标准库 + 原生 JS。Ed25519 为内置纯 Python
实现（`seal/crypto.py`，RFC 8032，全部官方测试向量 + OpenSSL 双向交叉验证）。

```bash
python3 -m seal.httpapi --store sealdata --port 8090   # REST + 页面 http://localhost:8090
python3 -m seal.cli --store sealdata envelopes         # 命令行
python3 -m seal.demo                                   # A~G 七场景端到端演示
```

## 目录

```
seal/
  crypto.py    纯 Python Ed25519（RFC 8032；RFC 向量测试 + OpenSSL 交叉验证）
  merkle.py    Merkle 包含证明（叶/内部域分隔；排序内部节点；奇数节点上提）
  util.py      规范 JSON、原子写（tmp+fsync+rename）、可重入 fcntl 锁、审计时间
  errors.py    统一错误（code/message/http_status）与 VerifyFailed
  store.py     落盘布局、CAS/chunks、服务密钥创世与轮换、prev_hash 审计链、journal
  registry.py  签名者/密钥注册表（append-only 事件，服务密钥逐条签名，启动重放验签）
  service.py   领域核心：组装、分块续传、封装、多方签名、两阶段原子发布、恢复、验真、谱系
  offline.py   纯离线验真器（只吃信封目录/导出包，不依赖运行中的服务）
  cli.py       命令行
  httpapi.py   stdlib http.server REST + 页面
  demo.py      七场景演示
  web/         查看页面（信封谱系/签名状态/校验结果/分块进度/审计）
tests/
  test_ed25519.py        9 个 RFC 8032 向量与可塑性/性能测试
  test_merkle.py         8 个 Merkle 证明性质测试
  test_seal_service.py  42 个领域不变量测试
  test_seal_httpapi.py   6 个真实 socket HTTP 端到端测试
```

## 内容寻址：信封 id 只由“发布了什么”决定

manifest 分成两块：

- `content`（**信封 id = SHA-256(canon(content))**，目录名即此值）：
  发布名、项目、父信封、必需签名者、**注册表快照稳定摘要**、制品清单
  （kind/name/digest/size/storage/分块索引）、Merkle 根与叶序。
- `provenance`（装配溯源，**不参与 id**）：assembly_id、创建人、
  创建/封装时间、备注。

因此同一份发布内容由任何人、在任何时刻、用不同组装封装，都得到**同一个
信封 id**；`created_by/sealed_at` 不同不影响去重。`content.registry_digest`
又把内嵌签名者快照钉进 id，换快照即换内容。

## 封装与多方签名

- 制品按 kind 分四类：`netlist / constraint / module / signoff`；
  小对象内联入库（JSON/文本/字节），大文件走分块上传。
- Merkle：叶输入为每制品 SHA-256 的原始字节，叶节点
  `SHA256(0x00‖leaf)`、内部节点 `SHA256(0x01‖min‖max)`；每个制品一份
  inclusion proof 落 `merkle_proofs.json`。
- 每条签名是 Ed25519 对**签名声明**
  `{alg, claim, envelope_id, signer_id, kid, signed_at}` 的规范字节签名
  ——不只签 manifest，杜绝回填时间/张冠李戴。外部离线签名可提交签名值，
  服务端按 ±300s 漂移窗校验 `signed_at`（不早于密钥登记、不超未来）。
- 每条签名落账时还附带服务密钥对
  `signer-key-binding`（签名者↔kid↔公钥↔信封↔时刻）的**绑定作证**：
  这样封装快照之后才轮换/登记的新代次密钥对历史信封补签也能离线验证
  （快照里没有该密钥时回退校验绑定作证，`via_binding=true`），而伪造
  公钥绑定需要服务私钥。
- **发布门禁**：`required_signers` 必须全部有有效签名（可 `--no-quorum`
  显式跳过，留痕）。发布瞬间服务密钥对**最终签名清单**做 roster 作证，
  已发布信封不可变，之后注入/改动任何签名都会使作证失效。

## 撤权后历史验真与密钥轮换

- 注册表是 append-only 事件链（登记/停用/登记密钥/轮换/撤权），每条由
  当前服务密钥签名；启动逐条重放，任一签名/摘要/链断裂即拒绝启动。
- 信封内嵌**封装时刻的注册表快照**（服务签名，且摘要被 content 钉住）。
  验历史签名时只看快照与 `signed_at`：密钥在签名时刻有效即
  `then_valid=true`。**撤权/轮换不影响撤权前的历史信封验真**；撤权后用
  旧密钥提交新签名 → `SIGNER_KEY_REVOKED`。
- 签名者密钥可登记新代次；**服务密钥**可轮换，轮换记录由新密钥对
  （新公钥+前驱公钥+时间）自签成链，旧信封固化了签发时的 kid，轮换后
  仍可验。

## 分块上传（中断续传）

- `upload start` 立即落盘会话元数据（总块数、每块大小），之后**每块落盘
  并 fsync 后原子更新索引**；进程重启会话与进度不丢，可乱序/重传。
- 同一 seq 相同摘要重传幂等；不同摘要 → `CHUNK_CONFLICT`；块大小不符
  → `CHUNK_SIZE_MISMATCH`；声明摘要不符 → `CHUNK_DIGEST_MISMATCH`。
- `complete` 前逐块回读重算（盘上被改即 `CHUNK_TAMPERED`、丢即
  `CHUNK_MISSING`），通过后把完整文件重组入 CAS；`artifact.digest` 与内联
  制品同为整文件摘要，`chunk_index` 用于定位被篡改的具体块。分块 blob 也
  固化进信封目录，离线包可逐块验。

## 原子发布与崩溃恢复（绝不产生两个有效信封）

- `seal`：持全局锁 → 组装态置 `SEALING` → 在 `.tmp-*` 目录组装并通过内部
  完整性自检 → **一次同目录 rename** 到 `envelopes/<eid>`。目标已存在
  （并发同内容）时复用并把组装收敛到既有 eid，绝不新建第二个。
- `publish` 两阶段：`PUBLISH_INTENT` 落 journal 并 fsync → 同一把发布锁内
  顺序原子写 roster 作证、`publication.json`、名字指针、`status.json` →
  `PUBLISH_DONE`。
- 启动 `recover()` 幂等：清理孤儿 `.tmp-*`；`SEALING` 组装按信封是否已在
  收敛为 `SEALED` 或回退 `OPEN`；对未完成的 `PUBLISH_INTENT` 补齐作证/
  publication/名字指针（名字已被不同内容占用则不覆盖，记
  `recover.publish.conflict` 审计）。

## 同名不同内容

发布名指针 `names/<release_name>` 只指向一个 eid。已发布的名字再发布
不同内容 → `409 NAME_CONFLICT`（返回当前/试图的两个摘要），必须改名或
以父信封续版（谱系）。

## 篡改拒绝与审计

- 在线 `verify` / 离线 `verify-bundle` 覆盖：目录名==content 摘要、
  快照钉扎、每制品 SHA-256、逐分块摘要、Merkle 包含证明与根、注册表快照
  服务签名、每条签名声明验签、roster 作证、发布指针。
- 任一签名、摘要或分块被篡改 → 验真失败并返回全部问题码，同时写
  `audit/log.jsonl`（`prev_hash` 串接的记录级哈希链，逐条 fsync）。
- 审计链本身被篡改：启动检测到链断裂 → **只读降级**（`SERVICE_READ_ONLY`
  拒绝一切写操作），页面与 `/api/health` 显式告警。

## 离线验真

`cli bundle <eid> out.tar`（或 `GET /api/envelopes/<eid>/bundle`）导出
自包含信封（manifest、制品、分块 blob、Merkle 证明、服务信任链、签名
清单、发布记录）。任何机器无需服务即可：

```bash
python3 -m seal.cli verify-bundle out.tar                 # 信任包内服务链
python3 -m seal.cli verify-bundle out.tar --trust-pub <hex>  # 钉死创世公钥
# 或解包后：
python3 -m seal.cli verify-dir ./<envelope_id>
```

信任模型：离线验证者要么信任 `service_history.json` 的创世公钥
（`--trust-pub`），要么通过带外渠道确认；签名者公钥以服务签名的注册表
快照为准，签名者私钥永不经过服务端（服务端代签仅用于 CLI/演示）。
