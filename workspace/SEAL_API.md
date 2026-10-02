# 设计签名封装服务 API 契约

基础路径 `http://<host>:8090`，除制品/分块/离线包外全部 JSON。
错误统一：

```json
{ "error": "CODE", "message": "可读说明", "detail": { } }
```

启动：`python3 -m seal.httpapi --store sealdata --port 8090`
页面：`GET /`（信封谱系/签名状态/校验结果/分块进度/审计）。

## 原因码

### 组装 / 封装
- `ASSEMBLY_NOT_FOUND`、`ASSEMBLY_NOT_OPEN`、`EMPTY_ASSEMBLY`
- `BAD_ARTIFACT_KIND`（kind 限 netlist/constraint/module/signoff）
- `ARTIFACT_NAME_EXISTS`（同组装内制品名唯一）
- `UPLOAD_STILL_OPEN`（仍有未完成分块上传时禁止封装）
- `MANIFEST_TAMPERED`（content 摘要≠目录名，或注册表快照未被 content 钉住）

### 分块上传
- `UPLOAD_NOT_FOUND`、`UPLOAD_INCOMPLETE`（缺块即拒绝完成）、
  `UPLOAD_NOT_OPEN`
- `BAD_CHUNK_SEQ`（越界）、`CHUNK_SIZE_MISMATCH`、
  `CHUNK_DIGEST_MISMATCH`（声明摘要≠实际）、`CHUNK_CONFLICT`
  （同 seq 已收不同内容）、`CHUNK_MISSING`、`CHUNK_TAMPERED`
  （complete/验真时回读盘块摘要不符）、`REASSEMBLE_SIZE_MISMATCH`

### 签名 / 发布
- `QUORUM_NOT_MET`（required_signers 未齐；返回 valid_count/missing）
- `ALREADY_SIGNED`、`ENVELOPE_IMMUTABLE`（已发布信封不可追加签名）
- `BAD_SIGNATURE`（签名声明验签失败）、`SIGNING_CLAIM_MISMATCH`
- `SIGNED_AT_REQUIRED` / `BAD_SIGNED_AT` /
  `SIGNED_AT_BEFORE_KEY_REGISTERED`（禁止回填）/ `SIGNED_AT_IN_FUTURE` /
  `SIGNED_AT_TOO_OLD`（外部签名 ±300s 漂移窗）
- `NO_SIGNATURE`、`PRIVKEY_PUBKEY_MISMATCH`
- `KEY_SIGNER_MISMATCH`、`SIGNER_KEY_REVOKED`、`SIGNER_KEY_ROTATED`、
  `SIGNER_DEACTIVATED`
- `NAME_CONFLICT`（同名发布名已指向不同内容）
- `SERVICE_READ_ONLY`（审计链断裂/恢复异常时只读降级）

### 验真问题码（verify 返回的 problems[]，HTTP 仍 200，`ok:false`）
`MANIFEST_ID_MISMATCH`、`REGISTRY_DIGEST_PIN_MISMATCH`、
`REGISTRY_SNAPSHOT_DIGEST_MISMATCH`、`REGISTRY_SNAPSHOT_SIG_INVALID`、
`SERVICE_KID_UNKNOWN`、`TRUST_ROOT_MISMATCH`、
`ARTIFACT_MISSING/ARTIFACT_SIZE_MISMATCH/ARTIFACT_DIGEST_MISMATCH`、
`CHUNK_MISSING/CHUNK_TAMPERED`、
`MERKLE_ROOT_MISMATCH/MERKLE_ROOT_REBUILD_MISMATCH/MERKLE_PROOF_INVALID`、
`SIGNATURE_INVALID`（含 BAD_SIGNATURE/UNKNOWN_SIGNER_OR_KEY/
PUBLIC_KEY_MISMATCH/KEY_NOT_YET_VALID_AT_SIGN_TIME）、
`ROSTER_ATTEST_MISSING/ROSTER_DIGEST_MISMATCH/ROSTER_ATTEST_SIG_INVALID/
ROSTER_ATTEST_UNEXPECTED`、`PUBLICATION_ID_MISMATCH`、`QUORUM_NOT_MET`。

## 端点

### 服务与签名者管理
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 只读状态、审计链校验、当前服务 kid |
| POST | `/api/service-key/rotate` | `{note?}` 轮换服务密钥（自签衔接链） |
| POST | `/api/signers` | `{signer_id,name,public_key,kid?,org?,label?}` → 201 |
| GET | `/api/signers` | 签名者与全部密钥状态（ACTIVE/ROTATED/REVOKED） |
| POST | `/api/signers/{id}/deactivate` | `{reason?}` |
| POST | `/api/keys` | `{signer_id,public_key,kid?,label?}` 登记新代次密钥 |
| POST | `/api/keys/{kid}/revoke` | `{reason?}` 撤权（历史签名仍有效） |

### 组装与制品
| 方法 | 路径 | Body / 说明 |
|---|---|---|
| POST | `/api/assemblies` | `{release_name,created_by,project?,note?,parent_envelope?,required_signers[],idempotency_key?}`；同幂等键重放返回首次组装 |
| GET | `/api/assemblies` / `/api/assemblies/{aid}` | 列表 / 详情（含 uploads 进度） |
| POST | `/api/assemblies/{aid}/artifacts` | `{kind,name,content_base64? 或 json? 或 text?,content_type?,by?}` |

### 分块上传（可中断续传、可乱序、幂等重传）
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/assemblies/{aid}/uploads` | `{kind,name,size,chunk_size?,content_type?,by?}` → 会话（总块数/每块大小立即落盘） |
| PUT | `/api/uploads/{sid}/chunks/{seq}` | body=原始分块字节；可带头 `X-Chunk-Digest: <sha256hex>`；同内容重传 `replayed:true` |
| GET | `/api/uploads/{sid}` | 每块 received/digest/remaining |
| POST | `/api/uploads/{sid}/complete` | 缺块 409 `UPLOAD_INCOMPLETE`；逐块回读后重组入 CAS |
| POST | `/api/uploads/{sid}/abort` | 置 ABORTED |

### 封装 / 签名 / 发布 / 验真
| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/assemblies/{aid}/seal` | 原子封装；同内容返回同一信封（`replayed:true`） |
| GET | `/api/envelopes` / `/api/envelopes/{eid}` | 列表 / 详情 |
| POST | `/api/envelopes/{eid}/sign` | `{signer_id,kid,signature?,signed_at?}` 或 `{...,priv_hex}`（CLI/演示）；外部签名走 ±300s 时间窗 |
| POST | `/api/envelopes/{eid}/publish` | `{by?,no_quorum?}` 两阶段原子发布；未齐签 409 |
| GET | `/api/envelopes/{eid}/verify` | 完整校验结果（problems[]、每条签名 valid/then_valid/current_status） |
| GET | `/api/envelopes/{eid}/lineage` | 沿 parent_envelope 的祖先链 |
| GET | `/api/envelopes/{eid}/proof?name=` | 单制品 Merkle 包含证明 |
| GET | `/api/envelopes/{eid}/artifacts/{name}` | 制品原始字节 |
| GET | `/api/envelopes/{eid}/bundle` | 自包含离线验真包（.tar） |
| GET | `/api/names` | 发布名 → publication 指针 |
| POST | `/api/recover` | 手动触发崩溃恢复（启动时已自动执行） |
| GET | `/api/audit` | 审计链（含 result=REJECT 与 reason） |

## 离线验真

```bash
python3 -m seal.cli verify-bundle out.tar [--trust-pub <创世服务公钥hex>]
python3 -m seal.cli verify-dir <解包后的信封目录>
```

离线校验链：目录名==SHA256(canon(content)) 且 content.registry_digest
与内嵌快照一致 → 每制品/逐分块摘要 → Merkle 包含证明与根 → 注册表快照
服务签名 → 每条签名声明 Ed25519 验签（密钥取自快照，按 signed_at 判历史
有效）→ 已发布信封的 roster 作证 → 可选创世信任根。

## 典型时序

```
POST /signers(alice/bob 公钥)
POST /assemblies                         {required_signers:[alice,bob]}
POST /assemblies/{aid}/artifacts         网表/约束/模块清单/签核记录
  （大文件）POST .../uploads → PUT chunks/{seq}（可中断/乱序/重传）→ complete
POST /assemblies/{aid}/seal              → envelope_id（=内容摘要）
签名者离线对 signing_claim 签名 → POST /envelopes/{eid}/sign ×N
POST /envelopes/{eid}/publish            两阶段原子发布
GET  /envelopes/{eid}/verify · /lineage · /proof · /bundle
```
