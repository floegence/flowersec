# Flowersec v3 传输安全与 Wire Contract 最终设计

状态：最终定稿
规范版本：3.0.0
基准提交：`026cb52d116d2a04de50d0f0621fff57c7657120`
适用实现：TypeScript、Go、Rust、Swift

## 1. 结论

Flowersec v3 将 TLS 信任策略定义为 candidate 的必要组成部分，并把它纳入 candidate canonicalization、candidate set hash、FSB3 和 admission binding。v3 同时支持公共 CA、预安装的私有 CA 和叶证书 pinning；任何模式都不得自动降级为另一模式。

Flowersec 负责可靠传递、绑定并执行 endpoint 信任策略。证书签发、CA 管理、pin 生成、证书发布和轮换编排仍由部署系统负责。证书 pin 是 endpoint 认证材料，不是 Flowersec peer identity，也不替代 admission credential 或 Flowersec E2EE。

本设计作为一个完整的新 contract 落地，不在 v2 上增加例外。v3 使用 `flowersec/3`、`flowersec-direct/3`、`flowersec-tunnel/3` 和完整的 `FS*3` frame family。v2 与 v3 可以由部署方并行开放，但单次连接不协商版本，也不自动回退。

## 2. 规范语言和边界

本文中的“必须”“不得”“应”“可以”分别对应 RFC 2119 / RFC 8174 的 MUST、MUST NOT、SHOULD、MAY。

### 2.1 Flowersec v3 负责

- 定义 artifact、candidate 和 TLS policy 的严格 schema；
- 对 URL、pin 集合和 candidate 集合做确定性 canonicalization；
- 将 TLS policy 绑定到 candidate hash、FSB3 和 admission；
- 按 runtime capability 选择可执行的 candidate；
- 通过统一 adapter 执行 CA 或 pin 验证；
- 为 TLS 失败、artifact 刷新和 lease 生命周期提供跨语言一致的状态语义；
- 维护跨 TypeScript、Go、Rust、Swift 的 codec、vectors 和互操作测试。

### 2.2 Flowersec v3 不负责

- 生成、签发、续期或吊销证书；
- 建立、分发或修改公共 CA、私有 CA 和平台 trust store；
- 主动连接 endpoint 以抓取证书或推导 pin；
- 决定证书灰度、回滚、重叠窗口和部署批次；
- 将证书 hash 暴露给 Session、RPC、Stream 或应用消息 API；
- 在本次演进中重做 E2EE、RPC、stream、DATAGRAM 或业务授权语义。

部署系统必须先从可信的证书发布流程获得 pin，再把它交给 Flowersec control plane。SDK 不提供 trust-on-first-use，也不接受“连接一次并记住证书”的隐式模式。

## 3. v3 Contract 的规范来源

本文是 v3 设计阶段的最高优先级、自包含规范来源，完整定义 v3 相对 v2 的变更。未被本文改写的 frame、session wire 和应用 codec 规则，规范性继承下列固定基准来源，并严格应用 3.2 和 3.3 的替换。基准提交固定后，这些文件的后续变化不会自动改变 v3：

- `docs/TRANSPORT_V2_WIRE.md`：未改写的 frame layout、状态机、资源上限、密码学运算和失败关闭规则；
- `docs/TRANSPORT_V2_ARCHITECTURE.md` 与 `stability/transport_v2_contract.json`：仅限本文明确引用的 carrier tuple、生命周期和 Controller 基线；
- `stability/transport_v2_contract.json` 的 `wire_fixtures` 所登记 vectors：仅限 v2 wire 文档明确声明由 vector 冻结的字段集、字节序、registry 值和 canonical codec；
- `testdata/transport_v2/connection_controller_vectors.json` 与 `stability/connection_controller_recovery.json`：仅限本文未改写的 Controller 生命周期和错误恢复映射。

Artifact v3、candidate、URL normalization、TLS policy、capability v3、pin refresh、lease 和 Controller 调度由本文完整定义，不从实现代码推导。有限的正例 vector 不能扩大接受集合；负例 vector 不能替代本文的通用拒绝规则。

规范优先级如下：

1. 本文；
2. 上述固定基准来源，且只在各自限定范围内有效；
3. 实现阶段从本文生成并经审计的 v3 machine-readable registry 和 v3 vectors。

实现代码、v2 runtime 行为和其他说明文档不是 v3 的补充规范。本文定稿不依赖尚未生成的 v3 registry、英文实现规范或 vectors；它们是实现阶段的派生一致性产物，不能反向扩大或修改本文。派生产物缺失时不得发布 v3 实现；派生产物与本文冲突时必须停止发布并修正冲突，不能任选一方解释。实现完成后，仓库内英文规范必须完整转录本文的规范语义，中文设计定稿与英文实现规范的任何歧义都必须在 release 前通过正式设计修订消除。

### 3.1 Version、profile、路径和路由标识

| 项目 | v3 固定值 |
| --- | --- |
| artifact version | `3` |
| session profile | `flowersec/3` |
| direct wire profile / raw QUIC ALPN | `flowersec-direct/3` |
| tunnel wire profile / raw QUIC ALPN | `flowersec-tunnel/3` |
| direct WebSocket path | `/flowersec/v3/direct` |
| tunnel WebSocket path | `/flowersec/v3/tunnel` |
| direct WebSocket subprotocol | `flowersec.direct.v3` |
| tunnel WebSocket subprotocol | `flowersec.tunnel.v3` |
| direct WebTransport path | `/flowersec/webtransport/v3/direct` |
| tunnel WebTransport path | `/flowersec/webtransport/v3/tunnel` |
| correlation version | `3` |
| capability schema version | `3` |

跨 path 的组合无效。生产 v3 candidate 只允许 `wss://`、`quic://` 和 `https://`；v2 的明文 `ws://` loopback 例外不进入 v3。明文回环只能存在于独立、不可签发生产 artifact 的 test-only profile。

### 3.2 Frame family 替换

| v2 | v3 | 其他布局变化 |
| --- | --- | --- |
| `FSB2` | `FSB3` | payload 中 candidate 增加必需的 `tls` |
| `FSA2` | `FSA3` | 无 |
| `FSC2` | `FSC3` | 无 |
| `FSH2` | `FSH3` | profile、admission binding 和域标签升级 |
| `FSS2` | `FSS3` | setup MAC 域标签升级 |
| `FSR2` | `FSR3` | record AAD 域标签升级 |
| `FSD2` | `FSD3` | unreliable AAD 和密钥域标签升级 |

上述 frame 的 magic 最后一字节由 ASCII `2` 改为 ASCII `3`，固定 version byte 由 `2` 改为 `3`。长度、offset、状态码、消息顺序、保留位、上限和状态机保持基准 v2 规范不变，除非本文另有明确规定。

FSB3 仍为 `12 + payload_length` 字节，payload 为 `1..32768` 字节。FSA3 仍为 `8 + reason_length` 字节，reason 最多 64 字节。FSC3、FSH3、FSS3、FSR3、FSD3 继承对应 v2 frame 的精确长度和上限。

### 3.3 密码学和 hash 域替换

每个 v2 域都必须替换为独立的 v3 域；禁止 v2/v3 共用标签。精确替换如下：

| v2 label | v3 label |
| --- | --- |
| `flowersec-v2-session-contract\0` | `flowersec-v3-session-contract\0` |
| `flowersec-v2-candidates\0` | `flowersec-v3-candidates\0` |
| `flowersec-v2-admission\0` | `flowersec-v3-admission\0` |
| `flowersec-v2-runtime-capability\0` | `flowersec-v3-runtime-capability\0` |
| `flowersec-v2-handshake\0` | `flowersec-v3-handshake\0` |
| `flowersec v2 server finished` | `flowersec v3 server finished` |
| `flowersec v2 client finished` | `flowersec v3 client finished` |
| `flowersec v2 epoch zero` | `flowersec v3 epoch zero` |
| `flowersec v2 control root` | `flowersec v3 control root` |
| `flowersec v2 stream root` | `flowersec v3 stream root` |
| `flowersec v2 setup root` | `flowersec v3 setup root` |
| `flowersec v2 rekey root` | `flowersec v3 rekey root` |
| `flowersec v2 next epoch` | `flowersec v3 next epoch` |
| `flowersec v2 stream` | `flowersec v3 stream` |
| `flowersec v2 control` | `flowersec v3 control` |
| `flowersec v2 record key` | `flowersec v3 record key` |
| `flowersec v2 nonce` | `flowersec v3 nonce` |
| `flowersec v2 unreliable root` | `flowersec v3 unreliable root` |
| `flowersec v2 unreliable` | `flowersec v3 unreliable` |
| `flowersec v2 unreliable key` | `flowersec v3 unreliable key` |
| `flowersec v2 unreliable nonce` | `flowersec v3 unreliable nonce` |
| `flowersec-v2-unreliable` | `flowersec-v3-unreliable` |
| `flowersec-v2-setup\0` | `flowersec-v3-setup\0` |
| `flowersec-v2-record\0` | `flowersec-v3-record\0` |
| `flowersec-v2-open\0` | `flowersec-v3-open\0` |
| `flowersec-v2-acceptor-admissions\0` | `flowersec-v3-acceptor-admissions\0` |

v3 新增：

```text
tls_policy_digest = SHA-256(
  "flowersec-v3-tls-policy\0" || LP(JCS(tls_policy))
)
```

其中 `LP(x) = uint32_be(len(x)) || x`，`len` 是字节数。实现必须审计所有包含 `v2` 的密码学 preimage、HKDF info、HMAC input、AAD 和稳定 hash label；v3 路径不得调用仍使用 v2 label 的 helper。

acceptor admissions hash 的输入是同一 artifact 为每个 candidate 生成的完整 FSB3，按 `chosen_candidate_id` 的 ASCII 字节字典序严格升序：

```text
acceptor_admissions_hash = SHA-256(
  "flowersec-v3-acceptor-admissions\0"
  || LP(complete_FSB3_1)
  || ...
  || LP(complete_FSB3_n)
)
```

`n` 必须为 `1..4`。registry 必须包含此公式和至少一个多 candidate vector。

### 3.4 版本隔离

- v3 client 只连接 v3 URL/profile，只发送 `FS*3`；
- v3 server 在 v3 path/ALPN/subprotocol 上只接受 `FS*3`；
- 收到 v2 magic、profile、ALPN 或 subprotocol 时立即以 protocol failure 关闭；
- artifact 不携带版本候选列表；SDK 不做 wire negotiation；
- v3 失败后不得自动请求 v2 artifact 或改连 v2 endpoint。

部署迁移必须通过独立的 v2、v3 endpoint 和显式选择完成。

## 4. 严格 JSON 与通用限制

以下对象且只有以下对象使用 RFC 8785 JSON Canonicalization Scheme（JCS）：

- 完整 artifact，包括 `scoped.payload`；
- FSB3 payload；
- runtime capability descriptor；
- canonical candidate、TLS policy、candidate set、session contract projection 和其他明确写为 `JCS(...)` 的 hash 输入。

这些对象中由 Flowersec 固定 schema 定义的数值字段必须是 `0..9007199254740991` 范围内的整数；具体字段的更小边界继续生效。`scoped.payload` 使用 5.3 的独立 signed-safe-integer 规则。

FSH3 JSON payload 不升级为 JCS，而是逐字节继承基准 FSH2 canonical encoding 和 handshake vectors，只应用 3.2/3.3 的版本替换。RPC/application JSON 继续使用其固定的 v2 codec。本文没有改变 FSH3、FSS3/OPEN、RPC 或应用 payload 的 JSON value domain。

OPEN metadata 的非 JCS canonical JSON 规则在 v3 中明确冻结为：根必须是 object；只允许 object、array、string、boolean、null 和 `-9007199254740991..9007199254740991` 的十进制整数；禁止浮点、指数、负零、重复 key、尾随字节和非法 UTF-8。string 与 key 必须为 Unicode 15.1 已分配 scalar 的 NFC，禁止 C0/C1 control；object key 非空且按 UTF-16 code unit 字典序排列，array 保序；字符串只转义 `"` 和 `\\`，不得使用其他可选转义。空 metadata 在发送前编码为 `{}`。资源上限为 canonical UTF-8 4096 字节、depth 4、根之外总 node 64、每个 object 64 members、每个 array 32 elements、key 64 UTF-8 字节、string value 512 UTF-8 字节。OPEN kind 使用同一 Unicode/NFC/control 规则，且为 `1..128` UTF-8 字节。RPC/application JSON 的可接受值域和编码继续由其固定基准 codec 定义，不进入 artifact/FSB3 的 JCS 域。

对于上面列出的 JCS 对象，解码器必须在构造对象前拒绝重复 key，并拒绝非法 UTF-8、BOM、错误类型、非 JCS 字节、非 canonical base64url、违反本节数组规则的顺序或重复项、超限值和尾随字节。固定 schema object 拒绝未知或缺失字段；`scoped.payload` 允许业务自定义 key，只执行 5.3 的值域和资源限制。继承的非 JCS codec 只执行固定 v2 规则，不得额外套用本段 JCS rejection。URL host 的 Unicode 处理由 5.5 完整定义。

规范 vector 文件的 JSON 容器不是 wire，除非 registry 对该文件明确声明 canonical container。vectors 必须携带上述对象的精确 canonical UTF-8/hex/base64url 结果以及正反例，不能依赖 vector 文件自身的成员顺序表达 wire。

JCS 不重排数组。v3 对每个数组采用以下唯一规则：

| 数组 | 输入和 canonicalization 规则 |
| --- | --- |
| artifact `path.candidates` | 接受任意输入顺序；生成 canonical candidate set 时按 candidate ID 排序 |
| canonical candidate set / FSB3 `candidates` | 输入必须已按 candidate ID 严格排序 |
| pin policy `pins` | 输入必须按第 6.2 节严格排序 |
| `allowed_suites` | 输入必须按 suite 数值严格升序 |
| capability `tuples` / `unsupported` | 输入必须按第 8 节严格排序 |
| `scoped` / `correlation.tags` | 是有序列表；保留输入顺序，只拒绝重复的 scope/key |

FSH3、OPEN、RPC/application 等非 JCS 对象的数组保持各自固定 codec 的顺序语义。实现不得为了得到 JCS 而对未被上述规则授权的数组静默重排。

固定上限如下：

| 对象 | 上限 |
| --- | ---: |
| artifact canonical UTF-8 JSON | 65536 字节 |
| 每个 artifact 的 candidates | 1..4 个 |
| 单个 canonical candidate | 2304 字节 |
| canonical candidate set | 12288 字节 |
| FSB3 canonical payload | 32768 字节 |
| 单个 candidate URL / normalized URL | 2048 字节 |
| 单个 candidate ID | 64 字节 |
| pin 集合 | 1..4 个 |

原始 artifact 输入也不得超过 65536 字节，并且必须逐字节等于解析结果的 JCS 编码。

## 5. Artifact v3 schema

### 5.1 顶层和 session

Artifact 顶层必须恰好包含：

```text
v, profile, session, path, scoped, correlation
```

`v` 必须为 `3`，`profile` 必须为 `flowersec/3`。

`session` 必须恰好包含：

```text
channel_id
init_expire_at_unix_s
idle_timeout_seconds
establish_timeout_seconds
rekey_prepare_timeout_seconds
rekey_completion_timeout_seconds
max_inbound_streams
e2ee_psk_b64u
allowed_suites
default_suite
selected_features
contract_hash_b64u
```

session 字段的完整约束如下；除 `allowed_suites` 外均为 scalar：

| 字段 | 精确约束 |
| --- | --- |
| `channel_id` | 匹配 `[A-Za-z0-9._~-]+`，UTF-8 长度 `1..128` 字节 |
| `init_expire_at_unix_s` | `1..9007199254740991` 的整数，表示 initiation 的排他过期时刻 |
| `idle_timeout_seconds` | `0..4294967295` 的整数；`0` 表示禁用 session idle timer |
| `establish_timeout_seconds` | 整数 `30` |
| `rekey_prepare_timeout_seconds` | 整数 `10` |
| `rekey_completion_timeout_seconds` | 整数 `30` |
| `max_inbound_streams` | `1..128` 的整数 |
| `e2ee_psk_b64u` | 解码为恰好 32 字节的无填充 canonical base64url |
| `allowed_suites` | 非空、严格数值升序、无重复，只允许 `1` 和 `2` |
| `default_suite` | 整数，且必须出现在 `allowed_suites` 中 |
| `selected_features` | 整数 `0` |
| `contract_hash_b64u` | 解码为恰好 32 字节的无填充 canonical base64url，并等于本节计算值 |

在可信 wall clock 上，`now >= init_expire_at_unix_s` 即 artifact initiation 已过期。client 必须在 candidate race 前、每次 race 无 winner 结束后且聚合失败或判断 policy-refresh trigger 前、TLS winner 后且 `commitSpend` 前、以及 `commitSpend` 后且发送 FSB3 前检查。该 race-end 检查同时适用于 primary A 和 replacement B；此时若已过期，必须 retire pre-spend lease，返回 `expired_artifact / retryable` 并进入普通 primary acquisition，不得由这次过期触发 policy refresh 或取得 B。其他 pre-spend 过期使用同一处理；若过期的是已经成功 claim 的 replacement B，取得 B 时已耗尽的 cycle replacement 配额不得恢复，后续 primary 再出现 policy-refresh trigger 时 terminal。若 `commitSpend` 已开始，lease 保持 consumed，仍不得发送 FSB3，并返回同一公共错误。server 必须在接收 FSB3 时检查；若其时钟判定已过期，以 FSA3 retryable 和已审计 reason `expired_artifact` 拒绝，client 仍按 FSA3 的脱敏 admission error 暴露，不信任远端 reason 生成本地 `expired_artifact` code。过期不是 TLS failure；它本身不创建或递增 replacement 配额，但也不撤销已经取得 B 时消耗的配额。

session contract projection 必须恰好包含下列字段和值，不包含 initiation expiry、PSK 和 hash 自身：

```text
projection.allowed_suites                  = session.allowed_suites
projection.channel_id                      = session.channel_id
projection.default_suite                   = session.default_suite
projection.establish_timeout_seconds       = session.establish_timeout_seconds
projection.idle_timeout_seconds            = session.idle_timeout_seconds
projection.max_inbound_streams             = session.max_inbound_streams
projection.profile                         = "flowersec/3"
projection.rekey_completion_timeout_seconds = session.rekey_completion_timeout_seconds
projection.rekey_prepare_timeout_seconds   = session.rekey_prepare_timeout_seconds
projection.selected_features               = session.selected_features
```

```text
session_contract_hash = SHA-256(
  "flowersec-v3-session-contract\0" || LP(JCS(session_contract_projection))
)
```

### 5.2 Path

direct path 必须恰好包含：

```text
kind = "direct"
rendezvous_group_id
listener_audience
routing_token
candidates
```

tunnel path 必须恰好包含：

```text
kind = "tunnel"
rendezvous_group_id
listener_audience
role
local_endpoint_instance_id
expected_peer_endpoint_instance_id
token
candidates
```

两个 path 共有以下约束：`rendezvous_group_id` 和 `listener_audience` 都匹配 `[A-Za-z0-9._~-]+`，UTF-8 长度均为 `1..128` 字节；`candidates` 为第 5.4 节定义的 `1..4` 项数组。

direct 的 `routing_token` 必须是 `1..8192` 字节的 ASCII string。tunnel 的 `role` 必须是整数 `1` 或 `2`：`1` 表示该 artifact 持有方建立 Flowersec client-role Session，`2` 表示建立 Flowersec server-role Session。`local_endpoint_instance_id` 和 `expected_peer_endpoint_instance_id` 使用同一 `1..128` 字节 registry-ID 规则且不得相等；`token` 必须是 `1..8192` 字节的 ASCII string。这里 ASCII 指每个 Unicode scalar 都在 `U+0000..U+007F`，长度等于 UTF-8 字节数。direct 与 tunnel 字段不得混用。

### 5.3 Scope 和 correlation

`scoped` 的每项必须恰好包含 `scope`、`scope_version`、`critical`、`payload`；最多 8 项，scope 名不可重复。`scope` 匹配 `[a-z][a-z0-9._-]{0,63}`，`scope_version` 为 `1..65535`，`critical` 为 boolean。

`payload` 必须是 JSON object，并作为完整 artifact 的一部分使用 JCS。业务 key 不属于 Flowersec 固定 schema，允许任意符合 JCS 的 Unicode string；duplicate key 必须在解析前拒绝。递归值域只允许 object、array、string、`true`、`false`、`null` 和 `-9007199254740991..9007199254740991` 的整数；不允许浮点、负零或超出 safe-integer 的 number。资源边界固定为：

| `scoped.payload` 项目 | 上限 |
| --- | ---: |
| JCS UTF-8 总长度 | 4096 字节 |
| nesting depth | 16，根 object 计为 1 |
| 总 JSON node | 256，根和每个 container/scalar 都计 1 |
| 每个 object 的 members | 64 |
| 每个 array 的 elements | 64 |
| 单个 object key | 128 UTF-8 字节 |
| 单个 string value | 1024 UTF-8 字节 |

Object member 由 JCS 排序；array 顺序保留且有语义。所有语言必须在递归分配前执行 depth/node/collection 上限，并共享空 object、每个整数边界、Unicode key、最大深度/节点和超限拒绝 vectors。

`correlation` 必须恰好包含 `v`、`tags`，其中 `v` 必须为 `3`；`tags` 必须是 `0..8` 项数组。每个 tag 必须恰好包含 `key`、`value`：`key` 匹配 `[a-z][a-z0-9._-]{0,31}`，`value` 是 `1..128` 字节 ASCII string，key 不可重复。tag 数组有序且保留输入顺序。

### 5.4 Candidate

artifact 中每个 candidate 必须恰好包含以下五个字段：

```text
id, carrier, url, wire_profile, tls
```

- `id` 匹配 `[a-z0-9][a-z0-9._-]*`，UTF-8 长度为 `1..64`，在 artifact 内唯一；
- `carrier` 只能是 `websocket`、`raw_quic`、`webtransport`；
- `wire_profile` 必须与 path 精确对应；
- `url` 必须按第 5.5 节执行 v3 URL normalization；
- `normalized_url` 不是 artifact 输入字段，只能是解码后内部生成的值；
- `tls` 必须符合第 6 节的唯一一种 policy。

canonical candidate 必须恰好包含：

```text
carrier, id, normalized_url, tls, wire_profile
```

candidate 按 `id` 的 ASCII 字节字典序严格升序排列。candidate set 是该有序数组的 JCS 编码：

```text
candidate_set_hash = SHA-256(
  "flowersec-v3-candidates\0" || LP(JCS(canonical_candidates))
)
```

endpoint key 定义为 `(carrier, path.kind, normalized_url)`。一个 artifact 中 endpoint key 必须唯一；因此同一 endpoint 不得重复出现，也不得分别以 CA 和 pin 两种 policy 出现。轮换所需的多个 pin 必须放在同一个 policy 的 `pins` 数组中。

不同 endpoint key 可以分别使用 CA 和 pin，也可以参与同一次受控竞速，因为它们都是 artifact 显式授权的独立 endpoint。这不构成同一 endpoint 的安全降级。

### 5.5 URL normalization

实现必须直接按以下算法处理 candidate `url`，不得委托给会改写接受集合的通用 URL serializer：

1. 输入必须是 `1..2048` UTF-8 字节；出现 `\\`、`?`、`#` 或 `%` 时拒绝，因此不允许 userinfo、query、fragment、percent escape 或反斜线；
2. 在第一个字面量 `://` 处分割；scheme 必须匹配 ASCII `[A-Za-z][A-Za-z0-9+.-]*` 并转换为 lowercase；其后内容在第一个 `/` 处分成 authority 和 path；authority 必须非空且不得含 `@`；
3. 以 `[` 开头的 authority 必须是 `[IPv6]` 或 `[IPv6]:port`；IPv6 必须合法、无 zone ID、无 embedded dotted-decimal，并按 RFC 5952 lowercase 压缩格式输出且保留方括号；非括号 authority 最多含一个 `:`；
4. 非括号 host 若只含 ASCII digit 和 `.`，必须恰好是四段十进制 IPv4，每段 `0..255`，除单个 `0` 外不得有前导零，并按无前导零形式输出；否则按 Unicode 15.1 UTS #46 lookup profile 处理：non-transitional、STD3、label validation、hyphen、ContextJ、Bidi 和 DNS length checks 全部开启，输出 lowercase A-label。对该 ASCII 输出再执行 WHATWG `ends in a number` 防护：若最后一个 label 匹配 `[0-9]+`，或按 ASCII 大小写不敏感匹配 `0x[0-9a-f]*`（包括 `0x`），必须拒绝整个 URL，不得交给平台解析器改写为 legacy、缩写或整型 IPv4；空 host、空 label、trailing dot、超过 63 字节的 label 或超过 253 字节的 host 同样拒绝；
5. port 若存在必须匹配 `[0-9]+` 且数值为 `1..65535`；输出时去掉前导零，`443` 完全省略；
6. `websocket` 只接受 `wss` 和精确 path `/flowersec/v3/{direct|tunnel}`；`webtransport` 只接受 `https` 和精确 path `/flowersec/webtransport/v3/{direct|tunnel}`；`raw_quic` 只接受 `quic`，path 只能为空或 `/` 且输出为空；生产 v3 不接受 `ws`；
7. 输出为 `scheme://normalized_authority + normalized_path`，必须仍不超过 2048 UTF-8 字节。任何解析错误都拒绝整个 artifact，不尝试浏览器或平台的宽松修复。浏览器 adapter 把该 normalized URL 交给 WHATWG URL parser 后，必须验证 parser 输出的 scheme、host、port 和 path 与输入逐项相同；任何改写或拒绝都是 `invalid_artifact`，不得发起连接。

`testdata/transport_v3/idna_vectors.json` 必须冻结 Unicode 15.1 delta、A-label round-trip、IPv4/IPv6、端口和所有拒绝边界；至少覆盖 canonical 四段 IPv4、前导零、缩写 IPv4、单 label 整数、legacy hex、`0x7f.0.0.1`、`1.2.3.0x7f`、`example.1`、`example.0x` 和不以数字结尾的合法 DNS。浏览器 vectors 还必须证明 normalized URL 经 WHATWG parser 后不被改写或拒绝；四语言的 normalized URL 必须逐字节一致。

## 6. TLS policy

每个 candidate 必须选择且只能选择一种模式。

### 6.1 CA mode

CA policy 的 JCS 值必须恰好为：

```json
{"mode":"ca"}
```

CA mode 使用标准 Web PKI / 平台验证：

- 验证完整证书链、用途、签名、有效期和平台安全策略，并执行平台或显式 verifier 配置的吊销策略；
- 按 normalized URL 的 host 验证 DNS-ID / IP SAN；不得只比较 Common Name；
- 公共 CA 使用平台 trust roots；
- 私有 CA 只通过预安装或管理员管理的 trust roots 生效；
- 原生 SDK 可以使用调用方明确配置的 roots，否则使用平台 trust store；
- artifact 不携带 root certificate，也不能打开通用的 `InsecureSkipVerify`。

浏览器无法通过 Flowersec JavaScript API 临时安装私有根。浏览器中的私有 CA 必须先进入浏览器或操作系统的受管信任库。

CA mode 构造 WebTransport 时不得设置 `serverCertificateHashes`；不能传空数组来模拟 CA mode。

### 6.2 Pin mode schema

Pin policy 的精确代数结构为：

```text
PinPolicy {
  mode: "pin"
  pins: Pin[1..4]
}

Pin {
  algorithm: "sha-256"
  not_after_unix_s: safe_integer
  value_b64u: base64url_sha256
}
```

每个 pin 必须恰好包含 `algorithm`、`value_b64u`、`not_after_unix_s`。

- `algorithm` 初始 registry 只有 `sha-256`；未知算法使整个 artifact 成为 `invalid_artifact`；
- `value_b64u` 必须是叶 X.509v3 证书完整 DER 的 SHA-256；
- `value_b64u` 必须是解码后恰好 32 字节、无填充且重新编码不变的 base64url；
- `not_after_unix_s` 必须是 `1..9007199254740991` 的整数，表示该 pin policy 的排他过期时刻；
- 相同 `(algorithm, value_b64u)` 不得重复，即使过期时间不同；
- pins 按 `algorithm`、再按 canonical `value_b64u` 的 ASCII 字节字典序严格升序；比较的是编码后的字符串，不是解码后的 32 字节；输入顺序错误时拒绝 artifact，不由消费者静默重排；
- pin 数量必须为 `1..4`。

Pin mode 的 pin 集合是 endpoint 的唯一证书身份信任依据。它替代 RFC 5280 chain、hostname 和 PKI revocation 的信任决定，不与 CA mode 叠加，也不执行 CRL/OCSP 查询。URL 仍决定网络地址、Origin、SNI、path 和 endpoint key，但不额外授权一条 CA 信任路径。旧 pin 的失效只由 artifact 生命周期、`not_after_unix_s` 和重新签发控制。

Pin mode 允许自签名叶证书，也允许 CA 签发的叶证书；它不要求叶证书必须自签名。无论 issuer 是谁，chain trust 都不参与 pin mode 的接受决定，证书仍必须满足 6.3 的当前有效期、有效期长度、算法和 TLS 私钥持有证明。

### 6.3 Pin 证书的可移植基线

为与浏览器 WebTransport `serverCertificateHashes` 保持共同语义，v3 定义以下可移植签发与部署 profile：

- TLS 只使用 1.3；
- 服务器叶证书是语法有效的 X.509v3；
- handshake 时证书处于自身 NotBefore / NotAfter 有效期内；
- 证书总有效期 `NotAfter - NotBefore` 不超过 1209600 秒；
- 叶证书的 SubjectPublicKeyInfo 必须是 ECDSA secp256r1（P-256）；这里不把 CA 对叶证书的签名算法当作额外 pin 信任依据；RSA 叶公钥不得用于 pin mode；
- 计算并以 constant-time 方式比较叶证书完整 DER 的 SHA-256；
- 至少匹配一个 attempt 的 active pin。

这些限制只约束 pin mode。CA mode 的证书算法和有效期继续服从平台 PKI policy。原生 verifier 必须拒绝非 P-256 pin 证书。浏览器 adapter 必须执行 WebTransport 标准的 custom-certificate requirements；JavaScript 无法独立读取 peer certificate 并额外证明 P-256-only，因此浏览器可能接受标准允许的其他非 RSA 算法。使用此类证书的 endpoint 不符合 Flowersec v3 部署 profile，也不具备跨 runtime 互操作保证；SDK 不得把这种平台限制误报为已由 JavaScript 验证。

Pin mode 只替换证书身份的 PKI 信任决定。TLS 1.3 key exchange、Server CertificateVerify、Finished、transcript、cipher suite、signature scheme 和 ALPN 验证必须继续由标准 TLS provider 执行；peer 必须证明持有叶证书 SPKI 对应的私钥。由于标准 provider 的 certificate callback 通常先于 CertificateVerify/Finished，静态证书 profile 检查与 pin 比较可以先执行，hash 匹配只允许握手继续，不能单独建立 carrier。自定义 verifier 不得伪造 signature-validation success，也不得在完整 TLS handshake 和 pin 验证都成功前暴露 carrier、发送 HTTP Upgrade/CONNECT、发送应用字节或发送 FSB3。

v3 endpoint 必须只开放 TLS 1.3，必须禁用 TLS 0-RTT，并在 v3 首版禁用 TLS session ticket 和 session resumption。可配置这些选项的客户端也必须关闭它们；浏览器客户端依赖服务器端配置。Flowersec application 0-RTT 继续被禁止。

### 6.4 Active pin snapshot 与过期语义

每次 candidate attempt 开始时，Controller 从其可信 wall clock 取得一次整数 Unix 秒 `attempt_now`，并固定：

```text
active_pins = [pin for pin in declared_pins
               if attempt_now < pin.not_after_unix_s]
```

- 过滤必须发生在构造 transport adapter 之前；
- active set 为空时不得创建 socket、TLS 或 WebTransport，不得 durable-spend lease，结果为 `tls_policy_expired`；
- adapter 只接收 active pins；
- canonical candidate、candidate set hash 和 FSB3 始终绑定 artifact 中完整的 declared pins；
- attempt 开始后 policy 时间不再变化；TLS stack 仍独立检查证书自身的当前有效期；
- 已建立 Session 不因随后到达 pin policy 过期时间而关闭；重连必须使用新的 artifact；
- SDK 不自行延长 `not_after_unix_s`，不加入隐式 clock-skew grace period。

签发方必须让 `not_after_unix_s` 不晚于对应证书的 NotAfter，并通过足够的旧、新 pin 重叠窗口吸收客户端时钟误差和发布延迟。时钟容差属于签发与部署 policy，不属于 adapter 行为。

### 6.5 轮换

轮换按以下顺序由部署系统执行：

1. 在切换证书前签发同时包含旧、新 pin 的 artifact；
2. 等待该配置到达需要覆盖的客户端；
3. 服务器切换为新证书；
4. 保持双 pin 到既定重叠窗口结束；
5. 后续 artifact 删除旧 pin，或让旧 pin 到达其显式 `not_after_unix_s`。

Flowersec 不保证旧 artifact 在服务器提前切换、重叠窗口不足或客户端时钟错误时仍可连接；它只按第 10 节执行一次受限刷新，绝不自动改用 CA。

## 7. FSB3 和 admission binding

FSB3 payload 使用 JCS，字段必须恰好如下。

direct：

```text
candidate_set_hash_b64u
candidates
channel_id
chosen_candidate_id
listener_audience
profile
rendezvous_group_id
routing_token
session_contract_hash_b64u
```

tunnel：

```text
attach_token
candidate_set_hash_b64u
candidates
channel_id
chosen_candidate_id
endpoint_instance_id
listener_audience
profile
rendezvous_group_id
role
session_contract_hash_b64u
```

FSB3 必须由已验证 artifact 和被选 candidate 按以下等式投影，不接受调用方独立提供这些值：

```text
common.profile                    = artifact.profile = "flowersec/3"
common.channel_id                 = artifact.session.channel_id
common.session_contract_hash_b64u = artifact.session.contract_hash_b64u
common.rendezvous_group_id        = artifact.path.rendezvous_group_id
common.listener_audience          = artifact.path.listener_audience
common.candidates                 = canonicalize(artifact.path.candidates)
common.candidate_set_hash_b64u     = candidate_set_hash(common.candidates)
common.chosen_candidate_id         = chosen_candidate.id

direct.routing_token              = artifact.path.routing_token

tunnel.attach_token               = artifact.path.token
tunnel.endpoint_instance_id       = artifact.path.local_endpoint_instance_id
tunnel.role                       = artifact.path.role
```

direct FSB3 只能由 direct artifact 生成，且不得含 `attach_token`、`endpoint_instance_id` 或 `role`；tunnel FSB3 只能由 tunnel artifact 生成，且不得含 `routing_token`。tunnel `role=1` 必须解释为 client role，`role=2` 必须解释为 server role。接收端除通用 canonical 校验外，必须将每个 FSB3 字段与其已查得 authorization record 中的 artifact 投影逐项比较；任何缺失、跨 variant 字段、role 解释或等式不一致都以 admission invalid 失败关闭。

`candidates` 是第 5.4 节的完整 canonical candidate set，因而包含每个 candidate 的完整 TLS policy。`chosen_candidate_id` 必须存在于该集合。接收方必须重新执行 URL normalization、TLS policy 校验、排序、endpoint key 唯一性、candidate hash 和 session contract hash 校验。

```text
admission_binding = SHA-256(
  "flowersec-v3-admission\0" || complete_FSB3
)
```

TLS policy 的任何变化，包括 mode、pin value、pin 过期时间或 pin 集合变化，都必须改变 canonical candidate、candidate set hash、完整 FSB3 和 admission binding。

TLS handshake 完成前不得发送 FSB3。选出 carrier winner 后，connector 按 v2 的 one-shot 规则 durable-spend lease，然后只写一次 FSB3 credential。TLS 失败发生在 admission 之前，不能发送或伪造 FSA3。

FSA3 只保留部署方 admission reason：success 的 reason 为空，reject/retryable 的 reason 必须是已审计 registry 中的 `[a-z][a-z0-9_]*` token。TLS 错误永远不是 FSA3 reason。

## 8. Runtime capability v3

capability descriptor 必须恰好包含：

```text
language, runtime, schemaVersion, tuples, unsupported
```

`schemaVersion` 必须为 `3`。每个 tuple 必须恰好包含：

```text
carrier
datagrams
migration
networkMode
path
reliableStreams
securityModes
sessionRole
```

descriptor scalar 和 tuple 的完整约束如下：

- `language`、`runtime` 和 `unsupported.reason` 都匹配 `[a-z][a-z0-9_]{0,127}`；`language/runtime` 组合必须存在于 8.1 的初始 registry；reason 必须是 8.1 为该 runtime/carrier/state 精确指定的值，不能从一个通用字符串集合中任意选择；
- `carrier` 只能是 `websocket`、`raw_quic`、`webtransport`；`networkMode` 只能是 `dial`、`listen`；`sessionRole` 只能是 `client`、`server`；`path` 只能是 `direct`、`tunnel`；三个 capability 字段必须是 boolean；
- `reliableStreams` 必须为 `true`；WebSocket 的 `datagrams` 和 `migration` 必须为 `false`；其他 carrier 的三个 boolean 必须与 8.1 为该 runtime 登记的精确 tuple 一致；
- direct 只允许 `(dial,client)` 或 `(listen,server)`；tunnel 只允许 `dial`，role 可以是 `client` 或 `server`；不得出现 tunnel listen、direct dial server 或 direct listen client；
- tuple 的唯一身份是 `(carrier, networkMode, sessionRole, path)`；同一身份只能出现一次，即使 capability boolean 或 `securityModes` 不同也视为重复；
- `tuples` 按该四元组逐项比较，字符串全部使用 ASCII 字节字典序，严格升序排列；boolean 和 `securityModes` 不参与排序或 identity，但仍进入 JCS 和 digest。

`unsupported` 每项必须恰好包含 `carrier`、`reason`，按 `carrier` 的 ASCII 字节字典序严格升序；carrier 不得重复。`tuples` 和 `unsupported` 共同对三个已登记 carrier 做精确分区：每个 carrier 要么至少有一个 tuple，要么在 `unsupported` 中恰好出现一次，不得同时出现或两边都不出现。一个 carrier 被标记 unsupported 时，该 carrier 的全部 tuple 都必须缺失。

`securityModes` 规则如下：

- dial tuple：必须是 `['ca']`、`['pin']` 或 `['ca','pin']` 之一；
- listen tuple：必须是空数组 `[]`，因为 server certificate presentation 不是 dial-side verifier capability；
- 元素不得重复，顺序固定为 `ca` 后 `pin`；
- candidate 的 mode 不在对应 dial tuple 中时，不得创建 transport，结果为 `tls_unsupported`；
- tuple 不得从同一 runtime 的其他 tuple 推导或拼成笛卡尔积。

descriptor 使用 JCS，digest 为：

```text
runtime_capability_digest = SHA-256(
  "flowersec-v3-runtime-capability\0" || LP(JCS(descriptor))
)
```

### 8.1 首版 capability 基线

v3 初始 registry 的 runtime identity 固定为 `go/native`、`typescript/browser`、`typescript/node`、`rust/native`、`swift/ios`、`swift/macos`、`swift/linux`。为完整、无引用地枚举 tuple，定义以下封闭 tuple set；字段顺序为 `(networkMode,path,sessionRole,reliableStreams,datagrams,migration)`：

```text
W4 = (dial,direct,client,true,false,false)
     (dial,tunnel,client,true,false,false)
     (dial,tunnel,server,true,false,false)
     (listen,direct,server,true,false,false)
W3 = W4 删除 listen tuple

Q4M = (dial,direct,client,true,true,true)
      (dial,tunnel,client,true,true,true)
      (dial,tunnel,server,true,true,true)
      (listen,direct,server,true,true,false)
Q4N = Q4M 的四个 tuple 全部令 migration=false

H4 = (dial,direct,client,true,true,false)
     (dial,tunnel,client,true,true,false)
     (dial,tunnel,server,true,true,false)
     (listen,direct,server,true,true,false)
H3 = H4 删除 listen tuple
```

`W*` 只能配 `websocket`，`Q*` 只能配 `raw_quic`，`H*` 只能配 `webtransport`。每个 dial tuple 的 `securityModes` 使用下表值，每个 listen tuple 固定为 `[]`。`-` 表示该 carrier 不产生 tuple，并且必须产生表中精确的 unsupported reason。

| Runtime identity | WebSocket | Raw QUIC | WebTransport |
| --- | --- | --- | --- |
| `go/native` | `W4 / ['ca','pin']` | `Q4M / ['ca','pin']` | `H4 / ['ca','pin']` |
| `typescript/browser` | `W3 / ['ca']` | `- / browser_no_raw_udp` | `H3 / ['ca']`，匹配下述精确 provider registry 条目时为 `['ca','pin']` |
| `typescript/node` | `W4 / ['ca','pin']` | `Q4N / ['ca','pin']` | `- / node_webtransport_driver_unavailable` |
| `rust/native` | `W4 / ['ca','pin']` | `Q4M / ['ca','pin']` | `- / driver_unavailable` |
| `swift/ios` | `W3 / ['ca','pin']` | `- / swift_apple_client_profile_excludes_raw_quic` | `- / swift_apple_client_profile_excludes_webtransport` |
| `swift/macos` | `W3 / ['ca','pin']` | `- / swift_apple_client_profile_excludes_raw_quic` | `- / swift_apple_client_profile_excludes_webtransport` |
| `swift/linux` | `- / websocket_adapter_not_supported_on_linux` | `- / swift_apple_client_profile_excludes_raw_quic` | `- / swift_apple_client_profile_excludes_webtransport` |

首版只允许以下动态转换，除此之外不得删除 tuple、改变 boolean/securityModes 或选择其他 reason：

- browser 无 `WebSocket` API：完整删除 W3，reason 固定为 `browser_websocket_api_unavailable`；
- browser 无 `WebTransport` API：完整删除 H3，reason 固定为 `browser_webtransport_api_unavailable`；
- Node production native addon 未加载：完整删除 Q4N，reason 固定为 `node_native_transport_unavailable`；
- browser 不满足 pin allowlist：保留 H3，但其 dial `securityModes` 固定为 `['ca']`，不产生 unsupported 项；
- 同时命中多个转换时分别执行，并仍按 carrier 对 tuple/unsupported 做精确分区。

首版 reason registry 因而恰好为：`adapter_not_composed`（保留但首版 descriptor 不使用）、`browser_no_raw_udp`、`browser_websocket_api_unavailable`、`browser_webtransport_api_unavailable`、`node_native_transport_unavailable`、`node_webtransport_driver_unavailable`、`driver_unavailable`、`swift_apple_client_profile_excludes_raw_quic`、`websocket_adapter_not_supported_on_linux`、`swift_apple_client_profile_excludes_webtransport`。新增或改用 reason 是 contract 变更，不能由 runtime 自行创造。

浏览器 WebSocket 没有逐连接证书 pin API，因此永远不能声明 `pin`。Browser WebTransport pin 的首版 provider registry 只有一个精确条目：family `Chromium`，完整版本恰好为 `151.0.7922.34`。识别必须同时满足：`WebTransport` 为 function；`navigator.userAgentData.getHighEntropyValues(['fullVersionList'])` 成功；返回的 `fullVersionList` 恰有一个 brand 为 ASCII `Chromium` 的条目；其 version 必须逐字节等于四段无前导零十进制 `151.0.7922.34`。缺少 UA-CH、高熵值被拒绝、多个 Chromium 条目、非法版本、仅有传统 user-agent 字符串、任何其他完整版本或衍生 browser identity 都按未进入 registry 处理，只声明 `ca`。

该精确条目进入 registry 前必须对 Playwright `1.62.1` 固定下载的 Chromium `151.0.7922.34` 执行真实 production adapter 网络测试：P-256 短期证书配正确 pin 成功；同证书配错误 pin 失败；受公共 CA 信任的证书配错误 pin 仍失败；不支持 pin 参数时失败关闭而不是按 CA 建连。新增任何完整版本、browser family 或衍生 provider 都必须先通过相同测试，再更新本文或其正式后继 contract 和 machine-readable registry；版本范围、主版本推断和“相近构建”继承均禁止。

Web 沙箱没有可移植 API 可以认证浏览器二进制，也不能从不透明 `ready` rejection 证明失败由证书 hash 导致，因此 SDK 不执行目标 endpoint 负对照，也不把 rejection 当作 capability 证明。与原生 TLS provider、系统 trust store 和 WebCrypto 相同，已登记 browser provider 的正确实现属于可信计算基；伪造 UA-CH、篡改 WebIDL/TLS 行为或恶意忽略 pin 的运行时不在 Flowersec 可防御的威胁模型内。需要控制该风险的部署必须使用受管的精确浏览器构建，或只发布 CA candidate。UA-CH 仅用于选择一个已测试 provider 条目，不是远程证明或通用 feature detection。

capability descriptor 是一次 artifact acquisition 使用的不可变 snapshot。在 acquisition 前根据 `RuntimeCapabilityRegistry` instance 生成；digest 计算后不得原地修改。registry instance 由一个 runtime adapter/provider 拥有，可由多个 Controller 共享，但失效不传播到其他 registry instance 或进程。

匹配精确 provider 条目且尚未被撤销的 registry instance 状态是 `enabled`，其新 snapshot 对 H3 声明 `['ca','pin']`；未匹配条目或已经撤销的状态是 `ca_only`，只声明 `['ca']`。浏览器构造器同步抛出 `NotSupportedError` 时，adapter 必须在返回 `tls_unsupported` 前原子执行 `enabled -> ca_only`；该原子写入是线性化点，并同时影响所有 path 和 sessionRole。在线性化点前创建的 immutable snapshot 不被改写，但 adapter 必须在创建每个 pin transport 前读取 live registry gate，因此旧 snapshot 的并发或后续 pin attempt 也只能失败关闭；在线性化点后创建的 snapshot 必须从所有匹配 dial tuple 删除 `pin`。`ca_only` 在当前 registry instance 中是终态；页面、worker、进程、runtime 或 adapter 重建时创建新 instance 并重新执行精确条目识别。replacement artifact B 必须在该线性化点后创建新 snapshot，不得复用 A 的 snapshot。

## 9. 统一 TransportSecurityPolicy adapter

所有 TLS carrier 必须经过内部统一接口；carrier 不得各自解释 pin 编码、时间和降级规则。概念接口为：

```text
TransportSecurityPolicy =
  CA {
    server_name,
    roots_source
  }
  | Pin {
    server_name,
    active_leaf_der_sha256[]
  }
```

该接口是 SDK 内部边界，不进入 Session、RPC、Stream 或应用 API。

### 9.1 WebTransport

- CA mode：调用 `new WebTransport(url)`，不设置 `serverCertificateHashes`；
- pin mode：调用 `new WebTransport(url, {serverCertificateHashes:[...]})`；
- 传入的每项必须为 `{algorithm:'sha-256', value:ArrayBuffer}`，value 来自 active pin 的 32 字节解码值；
- 每次 candidate attempt 都创建独立 WebTransport；不得实现或声明 constructor pooling 选项；
- 构造器同步 `NotSupportedError` 映射为 `tls_unsupported`；
- pin mode 的 `ready` rejection 无法区分 pin、DNS、UDP/QUIC、HTTP/3 CONNECT、Origin、path 或普通网络失败，因此映射为 ordinary transport failure `connection_failed / retryable`，并携带仅供 Controller 使用的 `browser_pin_opaque` marker；该 marker 不声称 TLS 原因、不产生 `pin_mismatch` telemetry，也不直接投影为 `transport_security_failed`，但会按 10.3 发起一次 policy-sensitive replacement，禁止同 endpoint 重试旧 declared-policy digest 或改用 CA；只有新的 declared-policy digest 才能进入 replacement。
- CA mode 的 `ready` rejection 可能来自 DNS、UDP/QUIC、HTTP/3 CONNECT、Origin、path 或 TLS，浏览器不能证明层次时必须映射为 ordinary transport failure `connection_failed / retryable`，不得猜测 `ca_untrusted`、`tls_failed` 或触发 pin refresh。

Browser WebSocket 只有 CA mode。构造器异常、open 前 `error`/`close` 或其他无法分层的不透明失败必须映射为 ordinary transport failure `connection_failed / retryable`；已由 capability snapshot 证明缺少 WebSocket API 时仍在创建 transport 前按 `tls_unsupported` 跳过。不得根据浏览器错误文本猜测 TLS 原因。

### 9.2 Native TLS

Go、Rust、Node.js 和 Swift 的 pin adapter 必须执行第 6 节的相同 leaf-DER hash 和可执行证书约束，并保留标准 TLS provider 对私钥持有、transcript 和 Finished 的验证。CA mode 必须走平台或显式 roots 的标准 verifier，禁止任何 chain bypass。

Pin mode 可以通过 provider 的握手期 custom verifier 替换 RFC 5280/hostname 决定；也可以在一个 SDK 私有、隔离的 TLS socket 中仅关闭 chain rejection，等待标准 provider 完成 cryptographic handshake 后检查 leaf 和 pin。后一种方式只允许用于 pin mode，必须保留 CertificateVerify/Finished 验证，并且在 pin 成功前不得发送 WebSocket Upgrade、HTTP CONNECT、应用字节或 FSB3，也不得把 socket/transport 暴露给上层。Node.js 使用 `rejectUnauthorized:false` 只有在满足这个隔离边界时才允许；连接建立后再从已暴露 carrier 补查 hash 仍被禁止。任何 runtime 不具备上述任一安全路径时，对应 carrier 必须只声明 `ca`。

Raw QUIC 和 WebTransport 必须使用 v3 ALPN/path；WebSocket 必须使用 v3 path/subprotocol。TLS 层成功不代表 admission 或 Flowersec handshake 成功。

## 10. 错误、重试和 Controller

### 10.1 三层错误模型

FSA3、内部 transport failure 和公共 SDK error 是三个不同命名空间。

内部 transport registry 固定为：

| 内部 code | detail | 触发条件 | 默认 disposition |
| --- | --- | --- | --- |
| `invalid_artifact` | 无 | schema、未知算法、hash 编码、排序或 binding 输入无效 | 当前 connect terminal |
| `expired_artifact` | 无 | initiation 在 race 前、无 winner race 结束后、spend 前或 FSB3 前达到排他过期时刻 | 获取新的 primary artifact |
| `tls_unsupported` | 无 | runtime/tuple 不支持 mode，或浏览器同步拒绝 pin 参数 | 跳过 candidate |
| `tls_policy_expired` | 无 | attempt 开始时 active pin 为空 | 进入一次受限 artifact refresh |
| `tls_failed` | `ca_untrusted` | verifier 能证明 CA 链、hostname 或有效期不可信 | candidate terminal |
| `tls_failed` | `pin_mismatch` | 可观察 leaf 的静态 certificate profile 有效，但 DER hash 不匹配 active pins | 进入一次受限 artifact refresh |
| `tls_failed` | `unknown` | 原生 verifier 已把失败定位在 TLS 内但无法进一步区分，静态 profile 无效，或 hash 匹配后 TLS proof 失败 | candidate terminal；pin mode 可进入一次受限 refresh |
| `connection_failed` | `browser_pin_opaque` | browser pin WebTransport 的不透明 `ready` rejection | ordinary `connection_failed / retryable`；触发一次 policy-sensitive replacement |

“未知 hash”有两种不同情况：artifact 使用未知 hash 算法时是 `invalid_artifact`；服务器证书 hash 不在 active pin 集合中是 pin 验证失败，可观察并静态验证 leaf 的原生 adapter 报 `tls_failed + pin_mismatch`，已定位 TLS 但无法观察或完成静态分类的原生 verifier 报 `tls_failed + unknown`。Browser WebTransport 的不透明 `ready` rejection 不属于已定位的 TLS failure，按普通连接失败处理。不能把这些情况误写成未知算法或隐式 CA fallback。

Pin adapter 在取得 leaf 后先检查 X.509 语法、当前有效期、总有效期和 SPKI curve；这些静态检查通过而 DER hash 不匹配时可以报告 `pin_mismatch`，不要求 CertificateVerify/Finished 已先执行。hash 匹配后仍必须完成全部 TLS proof；后续 proof 失败报告 `unknown`。原生 provider 若已把失败定位在 TLS，但在 adapter 可取得并静态验证 leaf 前失败，只能报告 `unknown`。浏览器不能读取 leaf，也不能把不透明建连失败定位在 TLS；Browser WebTransport 和 Browser WebSocket 的此类失败均按 9.1 作为 ordinary transport failure。原生 `pin_mismatch` 与 `unknown` 只是受控 telemetry detail，不是跨 runtime 互操作承诺；二者在 pin mode 都是相同的 refresh trigger，并投影为同一个公共错误。

公共 SDK 只暴露稳定、脱敏的 `artifact_invalid`、`expired_artifact`、`transport_security_unsupported`、`transport_security_failed` 和既有 `connection_failed` 分类。公共 `RetryDisposition` 是三态代数类型：`terminal`、`retryable`、`retry_after(absolute_unix_ms)`；`retry_after` 是带绝对 not-before deadline 的 retryable 变体。`absolute_unix_ms` 必须是 JSON/语言层均可精确往返的十进制整数，值域为 `0..253402300799999`（含两端，对应 Unix epoch 至 `9999-12-31T23:59:59.999Z`）；禁止负数、小数、字符串、NaN、Infinity、超出值域或需要平台时间 API 舍入/截断的值。接受边界不得把秒误作毫秒，也不得把亚毫秒时间静默取整。

所有产生或接收公共 disposition 的 SDK 边界都必须先验证该值。特别地，`ArtifactSourceError` 携带非法 `retry_after` 属于 source contract violation，必须投影为 `artifact_invalid / terminal`，不得进入 scheduler、不得保留非法 deadline；内部 adapter 产生非法值同样按实现 contract violation fail closed。聚合多个合法 `retry_after` 时直接对整数取最大值。scheduler 以 `wall_now_ms = floor(Unix wall time in milliseconds)` 比较整数 deadline；等待时用饱和整数计算 `max(0, absolute_unix_ms - wall_now_ms)`，单次 timer 最长仍受 10.4 的 1000ms wall-clock 重读规则限制，不得依赖无法精确表示该 deadline 的平台日期对象。`retry_after(0)` 合法但不能缩短 monotonic backoff。`expired_artifact` 的默认 disposition 是 `retryable`。公共错误不得包含 URL、pin、服务器证书、原生 TLS 文本、credential、lease ID 或 FSA3 私有 reason。内部 detail 可以进入受控 telemetry，但不能由无法证明细节的 runtime 猜测。

### 10.2 Candidate 级处理

- `tls_unsupported` 只跳过当前 candidate；其他受 artifact 授权且 capability 匹配的 endpoint 可以继续；
- CA candidate 失败不得改成 pin，pin candidate 失败不得改成 CA；
- 同一 artifact 中不同 endpoint 的 CA/pin 竞速是显式授权，不是 fallback；
- candidate race 有 winner 时立即取消并关闭其他 attempt；取消不得覆盖 winner 的结果；
- 所有 candidate 都失败后，Controller 才决定是否进入 artifact refresh。
- 所有 candidate 都失败后必须先执行 5.1 的 race-end wall-clock expiry 检查；该检查优先于失败聚合和 policy-refresh trigger，primary A 与 replacement B 均不得跳过。

多 candidate 的最终结果必须与并发完成顺序无关，并按以下优先级归并：

1. artifact 在 race 前或服务端重验证时无效：`artifact_invalid / terminal`；
2. artifact initiation 已过期：`expired_artifact / retryable`，retire pre-spend lease 并进入普通 primary acquisition，不触发 policy refresh；
3. 存在 10.3 定义的 policy-refresh trigger 且 replacement lease 配额未使用：先执行 10.3，不立即暴露公共错误；
4. 不存在可执行的 policy refresh（包括 replacement 配额已耗尽、replacement 无效、同 endpoint policy 未变或 pin→CA）时，若存在 `tls_failed` 或 `tls_policy_expired` 产生的 security trigger，返回 `transport_security_failed / terminal`；
5. 不存在可执行的 policy refresh 时，若只有 `browser_pin_opaque` trigger，返回 `connection_failed / terminal`，不得改写为 TLS 安全错误；
6. artifact 声明的所有 candidate 都是 `tls_unsupported`：`transport_security_unsupported / terminal`；
7. 没有 TLS failure 或 policy-refresh trigger，但存在既有普通 transport failure：`connection_failed`，沿用该失败的既有 disposition；
8. 其余没有 winner 的情况：`connection_failed / terminal`。

同一优先级内不得使用第一个或最后一个完成的 candidate 选择公共错误。普通 transport failure 有多个 disposition 时按下列全序聚合：存在 `retry_after` 就返回最晚的 absolute deadline；否则存在 `retryable` 就返回 `retryable`；否则返回 `terminal`。candidate 完成顺序不参与计算。

### 10.3 Pin policy refresh 状态机

一个 connection cycle 在初次 `Start` 或已建立 Session 终止并决定重连时开始，到下一次 Session 建立或 Controller terminal 结束。cycle 内普通可重试失败可以获取多个 primary artifact，但最多取得一个 policy-sensitive replacement lease；该配额跨普通重试持续保留：

```text
acquire and claim primary artifact A_i / lease A_i
  -> validate and race eligible candidates
  -> TLS winner: commitSpend starts; lease becomes consumed
       admission and session success: established Session
       post-spend terminal failure: cycle terminal
       post-spend retryable/retry_after:
         wait under 10.4, acquire next primary A_(i+1)
         replacement-used flag is unchanged
  -> no TLS winner: retire A_i, aggregate pre-spend failures
       no policy-refresh trigger + terminal: cycle terminal
       no policy-refresh trigger + retryable/retry_after:
         wait under 10.4, acquire next primary A_(i+1)
       policy-refresh trigger + replacement lease not yet obtained:
         immediately start the first B acquisition; retry source failures under 10.4
         acquire until replacement artifact B / lease B is obtained
         claim B; replacement-used becomes true
         B expired before its race:
           retire B; expose expired_artifact/retryable
           wait under 10.4, acquire next primary A_(i+1)
           replacement-used remains true
         otherwise validate B and compare triggered endpoint policies
         no changed pin policy: retire B; cycle terminal
         changed pin policy: race B's precisely eligible candidates once
           no TLS winner and B now expired:
             retire B; expose expired_artifact/retryable
             wait under 10.4, acquire next primary A_(i+1)
             replacement-used remains true
           no TLS winner and B not expired: retire B; cycle terminal
           TLS winner: commitSpend starts; B becomes consumed
             admission and session success: established Session
             post-spend terminal failure: cycle terminal
             post-spend retryable/retry_after:
               wait under 10.4, acquire next primary A_(i+1)
               replacement-used remains true
       policy-refresh trigger + replacement lease already obtained: cycle terminal
```

只有 pre-spend、没有 TLS winner 的 claimed lease 才能 retire。`commitSpend` 一旦开始，该 lease 必须 consumed；后续 FSA3 reject/retryable、FSH3 或 session establishment failure 不得调用 retire。primary 和 replacement 的 post-spend failure 都保留原公共 error code 和 disposition。post-spend retry 可以进入下一次普通 primary acquisition，但已经取得过 replacement 的 cycle 不恢复 replacement 配额；后续再次出现 policy-refresh trigger 时 terminal，不能取得第二个 replacement。

policy-refresh trigger 是 pin candidate 的下列任一结果：`tls_policy_expired`；原生 verifier 已定位 TLS 后报告的 `tls_failed + pin_mismatch` / `tls_failed + unknown`；或 browser pin candidate 的 `connection_failed + browser_pin_opaque`。前两类为 security trigger，最后一类为 opaque trigger，公开命名空间和最终错误投影不同。定义：

```text
T = A 中产生 policy-refresh trigger 的 endpoint key 集合
F = A 中所有已失败或已跳过的 endpoint key 集合

changed_pin(k) =
  k in T
  and B[k] exists
  and B[k].tls.mode == "pin"
  and tls_policy_digest(B[k].tls) != tls_policy_digest(A[k].tls)
```

每个 `k in T` 在触发时都把 `(k, tls_policy_digest(A[k].tls))` 加入当前 cycle 的不可删除 `blocked_pin_policy` 集合。后续任何 primary 或 replacement artifact 在 candidate race 前都必须过滤：同 endpoint 的 CA candidate、以及 digest 在该集合中的 pin candidate 均不可执行；只有同 endpoint、未被阻塞且与触发 digest 不同的 pin policy 可以继续。这个过滤在 B race 前、B 因过期回到 primary 后、以及 replacement 配额耗尽后的所有普通 primary acquisition 都生效。它不限制不同 endpoint key 的显式 CA 或 pin candidate，也不限制未触发 endpoint 的既有正常重试。

B 只有在至少存在一个 `changed_pin(k)` 时才是有效 replacement。B race 的精确候选集合是：

```text
E = { B[k] | changed_pin(k) }
  union { B[k] | k not in A }
  union { B[k] | k in A and k not in F }
```

从 E 中再按 B acquisition 前生成的最新 immutable capability snapshot 和 `blocked_pin_policy` 过滤。A 中已失败且 policy 未变的 endpoint、B 中同 endpoint 的 pin→CA candidate，以及不在 E 中的 candidate 必须跳过。E 过滤后为空时 retire B 并按 trigger provenance terminal。不同 endpoint key 的新 CA candidate 可以进入 E，因为它由新 artifact 显式授权；同 endpoint pin→CA 永远不能进入。

`tls_policy_digest` 比较完整 declared policy，而不是 active subset。改变 pin 顺序不能制造变化，因为非 canonical 顺序已在解码时拒绝。

ArtifactSource acquisition failure 可以按其 disposition 重试，并执行 10.4 的统一 attempt、backoff 和终止规则。尚未取得 B 时不消耗 replacement-lease 配额；成功取得并 claim B 时立即耗尽该配额。B 无效、policy 未变、candidate 集合为空或非过期的 pre-spend 连接失败后不得取得第二个 replacement；只有上一段定义的 post-spend retryable/retry_after，以及 5.1 明确定义的 B pre-spend/race-end expiry，可以回到普通 primary acquisition。两种路径都保留 `replacement-used=true` 和 `blocked_pin_policy`，后续 policy-refresh trigger terminal。取得 B 前遇到 terminal source failure、cancellation 或 attempt budget exhaustion 时，沿用最后一个 artifact-source 公共失败并结束 cycle，而不是改写成 TLS 错误。

刷新仍受 10.4 的 cancellation、`retryNow`、absolute retry-after、deterministic backoff 和 `maximumAttempts` 约束。本节的一个 replacement lease 是更严格的附加上限。Controller 不迁移旧 Session，不重放 RPC/stream，也不因已建立 Session 的 pin 过期而主动断开。

### 10.4 Controller 调度与尝试预算

Controller 只有一个 scheduler，同一时刻最多一个 `ArtifactSource.Acquire` 或一个 connector attempt 在执行。`Start` 幂等，`Close` 的 cancellation 优先于 timer、`retryNow` 和新 acquisition；关闭后不得再启动。`maximumAttempts` 是 `0..9007199254740991` 的整数，`0` 表示无 acquisition 次数上限。attempt counter 属于当前 connection cycle：cycle 开始时为 0，Session 建立时该 cycle 结束并清零；该 Session 后续终止并决定重连时，新 cycle 以 counter 0 开始，第一次 `Acquire` 计为 1。规则如下：

- 每次调用 `Acquire` 前先检查 counter：若 `maximumAttempts != 0` 且 `counter >= maximumAttempts`，不得调用；否则以饱和整数将 counter 增加 1 后调用。counter 在 `9007199254740991` 饱和，不能回绕。primary、寻找 B 时的 source failure、成功返回 A/B lease 的调用都使用同一 cycle counter；
- 一个 source failure 只增加一次 `consecutive_failures`；每个已取得并 claim 的 lease，只要没有建立 Session，就在该 lease 的唯一最终结果处恰好增加一次，无论失败发生在 artifact/race 前校验、race-end expiry、candidate 聚合、`commitSpend` 前/后 expiry、admission 或 session establishment。单个 candidate failure、race loser cancellation 和同一 lease 上的多次检查不单独计数；成功 `Acquire` 不重置该值。`Close`、调用方 cancellation 和已建立 winner 导致的取消不计 failure。A 产生 policy-refresh trigger 时，先记入 A 的一次 failure，再立即寻找 B 而不等待 A 的 backoff；B race 前或 race-end expiry 同样记一次，随后按其 ordinal 等待并进入允许的 primary acquisition；
- Session 建立时 `consecutive_failures` 和 attempt counter 都清零并结束当前 cycle；该 Session 随后以 retryable/retry_after 终止时，新 cycle 以 failure ordinal 1 开始并先等待，等待后以 counter 0 执行该 cycle 的首次 acquisition；
- 第 `n` 个 consecutive failure 的 backoff 为 `min(250 * 2^(n-1), 30000)` 毫秒，jitter 固定为 0；计算必须使用饱和整数，不能溢出；
- artifact/initiation expiry、pin/证书绝对时间和 `absolute_unix_ms` 使用可信 wall clock；backoff 使用 monotonic clock。失败发生时固定 `backoff_start_mono` 和 `backoff_deadline_mono = backoff_start_mono + backoff`；retryable 必须等到该 monotonic deadline，retry_after 必须同时满足 monotonic deadline 和 `wall_now_ms >= absolute_unix_ms`。过去的 absolute deadline 不能缩短 backoff；
- wall clock 回拨只会延后尚未满足的 absolute retry-after，不得改变 monotonic backoff；wall clock 前跳可以满足 absolute deadline，但不能跳过 monotonic backoff。实现等待 absolute deadline 时必须至少每 1000ms monotonic 时间重新读取 wall clock，剩余 wall 时间更短时使用更短等待；任何 wake 后都重新检查两个条件，不能把 wall deadline 一次性转换成不再校正的 monotonic deadline；
- cancellation 立即结束等待；`retryNow` 只能唤醒当前既有 wait，不能创建第二个 scheduler。它可以跳过剩余 backoff，但不能越过未来的 `absolute_unix_ms`；不在 waiting、`absolute_unix_ms` 尚未到或 Controller 已 terminal/closed 时返回 `false`；
- A 出现 policy-refresh trigger 后先 retire A；若 attempt budget 允许，第一次 B acquisition 立即开始，不等待该 A failure 的 backoff。寻找 B 时若 source 返回 retryable/retry_after，该 source failure 计数一次，等待后继续寻找 B，而不是切回 primary；
- 普通 primary failure 和 10.3 明确允许的 post-spend failure 在等待后获取下一份 primary；B 已取得后的无效、policy 未变、empty eligible set 或 pre-spend failure 直接 terminal；
- 失败发生时若已经用完 `maximumAttempts`，Controller 保留最后 failure 的脱敏公共 code 和 phase，但把对外有效 disposition 强制改为 `terminal`，清除 retry-after deadline，进入 `failed`；原 disposition 只能进入受控 telemetry，`retryNow` 返回 `false`。

v3 Controller vectors 必须把上述 cycle counter/reset/饱和、failure ordinal、立即 B acquisition、B source retry、wall/monotonic deadline 组合、wall-clock 前跳与回拨、attempt exhaustion 和 cancellation 的状态/时间逐项冻结，不能只断言最终进入 `failed`。

### 10.5 Lease v3 状态机

v3 的 ArtifactLease 必须具有跨对象副本共享、原子且不可逆的内部状态：

```text
idle -> claimed -> spending -> consumed
                  -> retired
```

- `ArtifactLease.claim()` 是唯一的共享原子 claim 操作；成功时执行 `idle -> claimed` 并返回 SDK-internal、不可伪造的 `ClaimedArtifactLease` ownership token，同一 `lease_identity` 只能成功一次；各语言即使复制 wrapper，也必须共享同一原子状态，不能获得第二次 spend 权限；
- 公共 one-shot `connect(ArtifactLease)` 必须在入口调用 `claim()`；Controller 必须在每次 `Acquire` 成功返回 idle lease 后立即调用 `claim()`，然后把 `ClaimedArtifactLease` 交给内部 connector；ArtifactSource 在准备向 Controller 正常交付 lease 时不得预先 claim，唯一例外是下述 cancellation-first source-side cleanup；
- `commitSpend` 只存在于 `ClaimedArtifactLease`，原子执行 `claimed -> spending`；durable spend 成功、失败、取消或结果未知后都必须进入 `consumed`；
- `retire` 只存在于 `ClaimedArtifactLease`，原子执行 `claimed -> retired`，且必须在 owner 放弃当前 lease 时执行；
- `retired` 后的 `commitSpend`、再次 claim 或直接 connector 使用必须失败；
- `consumed` 和 `retired` 都是终态，不得回到 `idle` 或 `claimed`；
- retire cleanup callback 可以为空；存在时最多调用一次，cleanup 失败或取消只被脱敏记录，不得恢复 lease；
- ArtifactSource 不得再次返回已经出现过的 `lease_identity`；
- ClaimedArtifactLease owner 在离开当前 attempt/cycle 所有权前必须使其进入 `consumed` 或 `retired`，没有第三种结果；artifact 校验、capability 过滤、TLS、取消或 cleanup 在 spend 前失败时都必须 retire。

`ArtifactSource.Acquire` 的结果是严格互斥的代数类型：一次调用只能返回一个 idle lease 或一个 `ArtifactSourceError`，不能同时携带两者。lease ownership 在结果交付给 Controller 的线性化点之前属于 source，之后属于 Controller。cancellation 与交付竞态必须按同一个原子线性化点处理：

- cancellation 先发生时，source 保留 ownership，必须使其随后取得或生成的 lease 不对 Controller 可见；source-side wrapper 必须调用与 Controller 完全相同的共享原子 `claim()`，取得 SDK-internal token 后立即 `retire()`，形成唯一合法的 `idle -> claimed -> retired` cleanup 路径，再以 cancellation error 结束调用。该例外不能把 token 或 lease 交付给应用/Controller，也不能调用 `commitSpend`；
- 交付先发生时，Controller 即使紧接着观察到 cancellation，也必须 claim 该 lease 并立即 retire，不得把 idle lease 丢弃；
- 无法在语言 runtime 中原子取消 future/promise 的 wrapper 必须 drain 晚到结果；若 cancellation 在线性化点先发生，晚到 lease 由 source-side wrapper 按上一条内部 claim+retire；若交付先发生则由 Controller claim+retire；晚到 error 只作脱敏记录；
- `Close` 可以立即发布 `closed` 并禁止新工作，但其异步完成必须等待 in-flight Acquire 按上述规则 settle、以及必要的 retire cleanup 完成；ArtifactSource 必须响应 cancellation，不能让 Close 无限悬挂；
- source 违反互斥结果或 ownership 规则属于 SDK/source contract violation，公开投影为 `artifact_invalid / terminal`，且不能进入 connector。

one-shot claim 失败和 Controller acquisition 后 claim loser 都映射为公开 `artifact_invalid / terminal`，且不得调用 connector。`reused_artifact_lease` 只能作为受控内部 telemetry detail，不能成为公共 code。跨语言 public API 必须隐藏 ownership token 的构造器；TypeScript/Swift 也必须用私有 capability token 和共享状态执行同一原子约束，不能只依赖对象引用相等。

TLS 尚未成功时不得谎报 durable-spent，但无 winner 时仍必须 retire。若 durable spend 已开始，lease 无论结果如何都按 one-shot 规则永久 consumed。

## 11. Control plane API

v3 不接受只有 URL 的 `NewEndpointSet(urls ...string)`。Go 签发侧使用以下 typed API；`TLSPolicy` 的 tag 和字段保持私有，使调用方无法构造有效的未知 mode、字符串 hash 或空 pin policy。Go 公开类型不可避免存在零值，`TLSPolicy{}` 零值被定义为无效，而不是隐式 CA：

```go
type EndpointConfig struct {
    ID  string
    URL string
    TLS TLSPolicy
}

func CAPolicy() TLSPolicy

type CertificatePin struct {
    SHA256   [32]byte
    NotAfter time.Time
}

func PinPolicy(pins ...CertificatePin) (TLSPolicy, error)
func NewEndpointSet(configs ...EndpointConfig) (EndpointSet, error)

type ControlPlaneErrorCode string

const (
    InvalidEndpointCount ControlPlaneErrorCode = "invalid_endpoint_count"
    InvalidEndpointID    ControlPlaneErrorCode = "invalid_endpoint_id"
    InvalidEndpointURL   ControlPlaneErrorCode = "invalid_endpoint_url"
    DuplicateEndpoint    ControlPlaneErrorCode = "duplicate_endpoint"
    InvalidTLSPolicy     ControlPlaneErrorCode = "invalid_tls_policy"
    InvalidPin           ControlPlaneErrorCode = "invalid_pin"
)

type ControlPlaneError struct { /* private fields */ }
func (e *ControlPlaneError) Error() string
func (e *ControlPlaneError) Code() ControlPlaneErrorCode
func (e *ControlPlaneError) FieldPath() string
func (e *ControlPlaneError) Unwrap() error

var ErrIssuanceFailed error
var ErrInvalidControlPlaneInput error
```

`id` 使用 candidate ID 的同一约束，并由部署配置显式、稳定地提供，不能根据数组位置或同类 carrier 的计数生成。scheme 到 carrier 的映射固定为：`wss -> websocket`、`quic -> raw_quic`、`https -> webtransport`。其他 scheme 无效。

`PinPolicy` 必须把 `NotAfter` 无损转换为 UTC 整数 Unix 秒，把 SHA256 编码为 canonical `value_b64u`，并按 `value_b64u` 的 ASCII 字节字典序生成内部 pin 集合；不得按原始 SHA256 字节排序。含亚秒、转换后不在 `1..9007199254740991`、重复 hash、空集合或超过 4 项时返回错误。`SHA256` 在 typed API 中始终是 32 字节；base64url 只存在于内部 canonicalization 和 wire codec，不是 issuer API 输入。`TLSPolicy`、`CertificatePin` 和 `EndpointSet` 的 debug/string 输出必须脱敏。

`NewEndpointSet(configs ...EndpointConfig)` 只执行可脱离签发时钟和 path 的结构校验：

- 数量必须为 `1..4`；`0` 或大于 `4` 返回 `invalid_endpoint_count`，且 `FieldPath()` 恰好为 `endpoints`；
- 校验 ID 唯一、URL scheme、TLS policy 和 pin 时间字段；
- 以 `invalid_tls_policy` 和 `endpoints[<index>].tls` 拒绝 `TLSPolicy` 零值、未知内部 tag 或任何不能由 `CAPolicy` / `PinPolicy` 产生的状态；
- 要求调用方把轮换 pins 合并在一个 policy 中；
- 保存不可变的结构化 endpoint，不根据构造时钟判断 pin 是否 active；
- 不连接 endpoint、不抓取证书、不计算 pin、不修改 trust roots。

每次 `IssueDirect` 或 `IssueTunnelPair` 必须从 issuer 的可注入 clock 读取一次 `issuance_now` 并固定到操作结束，然后针对目标 path 重新执行完整 endpoint 校验：再次拒绝零值 EndpointSet、数量为 `0` 或大于 `4`、零值/未知 TLS policy，校验固定 URL path、normalization、endpoint key 去重、CA/pin 冲突、wire profile、candidate canonicalization，并要求每个 pin policy 至少有一个 `issuance_now < not_after_unix_s` 的 pin。EndpointSet 数量错误继续使用 `invalid_endpoint_count` / `endpoints`；预先构造或复用 EndpointSet 不得绕过这次签发时校验。

`ControlPlaneError` 只描述 `PinPolicy`、`NewEndpointSet` 和 issuer 的 endpoint/TLS 重校验错误；它必须可由 `errors.As` 取得，并 `Unwrap()` 到公开 sentinel `ErrInvalidControlPlaneInput`。其 code 只能是 `invalid_endpoint_count`、`invalid_endpoint_id`、`invalid_endpoint_url`、`duplicate_endpoint`、`invalid_tls_policy`、`invalid_pin`。`Error()` 对所有这类输入错误固定返回 `flowersec control-plane input is invalid`，稳定细节只能通过 `Code()` 和 `FieldPath()` 取得。`PinPolicy` 的字段路径只能是 `pins`、`pins[<index>]`、`pins[<index>].sha256` 或 `pins[<index>].not_after`。`NewEndpointSet` 和 issuer 必须把 endpoint 相关错误定位为 `endpoints`，或 `endpoints[<index>]` 加 `.id`、`.url`、`.tls` 或 `.tls.pins[<index>].not_after`；issuer 发现全 policy 已过期时使用 `invalid_tls_policy` 和 `endpoints[<index>].tls`。错误不得回显 URL、pin、证书、credential 或原生解析文本。

`IssueDirect` / `IssueTunnelPair` 的 session contract、correlation、metadata、rendezvous、listener audience、upstream 或其他非 endpoint 输入无效时，必须直接返回 `ErrInvalidControlPlaneInput`，不得伪造 `ControlPlaneError`、endpoint code 或 field path。该 sentinel 的 `Error()` 文本固定为 `flowersec control-plane input is invalid`；它只表达脱敏输入无效，不携带不稳定字段信息。随机源、熵源、clock/provider 故障或其他非输入签发失败不属于此类错误。

随机源、熵源或其他非输入的签发失败必须返回独立的 `ErrIssuanceFailed`，其文本固定为 `flowersec artifact issuance failed`，不得伪装成带 field path 的 `ControlPlaneError`。`ControlPlaneError`、`ControlPlaneErrorCode`、六个 code 常量、`Error`/`Code`/`FieldPath`/`Unwrap` accessor、`ErrInvalidControlPlaneInput` 和 `ErrIssuanceFailed` 都必须进入 v3 public API manifest；不得只在实现内部暴露字符串。

v3 首版只在 Go control-plane package 提供 artifact issuer 和结构化 `NewEndpointSet`。TypeScript、Rust、Swift v3 SDK 只消费签发后的 artifact，不提供 v3 issuer API；这不影响四种语言的 artifact、FSB3 和 session codec 互操作。若以后增加其他语言 issuer，必须复用同一 registry 和 vectors，不能定义语言私有 schema。

## 12. 实施和发布规划

### 12.1 Contract freeze

1. 新增 `stability/transport_v3_contract.json`，登记本文的仓库内英文规范、全部字段、registry、limits、domain labels 和 vectors；
2. 生成 v3 artifact、URL/IDNA、capability、Controller、FSB3/FSA3、handshake、crypto、session wire、DATAGRAM、Unicode 和 invalid-input vectors；
3. stability checker 必须扫描 v3 实现，防止 v3 路径残留 v2 magic、profile、path 或密码学 label；
4. registry 必须把第 5 节全部 scalar/URL 规则、第 8 节 tuple universe 和第 10.4 节调度常量登记为 machine-readable contract，不得只列样例；
5. registry 和 vectors 冻结后才开始公共 API 实现。

### 12.2 Codec 和核心状态机

1. 在 TypeScript、Go、Rust、Swift 实现 JCS、artifact v3、candidate/TLS policy、FSB3/FSA3；
2. 实现完整 `FSC3/FSH3/FSS3/FSR3/FSD3` 和新的域标签；
3. 更新 acceptor、tunnel authorization 和 admission binding 校验；
4. 实现 capability schema v3 和 digest；
5. 保持 v2 代码路径物理隔离，禁止共享带版本域标签的 helper。

### 12.3 Adapter 和 Controller

1. Go control plane 改为结构化 endpoint 配置；
2. 实现统一 `TransportSecurityPolicy` 和各 runtime verifier；
3. 浏览器 WebTransport 接入真实 constructor options；
4. 为 browser/runtime 建立精确 capability registry；
5. 实现 active pin snapshot、错误映射、lease retirement 和一次 refresh 状态机。

### 12.4 SDK major 与部署

- Go module 使用 `/v3`；
- TypeScript package、Rust crate 和 Swift package/tag 发布 v3 major；
- v3 使用独立 server path、WebSocket subprotocol 和 QUIC ALPN；
- v2 artifact 不能传给 v3 API，v3 artifact 不能传给 v2 API；
- 需要并行迁移时由部署方同时运行独立 v2/v3 listeners，并由上层显式选择 SDK major；
- 不提供 v2 到 v3 的运行时自动升级或降级。

## 13. 验证与实现接受门槛

v3 功能分支进入 main、声明 capability 和形成可发布版本前，必须在相应的 precommit、CI 或显式工程工作流中全部通过以下接受门槛。

### 13.1 跨语言 vectors

TypeScript、Go、Rust、Swift 对每个 vector 必须逐字节一致，至少覆盖：

- CA、单 pin、双 pin、四 pin candidate；
- session/path/correlation 每个 scalar 的字符集、最小值、最大值、固定值和 cross-field 约束；
- pin 顺序、重复、未知算法、非法 base64url 和整数边界；
- `scoped.payload` 的 signed safe-integer、Unicode key、array 保序、depth/node/member/string/byte 边界；
- 单 pin 过期、部分过期、全部过期和等于过期时刻；
- initiation 在 race 前、primary/replacement 无 winner race 结束后、spend 前、spend 后/FSB3 前和 server admission 时过期；
- URL normalization 的 UTS #46、Unicode 15.1 delta、IPv4/IPv6、默认/非默认端口和每个拒绝分支，以及 endpoint 重复和同 endpoint CA/pin 冲突；
- candidate、candidate set、TLS policy、session contract 和 capability digest；
- capability 的全部 runtime identity、封闭 tuple universe、carrier partition、reason token、boolean/path/role 非法组合；
- `retry_after` 的 `0`、`253402300799999`、过去/未来值、多个 deadline 取最大值，以及负数、小数、字符串、NaN、Infinity、`253402300800000`、亚毫秒平台时间和无法精确往返值的拒绝与 `artifact_invalid / terminal` 投影；
- raw SHA256 byte order 与 canonical base64url ASCII order 相反的双 pin、四 pin，以及 Go issuer 到四语言 decoder 的 round-trip；
- direct/tunnel FSB3 的逐字段 artifact projection、role 解释、cross-variant 拒绝、FSA3 和 admission binding；
- 单 candidate 与多 candidate 的 acceptor admissions hash；
- 所有 `FS*3` frame、transcript、KDF、MAC、AAD、rekey 和 unreliable message；
- v2/v3 magic、profile、path、ALPN 和 label 交叉拒绝；
- unknown/missing field、duplicate key、非 JCS、非法 UTF-8、边界和尾随字节；
- FSH3/OPEN/RPC 继承 codec 不被错误套用 artifact JCS rejection 的交叉案例。

### 13.2 真实 TLS 和浏览器测试

测试必须使用真实 TLS handshake 和生产 adapter，不能只 monkey-patch `WebTransport` 并断言 constructor 参数：

- 公共 CA；
- 预安装私有 CA；
- 自签名 ECDSA P-256 pin；
- 满足短期 profile 的 CA 签发 ECDSA P-256 leaf 配正确 pin；pin mode 不使用其 chain trust；
- 旧证书、新证书和双 pin 重叠；
- 错误 pin、过期 pin、尚未生效证书、已过期证书和总有效期超过 1209600 秒的证书；
- 受公共 CA 信任的证书配错误 pin 必须失败，以证明 pin 参数没有被静默忽略；
- 对每条原生 verifier/provider 路径，peer 呈现正确 pinned DER 但使用错误私钥或损坏 CertificateVerify 时，必须在 carrier 暴露、durable spend 和 FSB3 前失败；
- 对每条原生 verifier/provider 路径，非 P-256、有效期过长、非当前有效和无效 TLS proof 必须映射为 `tls_failed + unknown`；静态 certificate profile 有效但 hash 不匹配的 provider 可以映射为 `pin_mismatch`，provider 在 leaf 可检查前失败时映射为 `unknown`；两者公共结果和 refresh 行为相同。浏览器只验证 WebTransport 标准约束和 6.3 已声明的部署 profile 边界，不得把无法观察的非 P-256 情况伪装为该 TLS 分类；
- CA mode 不传 `serverCertificateHashes`；pin mode 只传 active pins；
- 浏览器 WebSocket 跳过 pin；不支持 hashes 的 WebTransport 报 `tls_unsupported`；
- Browser WebTransport CA mode 的不透明 DNS/QUIC/CONNECT/Origin/path/TLS `ready` rejection，以及 Browser WebSocket 的构造/open 前不透明失败，必须保持 ordinary `connection_failed / retryable`，不能变成 `transport_security_failed` 或 policy-refresh trigger；Browser WebTransport pin mode 的同类不透明 rejection 必须保持相同公共 `connection_failed / retryable`，但带 `browser_pin_opaque` marker 并执行一次 10.3 replacement；
- browser registry 必须覆盖精确 Chromium `151.0.7922.34`、未匹配版本/缺少 UA-CH 的 CA-only descriptor、同步 `NotSupportedError` 的 `enabled -> ca_only` 线性化、旧 snapshot live gate、registry 重建后重新识别，以及公共 CA 证书配错误 pin 必须失败的真实 production-adapter 测试；
- pin mismatch、policy expired 和 unknown TLS failure 都不降级 CA；
- v3 server 只接受 TLS 1.3、拒绝 0-RTT，并禁用 resumption；
- dedicated WebTransport connection 未 pooling；
- TLS 失败发生在 durable spend 和 FSB3 之前。

与固定 `@playwright/test 1.62.1` 对应的 Chromium `151.0.7922.34` 是 pin WebTransport 的首个必需浏览器；测试和 machine-readable registry 必须固定并核验该完整版本，不能让默认 browser job 静默降为 CA-only 或跳过 pin。Firefox 和 WebKit 必须执行 capability/unsupported 测试；只有进入受支持 browser/version registry 后才成为 pin 互操作必需项。

### 13.3 Controller 和安全不变量

模型测试、故障注入和并发测试必须证明：

- 一个 connection cycle 最多取得一个 policy-sensitive replacement lease；
- 相同 TLS policy 不会被无限重试；
- policy 变化使用 fresh artifact 和 fresh lease；
- 未 spend 但已 retire 的 lease 不会复用；
- spend 结果未知的 lease 永远不会复用；
- race loser 被关闭且不能写 FSB3；
- 不支持 candidate 被跳过而不创建 transport；
- 一个 endpoint 不能通过重复 candidate 获得 CA 降级路径；
- 已建立 Session 不因 pin policy 到时而中断；
- cancellation、retry-after、backoff 和最大尝试数继续生效。

调度 vectors 必须逐项证明：每个 source/聚合 connector failure 的 `consecutive_failures` 计数、candidate failure 不重复计数、每个已取得 lease 的 race 前/race-end/spend 前/后过期恰好计一次、A policy-refresh 后立即首次获取 B、B 过期后的 failure ordinal/backoff、成功 Acquire 不重置、Session 建立同时重置 failure/cycle attempt counter、Session termination 从 ordinal 1 和 cycle counter 0 开始、`250ms * 2^(n-1)` 的 30 秒 cap、monotonic backoff 与合法 `absolute_unix_ms` 的双条件、wall clock 前跳/回拨、最多 1000ms monotonic 间隔的 wall-clock 重读、timer 差值饱和、`retryNow` 只能跳过 backoff，以及 attempt exhaustion 强制输出 terminal disposition。非法 `ArtifactSourceError.retry_after` 必须在 scheduler 前变成 `artifact_invalid / terminal`，且不创建 timer。

Controller vectors 还必须覆盖：单 CA `ca_untrusted`、CA TLS failure 与普通 transport failure 混合、多个 trigger endpoint、B 中同 endpoint pin→CA、B acquisition 的 retryable 结果、B 在 race 前和无 winner race-end 过期后回到 primary且 replacement 配额不恢复、retire cleanup 失败、TLS/unsupported/普通网络失败混合，以及同一结果集合的并发完成顺序置换。还必须覆盖 browser `browser_pin_opaque` 的一次 replacement、同 endpoint changed pin 成功、同 endpoint CA/same digest 被过滤、B 或后续 primary 不能重试旧 digest、opaque trigger 耗尽后返回 `connection_failed / terminal`、普通 retry 后才触发 policy refresh、replacement 配额跨普通 retry保留、每次 A/B/source-failure acquisition 的 `maximumAttempts` 精确计数与 safe-integer 饱和、one-shot 与 Controller 对同一 lease 的并发 claim、claim loser 的公开 `artifact_invalid`、cancellation-first source-side `idle -> claimed -> retired`、delivery-first Controller retirement、Close 等待 cleanup，以及两个并发 acquisition 与 replacement B 跨 capability invalidation 线性化点的 barrier test。

Primary 与 replacement 都必须测试 TLS winner 后 `commitSpend` 开始、随后 FSA3 reject/retryable 和 FSH3 failure 的路径：lease 必须 consumed 而非 retired；terminal 保留原错误，retryable/retry_after 进入普通 primary acquisition；replacement 配额不得恢复，后续 policy-refresh trigger 不得取得第二个 replacement。

Go issuer 测试必须使用注入 clock 覆盖 `NewEndpointSet` 的 0/5 endpoint、零值 EndpointSet 在 issuer 的 `invalid_endpoint_count / endpoints` 投影、EndpointSet 提前构造后在签发时全部 pin 已过期、等于过期时刻、`TLSPolicy{}` 零值、未知内部 tag、`ControlPlaneError` 六个 code/field path/`Unwrap`/固定文本脱敏、非 endpoint issuer 输入的 `ErrInvalidControlPlaneInput`、独立 `ErrIssuanceFailed`，以及 raw SHA256 到 base64url comparator 的反序案例。客户端时间测试通过内部 wall/monotonic clock 注入覆盖 `attempt_now == not_after_unix_s`、race-end expiry、wall-clock 前跳/回拨和 monotonic backoff 不受 wall clock 影响；clock 注入不进入公共 API 或 wire。

### 13.4 接受判定与 release 边界

只有以下条件同时满足，v3 实现才可进入可发布状态：

- machine-readable registry、英文仓库规范和本文语义一致；
- 四语言 codec/vectors 全部一致；
- 每个声明的 capability 都有真实 production adapter 测试；
- 公共 CA、私有 CA 和自签名 pin 环境均有端到端证据；
- v2/v3 隔离、无自动降级和 lease one-shot 不变量通过测试；
- 所有公共错误和 debug 输出通过脱敏测试；
- 支持矩阵中未实现的 cell 明确标为 unsupported，不以 skip 伪装通过。

这些测试不由 release 命令执行，也不产生供 release 消费的 evidence、receipt 或 test artifact。`scripts/release.sh` 严格遵守仓库规则，只做版本与 ref 校验、打包、release artifact 签名、发布和 registry readback；它不运行测试。测试结果必须在进入 release 阶段前由对应工程 gate 得出。

## 14. 明确不进入 v3 首版的内容

- 不把 pin 放入 URL，也不仿造 libp2p multiaddr；
- 不提供 TOFU、动态抓取 pin 或自动信任首次证书；
- 不提供 `pin-or-ca`、`prefer-pin` 或其他混合/降级模式；
- 不把 root certificate、完整 certificate chain 或私钥放入 artifact；
- 不把 pin 暴露到 Session、RPC、Stream 或业务 API；
- 不让 Flowersec 承担证书签发、CA 管理或部署编排；
- 不借 v3 重做 E2EE、RPC、stream、DATAGRAM 或应用层接口；
- 不在生产 artifact 中恢复明文 loopback；
- 不提供 v2/v3 wire negotiation 或失败后的自动 fallback。

## 15. 最终安全不变量

v3 的实现和后续修改必须保持以下不变量：

1. candidate 的 TLS mode 和完整 declared pins 是 admission-bound 数据；
2. 同一 endpoint 在一个 artifact 中只有一个 TLS policy；
3. pin 的信任依据只有 active leaf certificate hashes，不附带隐式 CA 路径；
4. CA mode 执行完整平台 PKI 验证，不附带隐式 pin 或 insecure verifier；
5. 不支持、过期和失败都不会触发 mode 降级；
6. TLS 失败不进入 FSA3 命名空间；
7. TLS 成功前不 durable-spend lease、不发送 credential；
8. 一个 lease 最多服务一次可能提交 credential 的尝试，retired lease 不复用；
9. 每个 connection cycle 最多取得一个 policy-sensitive replacement lease，相同旧 policy 不会循环；
10. v2 和 v3 的 magic、profile、path、ALPN、subprotocol、hash 与密码学域完全隔离。
