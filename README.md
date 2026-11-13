# h2audit — HTTP/2 首部采集审计器

从零实现的、仅依赖 Python 标准库的 HTTP/2 帧校验与 HPACK 解压工具。
输入为**单连接、单方向、已去除连接前言与 SETTINGS 帧**的原始帧文件，
按 [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) §4/§6 校验帧框架，
按 [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) 自写 HPACK（含
Huffman）解压首部，输出 JSON。生产运行路径不使用任何第三方协议解码器。

## 入口与用法

```bash
# 推荐：隔离模式 + 薄启动脚本（不依赖当前目录或 PYTHONPATH）
python3 -I h2audit_cli.py 帧文件 [-o 输出.json]

# 已安装（pip install . ）后
h2audit 帧文件 [-o 输出.json]

# 模块方式（非 -I 环境）
python3 -m h2audit 帧文件 -o 输出.json
```

- `-o` 省略或为 `-` 时结果打印到标准输出。
- 成功时输出文件以同目录临时文件 + `os.replace` **原子替换**；
  失败时进程返回非零、诊断信息写到 stderr，**旧输出文件原样保留**，
  且不残留临时文件。
- 空输入文件输出 `[]`。

## 输出格式

按 HEADERS 帧出现顺序，每个完整首部块一个数组：

```json
[
  [stream_id, offset, [["name_hex", "value_hex"], ...]],
  ...
]
```

- `stream_id`：流标识（已忽略 R 保留位）。
- `offset`：该块**首帧**在输入文件中的零基字节偏移。
- `fields`：按原始顺序的字段对，名称与值均以**小写十六进制**保留原始字节
  （重复字段、任意字节都原样保留）；空块为 `[]`。

规范示例：流 1 的完整块 `40 01 78 01 61` 后接流 3 的完整块 `be`，
两者 `fields` 均为 `[["78","61"]]`（HPACK 先以字面量增量加入 `x: a`，
动态表绝对索引 62 即该条目）。

## 校验范围（按任务限定）

### 帧层（RFC 9113 §4、§6）

- 仅接受 `DATA(0)`、`HEADERS(1)`、`RST_STREAM(3)`、`CONTINUATION(9)`；
  其他帧类型（含应已移除的 SETTINGS）一律拒绝。
- 每帧 3 字节载荷长度硬上限 **16384**，超限即拒；帧头或载荷截断即拒。
- 忽略未知标志与 R 保留位；流号按低 31 位解析；四类帧流号均不得为 0。
- 校验 HEADERS 的填充（PADDED）与优先级（PRIORITY）**框架**：
  填充长度字段存在且不吞没自身、优先级区固定 5 字节；填充字节本身任意、
  不检查内容；优先级内容完全忽略。
- DATA 的填充同样只验框架；`RST_STREAM` 载荷必须恰为 4 字节。
- 未结束的块（无 END_HEADERS）之后**只能**紧跟同流 CONTINUATION；
  **END_STREAM 不结束块**。块中间出现任何其他帧（含 DATA/RST_STREAM）即拒。
- DATA、RST_STREAM 验完框架即忽略，**不清空** HPACK 动态表。
- 不校验流状态机、HTTP 语义、流控。

### HPACK 层（RFC 7541，自写）

- 内嵌 RFC 7541 附录 A 的 61 项静态表与附录 B 的 257 个 Huffman 码
  （含 30 位 EOS），运行时不依赖第三方码表/解码器。
- 整数严格按 §5.1 的数学过程解码；对有限编码**不另设值域或字节数上限**
  （仅结构性截断报错）。
- 动态表初始为空，当前容量与上限均为 4096；表大小更新只允许出现在
  **块首**（任何字段之后出现即拒），且不得超过 4096。
- 条目大小 = 名称与值解码字节数之和 + 32；超大条目淘汰到整表清空，
  字段仍照常输出；字面量的名称先解析、后淘汰。
- 拒绝：非法索引（0 或超出静态+动态表）、Huffman 串中出现 EOS、
  非法 Huffman 尾填充（非全 1 或长度达到最长码）、不可解码位序列。
- 同一文件内多个块共享一个解码器，动态表状态跨块持续。

### 两阶段与报错偏移

1. 先顺序扫描**整个文件**完成全部帧框架与续帧关系校验，通过后才开始
   HPACK 解压；任何错误都整次拒绝、不产生部分结果。
2. 帧层错误报**出错帧起点**；截断同样按帧起点报。
   唯 EOF 处仍缺 CONTINUATION 时，报该块 **HEADERS 帧起点**。
3. HPACK 错误报**所属块起点**（即其 HEADERS 首帧偏移）。

## 目录结构

```
h2audit/
  __init__.py     # audit() 总入口：先全量帧校验，再逐块解压
  __main__.py     # CLI、参数解析、原子输出
  framing.py      # RFC 9113 帧扫描、填充/优先级框架、续帧状态机
  hpack.py        # RFC 7541 整数/字符串/Huffman、动态表、块解码
  tables.py       # 内嵌标准静态表与 Huffman 码表（RFC 固定数据）
h2audit_cli.py    # -I 隔离模式下的薄启动器
run_tests.py      # 测试运行器（在 sys.path 注入工程根）
tests/
  test_framing.py     帧层合法/拒绝与偏移
  test_hpack.py       整数、字符串、Huffman、动态表、块解码
  test_rfc_vectors.py RFC 附录 C 风格向量与静态表锚点
  test_acceptance.py  与成熟库 hpack 的合法块对照 + 独立拒绝夹具
  test_boundary.py    16384 边界、长序列共享状态、淘汰对照
  test_cli.py         端到端、原子替换、失败保留、独立二进制夹具
  fixtures/           独立手工夹具及其生成脚本 build_fixtures.py
```

## 验收方式

```bash
# 1. 生成独立二进制夹具（纯手工字节，不依赖第三方库）
python3 -I tests/fixtures/build_fixtures.py

# 2. 运行全部测试（建议隔离模式）
python3 -I run_tests.py
```

- **合法 HPACK**：`test_acceptance.py` / `test_boundary.py` 用成熟库
  `hpack` 的 `Encoder` 产生合法块（含 Huffman、动态表索引与淘汰、
  表缩扩容），再由本解码器解压并逐字段对照；覆盖跨帧、跨流、缩扩容。
  该库仅在测试环境按需导入，生产包不引用。
- **拒绝与偏移**：使用 `tests/fixtures/` 下独立生成的二进制夹具与
  各测试内手工构造的字节，不经过任何第三方解码器。
- 无第三方库时，依赖 `hpack` 的对照测试自动跳过，其余测试仍完整运行。

## 设计取舍

- 长度上限固定为 16384：本输入不含 SETTINGS 协商，按任务给定硬上限处理。
- Huffman 用 `(码, 位长) -> 符号` 精确匹配，配合 EOS 全 1 前缀规则，
  天然识别 EOS、非法尾填充与不可解码序列。
- 输出采用十六进制而非文本，规避 HTTP/2 二进制首部（含非 UTF-8 字节）
  的编解码歧义，严格保留字节与重复字段。
