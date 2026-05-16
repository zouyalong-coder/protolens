# ProtoLens 架构设计

本文档描述 ProtoLens 在实现前的架构设计。整体方向是 Rust 核心引擎加薄产品入口，第一入口是 CLI，未来桌面程序应复用同一套核心 API，而不是 shell 调 CLI。

## 架构概览

```text
CLI / Desktop / Service
        |
        v
Controller API
        |
        v
Capture Pipeline -> Session Store -> Analyzer Pipeline -> Output Sinks
        |                 |                  |               |
        v                 v                  v               v
Capture Backends   Flow Model       Protocol Plugins   JSON/UI/Files
pcap/proxy/tun     TCP Sessions     AI Plugins         Events
```

核心思路：抓包来源、会话建模、协议分析、输出展示彼此解耦。CLI 只是发起任务、展示结果和处理用户输入。

## 推荐 Rust Workspace

```text
crates/
  protolens-cli/          CLI 入口
  protolens-core/         pipeline 编排和公共 API
  protolens-capture/      抓包后端和 packet source
  protolens-protocol/     协议插件 trait 和内置解析器
  protolens-mitm/         HTTPS 代理和证书处理
  protolens-store/        会话存储和导出格式
  protolens-ai/           未来 AI 分析集成
```

第一版可以更小：`protolens-core`、`protolens-capture`、`protolens-protocol`、`protolens-cli` 足够启动。

## 核心概念

### Packet Source

`PacketSource` 负责产生原始捕获事件，不关心 UI、存储、AI 或协议展示。

- `PcapSource`：通过 libpcap/Npcap 从网卡读取数据。
- `ProxySource`：接收本机或局域网设备发来的显式代理流量。
- `TunSource`：未来虚拟网卡/TUN 模式。
- `FileSource`：未来从 pcap 或导出的事件文件回放。

### Flow And Session Model

核心层将 packet 归一化成 flow 和 session。

- `FlowKey`：传输层五元组，例如源地址、源端口、目标地址、目标端口、协议。
- `TcpSession`：双向有序字节流和相关 metadata。
- `CaptureEvent`：稳定事件 envelope，供存储、UI 和分析器消费。

这个层非常关键，因为 CLI、桌面 UI、AI 分析都应消费同一种数据模型。

### Protocol Analyzer

协议分析器读取标准化 session 或事件，输出更高层的观察结果。

第一阶段建议先做内部 Rust trait，不急于做动态插件加载。等事件模型稳定后，再考虑外部进程插件或 WASM 插件。

```rust
pub trait ProtocolAnalyzer {
    fn id(&self) -> &'static str;
    fn supports(&self, session: &SessionMeta) -> bool;
    fn analyze(&mut self, event: &CaptureEvent, sink: &mut dyn AnalysisSink) -> anyhow::Result<()>;
}
```

内置分析器方向：

- TCP metadata 分析器，第一版目标。
- TLS metadata 分析器，提取 SNI、ALPN、证书信息和握手信息。
- HTTP 分析器，在明文 HTTP 或 MITM 能力完成后加入。
- 自定义应用协议分析器。

### Output Sink

`OutputSink` 接收结构化事件。

- CLI 表格或实时流式输出。
- JSON Lines 导出。
- 未来 SQLite 存储。
- 未来桌面 UI 事件总线。
- 未来 AI 输入管线。

### Desktop Packet Detail View

桌面端 packet timeline 消费同一套 `CaptureEvent` 和 `PacketMeta`，详情视图按协议层组织，而不是把所有字段压成单行文本。

- `L2 Link` 展示链路介质、封装协议、链路层 header 长度和 frame 长度。
- `L3 Network` 展示 IP 协议、header 长度、packet 长度和 TTL/hop limit。
- `L4 Transport` 展示传输协议、源/目标端点、header 长度、segment 长度和 TCP flags。
- `Payload` 展示原始长度、编码方式、截断状态、UTF-8 preview 和 base64 数据。
- 各层分区默认折叠，避免详情面板被低频字段占满；用户按需展开查看。
- Raw Event 属于调试信息，不常驻显示在详情主体，只通过调试入口临时查看。

## 抓包模式

### 网卡抓包

从指定网卡捕获 packet。这是本机和局域网抓包的基础路径，但依赖权限和网络拓扑。

推荐选型：

- `pcap` crate，绑定 libpcap/Npcap。
- BPF filter，用于缩小捕获范围，例如 `tcp`、`host`、`port`、`net`。

权衡：

- 跨平台路径相对成熟，但 Windows 需要 Npcap。
- 在交换网络里抓其他设备流量并不总是可行，可能需要本机作为网关、Wi-Fi monitor mode、端口镜像、ARP spoofing 或显式代理配置。

### 显式代理抓包

ProtoLens 启动本机或局域网代理。手机配置电脑 IP 和代理端口后，流量经过 ProtoLens。

手机抓包功能可以后置，但实现时优先采用显式代理路径，因为用户模型清晰，不需要一开始处理复杂路由。

HTTPS 代理需要：

- HTTP CONNECT 支持。
- 本地 root CA 生成。
- 按 host 生成 leaf certificate。
- CLI 提供安装和信任 CA 的指引。

### TUN 抓包

未来通过虚拟网卡接入流量，并将选定流量路由到 ProtoLens。

TUN 应被建模成另一个 `PacketSource`，而不是散落在主流程里的特殊分支。

后续可评估：

- `tun` crate 或平台专用适配层。
- 每个 OS 独立的 routing setup 模块。

权衡：

- 更接近系统级捕获。
- 平台差异和权限处理更复杂。
- DNS、路由、权限、异常清理都需要严肃设计。

## HTTPS 支持策略

HTTPS 能力应拆成两个层次，不要混在一起。

### TLS Metadata Capture

不解密时，仍可从 packet 或连接 metadata 中获得目标 IP、端口、TLS ClientHello、可见 SNI、ALPN、证书 metadata、时序信息。

这个能力可以先于完整 MITM 落地。

### HTTPS MITM 解密

要检查请求和响应 body，ProtoLens 必须作为显式代理或 routed MITM，且客户端必须信任 ProtoLens 的本地 CA。

该能力必须显式开启，并隔离在 `protolens-mitm`。

推荐选型：

- `tokio` 处理异步网络。
- `rustls` 处理 TLS。
- `rcgen` 生成证书。
- `hyper` 或更底层 HTTP crate，根据代理控制需求选择。

限制：

- 移动 App 的 certificate pinning 可能阻止解密。
- QUIC/HTTP3 可能需要在代理工作流中禁用或降级到 TCP/TLS。
- 工具不应静默安装 root CA。

## 插件模型

插件能力分阶段推进。

### 阶段 1：静态插件

内置分析器作为 Rust crate 编译进主程序，启动时注册。优点是简单、类型安全、适合早期。v1 明确只支持静态插件，不引入外部进程或动态插件机制。

### 阶段 2：外部进程插件

分析器作为子进程，通过 JSON Lines 或 protobuf 通信。优点是隔离性更好，也方便多语言扩展。

### 阶段 3：WASM 插件

事件模型稳定后再考虑 WASM。WASM 具备隔离性和可移植性，但会引入 runtime、ABI 和能力边界设计成本。

## CLI 形态

初始命令可以是：

```text
protolens interfaces
protolens capture --interface en0 --filter tcp
protolens capture --interface en0 --filter 'tcp port 443' --json out.jsonl
protolens proxy --listen 0.0.0.0:8080
protolens cert init
protolens cert path
```

CLI 应调用 `protolens-core` 暴露的 controller API。不要把业务逻辑写在命令处理器里。

推荐选型：

- `clap`：CLI 参数解析。
- `tracing` 和 `tracing-subscriber`：诊断日志。
- `serde`：事件序列化。
- `anyhow`：应用层错误。
- `thiserror`：库层错误。

## 数据模型方向

早期使用 append-only 结构化事件，保证捕获结果可以被回放。

事件类别示例：

- `capture.started`
- `interface.packet`
- `tcp.session.started`
- `tcp.bytes`
- `tcp.session.ended`
- `protocol.observation`
- `proxy.request`
- `proxy.response`
- `error`

JSON Lines 适合作为第一版持久化格式，因为它易调试，容易输入到桌面端、测试和 AI 工具。SQLite 可以等事件模型稳定、需要索引和大捕获文件时再加入。

payload 可以保留在事件里，但不能假设它是 UTF-8 字符串。建议使用带 encoding 标记的结构：

```json
{
  "payload": {
    "encoding": "base64",
    "data": "...",
    "truncated": false
  }
}
```

对可读文本可以额外提供 preview 字段，但原始 payload 表达应以 bytes 为准，避免二进制协议、压缩内容或非 UTF-8 数据丢失。

## 跨平台注意事项

### macOS

- 网卡抓包通常需要提升权限。
- TUN 和路由修改需要管理员权限。
- 系统证书信任需要 Keychain 交互和用户显式确认。

### Linux

- 网卡抓包可能需要 root，或 `CAP_NET_RAW`、`CAP_NET_ADMIN` 等 capability。
- TUN 和路由可行，但必须保证异常清理。
- 证书安装随发行版和浏览器不同而变化。

### Windows

- 网卡抓包通常需要 Npcap。
- 证书信任依赖 Windows certificate store。
- TUN 模式可能需要 Wintun 或其他驱动支持方案。

## 第一里程碑

构建一个 CLI，能够：

- 列出可用抓包网卡。
- 从指定网卡捕获 TCP packet。
- 在 metadata 层面聚合 TCP session。
- 打印可读的实时输出。
- 导出 JSON Lines 事件。

建议实现顺序：

1. 创建 Rust workspace 和核心 crate 边界。
2. 定义 `CaptureEvent`、`PacketSource`、analyzer、sink trait。
3. 使用 `pcap` 实现网卡列表和 TCP filter 抓包。
4. 增加基础 TCP flow/session tracking。
5. 增加 CLI 实时输出和 JSON Lines sink。
6. 为 flow key、事件序列化、analyzer 注册写测试。

## 待确认问题

- 第一阶段手机抓包功能后置；实现时优先做显式代理，而不是尝试原始局域网抓包。
- v1 的 JSON Lines 可以保存 payload bytes，但必须用 base64 等方式表达不可读或非 UTF-8 内容。
- v1 是否需要 SQLite，还是等事件模型稳定后再加入。
- v1 插件只做内部 Rust trait 和静态注册；外部进程插件后置。
- CLI 要自动执行多少 OS 设置，哪些只提供指引。
