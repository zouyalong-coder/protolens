# ProtoLens

ProtoLens 是一个使用 Rust 构建的模块化抓包与流量检查工具。当前阶段优先实现 CLI、可复用核心库和复用同一控制器的桌面端，未来会扩展协议分析、HTTPS 显式代理、TUN 模式和 AI 分析能力。

## 当前状态

项目处于早期可运行阶段，已经搭建：

- Cargo workspace。
- 核心事件模型和统一错误类型。
- 抓包源、协议分析器、事件输出相关 trait。
- 静态协议插件注册器。
- CLI 抓包、回放和格式化输出入口。
- Tauri 桌面端，用于选择接口、按目标诊断路由、加载 PCAP、查看链路、事件和 packet timeline。

当前 `capture` 和桌面端可解析常见链路类型上的 IPv4/IPv6 TCP 与 UDP packet，可从 DNS 响应学习域名展示，并会把 pcap 已收到但暂不支持解析的原始 frame 标记为 `unsupported_packet`；TCP session tracking、HTTPS 代理尚未实现。

## Workspace 结构

```text
crates/
  protolens-core/       公共类型、事件模型、trait、统一错误
  protolens-capture/    抓包后端和 PacketSource 实现
  protolens-output/     格式化输出等 EventSink 插件
  protolens-protocol/   协议分析器和静态插件注册
  protolens-controller/ CLI 和桌面端复用的控制器入口
  protolens-cli/        CLI 入口
  protolens-desktop/    Tauri 桌面端
docs/
  project-brief.md      产品方向和范围
  architecture.md       架构、模块边界和路线图
```

未来可复用、可独立发布或开源的代码优先放在 `crates/` 下，避免和 CLI 入口耦合。

## 开发环境

需要安装 Rust stable toolchain。

```sh
rustup toolchain install stable
rustup default stable
```

## 常用命令

格式化代码：

```sh
cargo fmt
```

检查格式：

```sh
cargo fmt --check
```

运行测试：

```sh
cargo test
```

编译整个 workspace：

```sh
cargo check
```

运行 CLI：

```sh
cargo run -p protolens-cli -- --help
```

查看接口：

```sh
cargo run -p protolens-cli -- interfaces
```

抓取指定网卡上的 TCP 包，并输出前 10 个解析结果：

```sh
cargo run -p protolens-cli -- capture --interface en0 --filter tcp --count 10
```

限制每个 packet payload 保存的最大字节数：

```sh
cargo run -p protolens-cli -- capture --interface en0 --filter tcp --payload-limit 1024
```

网卡抓包通常需要系统权限。例如 macOS/Linux 可能需要用 `sudo` 运行，Windows 通常需要安装 Npcap。

当前 `capture` 可解析常见链路类型上的 IPv4/IPv6 TCP 与 UDP packet；遇到不支持的链路层或网络/传输协议时，会输出 `unsupported_packet` 事件，便于区分“pcap 没收到包”和“收到了但解析器暂不支持”。TCP session tracking、HTTPS 代理尚未实现。

## 桌面端目标诊断

桌面端侧边栏提供 `Target` 输入框，可填写 `https://example.com`、域名、IP 或 `host:port`。点击 `Detect` 或直接 `Start` 时，桌面端会：

- 解析目标 host 和端口，默认 HTTPS 使用 443，HTTP 使用 80。
- 解析目标 IP，并在 macOS 上通过系统路由推荐接口，例如 `utun3`。
- 识别 `198.18.0.0/15` 这类代理 fake-ip 场景，提示应抓取 tunnel/VPN 接口而不是 Wi-Fi。
- 自动生成 BPF filter，例如 `host 198.18.1.11 and port 443`。
- 抓包启动后区分没有 raw packet、只有 unsupported packet、以及已解析 packet 三种状态。

## 桌面端 packet 详情

桌面端 timeline 的 packet 详情按协议层展示：

- `L2 Link`、`L3 Network`、`L4 Transport` 和 `Payload` 分区展示各层元数据。
- 各层分区默认折叠，点击分区标题展开或收起。
- `Payload` 同时展示 UTF-8 preview 和 base64 原始数据；preview 只用于阅读，真实 bytes 仍以 `payload.data` 为准。
- Raw Event 不在主详情中常驻显示，只通过详情标题右侧的 `Raw` 调试按钮在提示窗中查看。

## 开发约定

- Rust 代码修改后运行 `cargo fmt --check`。
- CLI、抓包或协议管理相关修改后运行 `cargo test`。
- 公共事件、错误和 trait 优先放在 `protolens-core`。
- 抓包实现放在 `protolens-capture`，不要直接写进 CLI。
- 协议分析器放在 `protolens-protocol`，v1 只支持静态 Rust 插件。
- CLI 只负责参数解析、调用 core controller 和展示结果，不承载核心业务逻辑。

## 设计文档

先阅读：

- `docs/project-brief.md`
- `docs/architecture.md`
- `docs/context/README.md`
