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

当前 `capture` 和桌面端可解析常见链路类型上的 IPv4/IPv6 TCP 与 UDP packet，可从 DNS 响应学习域名展示，并会把 pcap 已收到但暂不支持解析的原始 frame 标记为 `unsupported_packet`；已支持加载 NSS `SSLKEYLOGFILE`，对 TLS 1.3 `TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384` 和 `TLS_CHACHA20_POLY1305_SHA256` 连接还原 HTTPS application data 明文。TCP/TLS 明文可继续解析 HTTP/2 frame；UDP/QUIC 可在匹配 TLS 1.3 key log 时解密 QUIC v1 1-RTT packet，并以插件事件输出 QUIC frame 与 HTTP/3 HEADERS/DATA。HTTPS 代理尚未实现。

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

加载 Chrome/Firefox/curl 等客户端生成的 TLS key log：

```sh
cargo run -p protolens-cli -- capture --interface en0 --filter 'tcp port 443' --tls-key-log /tmp/protolens-sslkeys.log
cargo run -p protolens-cli -- replay sample.pcap --tls-key-log /tmp/protolens-sslkeys.log
```

Chrome 示例。如果已有 Chrome 正在运行，建议用独立 profile 启动，避免现有进程复用导致环境变量不生效：

```sh
SSLKEYLOGFILE=/tmp/protolens-sslkeys.log open -na "Google Chrome" --args --user-data-dir=/tmp/protolens-chrome-keylog-profile
```

桌面端可以在 `SSL Key Log File` 里选择已有 key log，或在 `Launch Chrome` 时新建文件。启动前会提示用户确认已关闭现有 Chrome；确认后 ProtoLens 会按当前平台启动带 `SSLKEYLOGFILE` 的 Chrome，并使用隔离 profile。访问目标站点后，live capture 或 PCAP replay 会自动重载 key log 文件并输出解密后的协议 observation。TCP/TLS 路径输出 `https.plaintext` 和 `http2.frames`；QUIC 路径输出 `quic.packet`，解密成功后继续输出 `http3.frame`，用于查看 HTTP/3 method、authority、path、status、content-type、DATA 长度和可读 preview。该控件在桌面端采用路径输入独占一行、操作按钮单独一行的布局，避免长路径挤压按钮。

网卡抓包通常需要系统权限。例如 macOS/Linux 可能需要用 `sudo` 运行，Windows 通常需要安装 Npcap。

当前 `capture` 可解析常见链路类型上的 IPv4/IPv6 TCP 与 UDP packet；遇到不支持的链路层或网络/传输协议时，会输出 `unsupported_packet` 事件，便于区分“pcap 没收到包”和“收到了但解析器暂不支持”。TLS 和 QUIC 解密都需要完整 packet payload，默认 payload limit 已提高到 65535；如果用户手动调小该值，TLS record 或 QUIC packet 被截断时无法解密。

## 桌面端 PCAP 保存

桌面端 live capture 会自动把原始抓包写入 `~/.protolens/capture.pcap`。每次点击 `Start` 时都会先清空这个工作文件，再开始写入本次抓包。用户点击 `Save captured PCAP...` 后选择目标路径，ProtoLens 会把当前工作文件移动到用户指定的位置；跨文件系统无法直接移动时会退化为 copy 后删除工作文件。

## 桌面端目标诊断

桌面端侧边栏提供 `Target` 输入框，可填写 `https://example.com`、域名、IP 或 `host:port`。点击 `Detect` 或直接 `Start` 时，桌面端会：

- 解析目标 host 和端口，默认 HTTPS 使用 443，HTTP 使用 80。
- 解析目标 IP，并在 macOS 上通过系统路由推荐接口，例如 `utun3`。
- 识别 `198.18.0.0/15` 这类代理 fake-ip 场景，提示应抓取 tunnel/VPN 接口而不是 Wi-Fi。
- 将建议的 BPF filter 作为默认值填入，例如 `host 198.18.1.11 and port 443`；如果用户手动修改，最终以人工输入为准。
- 抓包启动后区分没有 raw packet、只有 unsupported packet、以及已解析 packet 三种状态。

## 桌面端 packet 详情

桌面端 timeline 的 packet 详情按协议层展示：

- `L2 Link`、`L3 Network`、`L4 Transport` 和 `Payload` 分区展示各层元数据。
- protocol observation 也会展示对应的 L7 分区，例如 `L7 HTTPS`、`L7 HTTP/2`、`L7 QUIC`、`L7 HTTP/3`。
- 各层分区默认折叠，点击分区标题展开或收起。
- `Payload` 优先展示可读 plaintext、HTTP/2 frame 摘要、解密后的 QUIC frame 摘要或 HTTP/3 header/data 预览；真实 bytes 仍以 `payload.data` 为准。
- Raw Event 不在主详情中常驻显示，只通过详情标题右侧的 `Raw` 调试按钮在提示窗中查看。

## 开发约定

- Rust 代码修改后运行 `cargo fmt --check`。
- CLI、抓包或协议管理相关修改后运行 `cargo test`。
- 公共事件、错误和 trait 优先放在 `protolens-core`。
- 抓包实现放在 `protolens-capture`，不要直接写进 CLI。
- 协议分析器放在 `protolens-protocol`，v1 只支持静态 Rust 插件；packet-level 和 event-level 分析器都通过注册表接入，避免把 HTTP/2、QUIC、HTTP/3 等逻辑写入抓包主流程。
- CLI 只负责参数解析、调用 core controller 和展示结果，不承载核心业务逻辑。

## 设计文档

先阅读：

- `docs/project-brief.md`
- `docs/architecture.md`
- `docs/context/README.md`
