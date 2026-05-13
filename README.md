# ProtoLens

ProtoLens 是一个使用 Rust 构建的模块化抓包与流量检查工具。当前阶段优先实现 CLI 和可复用核心库，未来会扩展协议分析、HTTPS 显式代理、TUN 模式、桌面端和 AI 分析能力。

## 当前状态

项目处于初始骨架阶段，已经搭建：

- Cargo workspace。
- 核心事件模型和统一错误类型。
- 抓包源、协议分析器、事件输出相关 trait。
- 静态协议插件注册器。
- CLI 命令骨架。

实际网卡抓包、TCP session tracking、HTTPS 代理尚未实现。

## Workspace 结构

```text
crates/
  protolens-core/       公共类型、事件模型、trait、统一错误
  protolens-capture/    抓包后端和 PacketSource 实现
  protolens-output/     格式化输出等 EventSink 插件
  protolens-protocol/   协议分析器和静态插件注册
  protolens-cli/        CLI 入口
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

当前 `capture` 只解析常见链路类型上的 IPv4/IPv6 TCP packet，TCP session tracking、HTTPS 代理尚未实现。

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
