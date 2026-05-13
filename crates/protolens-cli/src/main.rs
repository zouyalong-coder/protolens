use clap::{Parser, Subcommand};
use protolens_capture::{CaptureInterface, PcapSource, PcapSourceConfig, list_interfaces};
use protolens_core::{EventSink, PacketSource, Result};
use protolens_output::FormattedEventSink;

/// ProtoLens CLI 参数入口。
#[derive(Debug, Parser)]
#[command(name = "protolens")]
#[command(about = "A modular packet capture and traffic inspection tool")]
struct Cli {
    /// 子命令。
    #[command(subcommand)]
    command: Command,
}

/// CLI 支持的子命令。
#[derive(Debug, Subcommand)]
enum Command {
    /// 列出 pcap 可发现的抓包接口。
    Interfaces,
    /// 从指定接口抓取 packet。
    Capture {
        /// 网卡名，例如 `en0`、`eth0`。
        #[arg(short, long)]
        interface: String,

        /// BPF filter，默认只抓 TCP。
        #[arg(short, long, default_value = "tcp")]
        filter: String,

        /// 输出指定数量的 packet 后退出；不传则持续运行。
        #[arg(short, long)]
        count: Option<usize>,

        /// 单个 packet payload 最多保留的原始字节数。
        #[arg(long, default_value_t = 4096)]
        payload_limit: usize,
    },
}

/// CLI 主入口只负责参数解析、调用底层 crate、选择输出 sink。
fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    match Cli::parse().command {
        Command::Interfaces => {
            for interface in list_interfaces()? {
                print_interface(interface);
            }
        }
        Command::Capture {
            interface,
            filter,
            count,
            payload_limit,
        } => {
            let config = PcapSourceConfig {
                interface,
                filter: Some(filter),
                payload_limit: Some(payload_limit),
                ..PcapSourceConfig::default()
            };

            run_capture(config, count)?;
        }
    }

    Ok(())
}

/// 执行 pcap 抓包并将事件写入格式化输出 sink。
fn run_capture(config: PcapSourceConfig, count: Option<usize>) -> Result<()> {
    let mut source = PcapSource::new(config)?;
    let stdout = std::io::stdout();
    let mut sink = FormattedEventSink::new(stdout.lock());
    let mut emitted_packets = 0usize;

    loop {
        if let Some(event) = source.next_event()? {
            // `--count` 只统计真实 packet，不统计 capture_started 等控制事件。
            let is_packet = matches!(
                event.kind,
                protolens_core::CaptureEventKind::InterfacePacket { .. }
            );

            sink.write(&event)?;
            sink.flush()?;

            if is_packet {
                emitted_packets += 1;
                if count.is_some_and(|count| emitted_packets >= count) {
                    break;
                }
            }
        }
    }

    Ok(())
}

/// 打印一个接口的详细信息。
fn print_interface(interface: CaptureInterface) {
    println!("{}", interface.name);

    if let Some(description) = &interface.description {
        println!("  description: {description}");
    }

    println!("  status: {}", interface.flags.connection_status);
    println!("  flags: {}", interface_flags(&interface));

    if interface.addresses.is_empty() {
        println!("  addresses: none");
    } else {
        println!("  addresses:");
        for address in interface.addresses {
            println!("    - address: {}", address.address);

            if let Some(netmask) = address.netmask {
                println!("      netmask: {netmask}");
            }

            if let Some(broadcast_address) = address.broadcast_address {
                println!("      broadcast: {broadcast_address}");
            }

            if let Some(destination_address) = address.destination_address {
                println!("      destination: {destination_address}");
            }
        }
    }
}

/// 将接口 flags 压缩成适合 CLI 展示的一行文本。
fn interface_flags(interface: &CaptureInterface) -> String {
    let mut flags = Vec::new();

    if interface.flags.is_up {
        flags.push("up");
    }
    if interface.flags.is_running {
        flags.push("running");
    }
    if interface.flags.is_loopback {
        flags.push("loopback");
    }
    if interface.flags.is_wireless {
        flags.push("wireless");
    }

    if flags.is_empty() {
        "none".to_owned()
    } else {
        flags.join(", ")
    }
}
