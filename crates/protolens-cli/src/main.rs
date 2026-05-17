use clap::{Parser, Subcommand, ValueEnum};
use protolens_capture::CaptureInterface;
use protolens_controller::{CaptureRunConfig, capture_interfaces};
use protolens_core::{Error, EventSink, Result};
use protolens_output::{FormattedEventSink, LinkEventSink};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

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

        /// BPF filter，默认抓 TCP 和 DNS 响应以便显示域名。
        #[arg(short, long, default_value = "tcp or udp port 53")]
        filter: String,

        /// 输出指定数量的 packet 后退出；不传则持续运行。
        #[arg(short, long)]
        count: Option<usize>,

        /// 单个 packet payload 最多保留的原始字节数。
        #[arg(long, default_value_t = 65_535)]
        payload_limit: usize,

        /// 输出视图：events 为逐事件输出，links 为按 TCP 链路聚合输出。
        #[arg(long, value_enum, default_value = "events")]
        view: CaptureView,

        /// 只输出匹配端点的 link；仅影响 --view links，可重复指定。
        ///
        /// 示例：--link-filter 10.0.0.2、--link-filter :443、--link-filter 10.0.0.2:443。
        #[arg(long)]
        link_filter: Vec<String>,

        /// 同步保存原始抓包为 pcap 文件，可用 Wireshark 打开。
        #[arg(long)]
        pcap_out: Option<PathBuf>,

        /// NSS SSLKEYLOGFILE 路径；用于后续 TLS session 解密匹配。
        #[arg(long)]
        tls_key_log: Option<PathBuf>,
    },
    /// 从 pcap 文件回放事件，用于离线调试。
    Replay {
        /// pcap 文件路径。
        file: PathBuf,

        /// 单个 packet payload 最多保留的原始字节数。
        #[arg(long, default_value_t = 65_535)]
        payload_limit: usize,

        /// NSS SSLKEYLOGFILE 路径；用于回放时匹配 TLS session secrets。
        #[arg(long)]
        tls_key_log: Option<PathBuf>,

        /// 输出视图：events 为逐事件输出，links 为按 TCP 链路聚合输出。
        #[arg(long, value_enum, default_value = "events")]
        view: CaptureView,

        /// 只输出匹配端点的 link；仅影响 --view links，可重复指定。
        #[arg(long)]
        link_filter: Vec<String>,
    },
}

/// capture 输出视图。
#[derive(Debug, Clone, Copy, ValueEnum)]
enum CaptureView {
    /// 保留原有逐 packet/事件输出。
    Events,
    /// 按双向 TCP 链路聚合展示建连、传输、断开。
    Links,
}

/// CLI 主入口只负责参数解析、调用底层 crate、选择输出 sink。
fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    match Cli::parse().command {
        Command::Interfaces => {
            for interface in capture_interfaces()? {
                print_interface(interface);
            }
        }
        Command::Capture {
            interface,
            filter,
            count,
            payload_limit,
            view,
            link_filter,
            pcap_out,
            tls_key_log,
        } => {
            let config = CaptureRunConfig::pcap(
                interface,
                filter,
                count,
                payload_limit,
                pcap_out,
                tls_key_log,
            );

            run_capture(config, view, link_filter)?;
        }
        Command::Replay {
            file,
            payload_limit,
            view,
            link_filter,
            tls_key_log,
        } => {
            replay_capture(file, payload_limit, tls_key_log, view, link_filter)?;
        }
    }

    Ok(())
}

/// 从 pcap 文件回放并将事件写入格式化输出 sink。
fn replay_capture(
    file: PathBuf,
    payload_limit: usize,
    tls_key_log: Option<PathBuf>,
    view: CaptureView,
    link_filter: Vec<String>,
) -> Result<()> {
    let stdout = std::io::stdout();
    let stdout = stdout.lock();
    let mut sink: Box<dyn EventSink + '_> = match view {
        CaptureView::Events => Box::new(FormattedEventSink::new(stdout)),
        CaptureView::Links => Box::new(LinkEventSink::new_with_filters(stdout, link_filter)),
    };

    let count =
        protolens_controller::replay_pcap_file(file, payload_limit, tls_key_log, |event| {
            sink.write(&event)?;
            sink.flush()?;
            Ok(())
        })?;

    eprintln!("[protolens] replay emitted {count} events");

    Ok(())
}

/// 执行 pcap 抓包并将事件写入格式化输出 sink。
fn run_capture(
    config: CaptureRunConfig,
    view: CaptureView,
    link_filter: Vec<String>,
) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let signal_running = Arc::clone(&running);
    ctrlc::set_handler(move || {
        eprintln!("[protolens] Ctrl-C received; stopping capture...");
        signal_running.store(false, Ordering::SeqCst);
    })
    .map_err(|error| Error::InvalidConfig(format!("failed to install Ctrl-C handler: {error}")))?;

    let stdout = std::io::stdout();
    let stdout = stdout.lock();
    let mut sink: Box<dyn EventSink + '_> = match view {
        CaptureView::Events => Box::new(FormattedEventSink::new(stdout)),
        CaptureView::Links => Box::new(LinkEventSink::new_with_filters(stdout, link_filter)),
    };

    protolens_controller::run_capture(
        config,
        |event| {
            sink.write(&event)?;
            sink.flush()?;
            Ok(())
        },
        || running.load(Ordering::SeqCst),
    )?;

    eprintln!("[protolens] capture loop stopped");

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
