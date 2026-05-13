use clap::{Parser, Subcommand};
use protolens_capture::{CaptureInterface, PcapSourceConfig, list_interfaces};
use protolens_core::Result;

#[derive(Debug, Parser)]
#[command(name = "protolens")]
#[command(about = "A modular packet capture and traffic inspection tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Interfaces,
    Capture {
        #[arg(short, long)]
        interface: String,

        #[arg(short, long, default_value = "tcp")]
        filter: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    match Cli::parse().command {
        Command::Interfaces => {
            for interface in list_interfaces()? {
                print_interface(interface);
            }
        }
        Command::Capture { interface, filter } => {
            let _config = PcapSourceConfig {
                interface,
                filter: Some(filter),
                ..PcapSourceConfig::default()
            };

            return Err(protolens_core::Error::Unsupported(
                "capture command is scaffolded but not implemented yet".to_owned(),
            ));
        }
    }

    Ok(())
}

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
