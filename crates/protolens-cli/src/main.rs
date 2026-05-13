use clap::{Parser, Subcommand};
use protolens_capture::{PcapSourceConfig, list_interfaces};
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
                match interface.description {
                    Some(description) => println!("{}\t{}", interface.name, description),
                    None => println!("{}", interface.name),
                }
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
