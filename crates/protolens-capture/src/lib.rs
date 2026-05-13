//! Capture backend abstractions and built-in source placeholders.

use protolens_core::{CaptureEvent, Error, PacketSource, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureInterface {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapSourceConfig {
    pub interface: String,
    pub filter: Option<String>,
    pub snaplen: i32,
    pub immediate_mode: bool,
}

impl Default for PcapSourceConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            filter: Some("tcp".to_owned()),
            snaplen: 65_535,
            immediate_mode: true,
        }
    }
}

pub struct PcapSource {
    id: String,
}

impl PcapSource {
    pub fn new(config: PcapSourceConfig) -> Result<Self> {
        if config.interface.is_empty() {
            return Err(Error::InvalidConfig(
                "pcap source requires an interface".to_owned(),
            ));
        }

        Err(Error::Unsupported(
            "pcap capture backend is not implemented yet".to_owned(),
        ))
    }
}

impl PacketSource for PcapSource {
    fn id(&self) -> &str {
        &self.id
    }

    fn next_event(&mut self) -> Result<Option<CaptureEvent>> {
        Err(Error::Unsupported(
            "pcap capture backend is not implemented yet".to_owned(),
        ))
    }
}

pub fn list_interfaces() -> Result<Vec<CaptureInterface>> {
    Err(Error::Unsupported(
        "interface discovery is not implemented yet".to_owned(),
    ))
}
