//! Capture backend abstractions and built-in source placeholders.

use protolens_core::{CaptureEvent, Error, PacketSource, Result};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureInterface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<InterfaceAddress>,
    pub flags: InterfaceFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub netmask: Option<IpAddr>,
    pub broadcast_address: Option<IpAddr>,
    pub destination_address: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceFlags {
    pub is_loopback: bool,
    pub is_up: bool,
    pub is_running: bool,
    pub is_wireless: bool,
    pub connection_status: String,
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
    let devices = pcap::Device::list().map_err(|error| Error::Capture {
        source_id: "pcap".to_owned(),
        message: format!("failed to list capture interfaces: {error}"),
    })?;

    Ok(devices
        .into_iter()
        .map(|device| CaptureInterface {
            name: device.name,
            description: device.desc,
            addresses: device
                .addresses
                .into_iter()
                .map(|address| InterfaceAddress {
                    address: address.addr,
                    netmask: address.netmask,
                    broadcast_address: address.broadcast_addr,
                    destination_address: address.dst_addr,
                })
                .collect(),
            flags: InterfaceFlags {
                is_loopback: device.flags.is_loopback(),
                is_up: device.flags.is_up(),
                is_running: device.flags.is_running(),
                is_wireless: device.flags.is_wireless(),
                connection_status: format!("{:?}", device.flags.connection_status),
            },
        })
        .collect())
}
