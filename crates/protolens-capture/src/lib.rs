//! 抓包后端和内置 packet source。
//!
//! 当前 crate 先提供 pcap 网卡抓包能力，并把 packet 归一化成 core crate
//! 定义的 `CaptureEvent`。后续显式代理、TUN、文件回放也应该放在这一层。

use pcap::{Active, Capture, Linktype};
use protolens_core::{
    CaptureEvent, CaptureEventKind, Endpoint, Error, FlowKey, PacketSource, Payload, Result,
    TcpSegmentMeta, TransportProtocol,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
/// 可用于抓包的系统网卡信息。
pub struct CaptureInterface {
    /// 系统网卡名，例如 macOS 的 `en0` 或 Linux 的 `eth0`。
    pub name: String,
    /// libpcap/Npcap 提供的描述信息；不是所有平台都有。
    pub description: Option<String>,
    /// 网卡关联的 IP 地址。
    pub addresses: Vec<InterfaceAddress>,
    /// 网卡状态和能力标记。
    pub flags: InterfaceFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// 网卡上的一个地址记录。
pub struct InterfaceAddress {
    /// 网卡地址。
    pub address: IpAddr,
    /// 子网掩码。
    pub netmask: Option<IpAddr>,
    /// 广播地址。
    pub broadcast_address: Option<IpAddr>,
    /// 点对点接口的目标地址。
    pub destination_address: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// 网卡状态和能力。
pub struct InterfaceFlags {
    /// 是否为 loopback 接口。
    pub is_loopback: bool,
    /// 接口是否处于 up 状态。
    pub is_up: bool,
    /// 接口是否 running。
    pub is_running: bool,
    /// libpcap 判断的无线接口标记。
    pub is_wireless: bool,
    /// 连接状态，直接映射 pcap 提供的枚举名称。
    pub connection_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// pcap 抓包源配置。
pub struct PcapSourceConfig {
    /// 要打开的网卡名。
    pub interface: String,
    /// BPF filter，例如 `tcp` 或 `tcp port 443`。
    pub filter: Option<String>,
    /// 单个 packet 最大捕获长度。
    pub snaplen: i32,
    /// 是否启用 immediate mode，降低实时输出延迟。
    pub immediate_mode: bool,
    /// 是否启用混杂模式。
    pub promiscuous: bool,
    /// pcap 读超时时间，避免 CLI 在无包时永久阻塞。
    pub read_timeout_ms: i32,
    /// 每个 packet payload 最多保存的字节数。
    pub payload_limit: Option<usize>,
}

impl Default for PcapSourceConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            filter: Some("tcp".to_owned()),
            snaplen: 65_535,
            immediate_mode: true,
            promiscuous: false,
            read_timeout_ms: 1_000,
            payload_limit: Some(4_096),
        }
    }
}

pub struct PcapSource {
    /// 事件来源标识。
    id: String,
    /// 已激活的 pcap capture handle。
    capture: Capture<Active>,
    /// 当前网卡的链路层类型，用于决定如何剥离链路层头。
    linktype: Linktype,
    /// 用于确保每个 source 只发送一次 `capture_started`。
    emitted_started: bool,
    /// payload 截断限制。
    payload_limit: Option<usize>,
}

impl PcapSource {
    /// 打开一个 pcap 抓包源并应用 BPF filter。
    pub fn new(config: PcapSourceConfig) -> Result<Self> {
        if config.interface.is_empty() {
            return Err(Error::InvalidConfig(
                "pcap source requires an interface".to_owned(),
            ));
        }

        let mut capture = Capture::from_device(config.interface.as_str())
            .map_err(map_pcap_error("failed to create pcap capture"))?
            .snaplen(config.snaplen)
            .promisc(config.promiscuous)
            .immediate_mode(config.immediate_mode)
            .timeout(config.read_timeout_ms)
            .open()
            .map_err(map_pcap_error("failed to open pcap capture"))?;

        if let Some(filter) = &config.filter {
            capture
                .filter(filter, true)
                .map_err(map_pcap_error("failed to apply pcap filter"))?;
        }

        let linktype = capture.get_datalink();

        Ok(Self {
            id: format!("pcap:{}", config.interface),
            capture,
            linktype,
            emitted_started: false,
            payload_limit: config.payload_limit,
        })
    }
}

impl PacketSource for PcapSource {
    fn id(&self) -> &str {
        &self.id
    }

    fn next_event(&mut self) -> Result<Option<CaptureEvent>> {
        if !self.emitted_started {
            self.emitted_started = true;
            return Ok(Some(CaptureEvent {
                timestamp: current_time_millis(),
                source_id: self.id.clone(),
                kind: CaptureEventKind::CaptureStarted {
                    mode: "pcap".to_owned(),
                },
            }));
        }

        loop {
            let packet = match self.capture.next_packet() {
                Ok(packet) => packet,
                Err(pcap::Error::TimeoutExpired) => return Ok(None),
                Err(error) => return Err(map_pcap_error("failed to read pcap packet")(error)),
            };

            // 目前只把 TCP packet 转成事件；其他协议会被静默跳过，后续协议支持
            // 可以在这里扩展或拆到独立 decoder。
            let timestamp = packet_timestamp_millis(packet.header);
            let parsed = parse_tcp_packet(self.linktype, packet.data, self.payload_limit);

            if let Some((flow, tcp, payload)) = parsed {
                return Ok(Some(CaptureEvent {
                    timestamp,
                    source_id: self.id.clone(),
                    kind: CaptureEventKind::InterfacePacket {
                        flow: Some(flow),
                        tcp: Some(tcp),
                        payload,
                    },
                }));
            }
        }
    }
}

/// 列出系统当前可被 pcap 发现的抓包接口。
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

/// 将第三方 pcap 错误转换成项目统一错误类型。
fn map_pcap_error(context: &'static str) -> impl FnOnce(pcap::Error) -> Error {
    move |error| Error::Capture {
        source_id: "pcap".to_owned(),
        message: format!("{context}: {error}"),
    }
}

/// 根据链路层类型剥离链路层头，并尝试解析 TCP packet。
fn parse_tcp_packet(
    linktype: Linktype,
    packet: &[u8],
    payload_limit: Option<usize>,
) -> Option<(FlowKey, TcpSegmentMeta, Option<Payload>)> {
    let ip_packet = match linktype {
        Linktype::ETHERNET => ethernet_payload(packet)?,
        Linktype::IPV4 | Linktype::IPV6 | Linktype::RAW => packet,
        Linktype::NULL | Linktype::LOOP => loopback_payload(packet)?,
        _ => return None,
    };

    parse_ip_packet(ip_packet, payload_limit)
}

/// 解析 Ethernet frame，返回 IPv4/IPv6 payload。
fn ethernet_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 14 {
        return None;
    }

    let mut offset = 14;
    let mut ethertype = u16::from_be_bytes([packet[12], packet[13]]);

    // 处理一层 VLAN tag。多层 QinQ 以后再扩展。
    if ethertype == 0x8100 || ethertype == 0x88a8 {
        if packet.len() < 18 {
            return None;
        }

        offset = 18;
        ethertype = u16::from_be_bytes([packet[16], packet[17]]);
    }

    match ethertype {
        0x0800 | 0x86dd => Some(&packet[offset..]),
        _ => None,
    }
}

/// 解析 BSD/macOS loopback header，返回其后的 IP packet。
fn loopback_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 5 {
        return None;
    }

    Some(&packet[4..])
}

/// 根据 IP version 分发到 IPv4 或 IPv6 TCP 解析。
fn parse_ip_packet(
    packet: &[u8],
    payload_limit: Option<usize>,
) -> Option<(FlowKey, TcpSegmentMeta, Option<Payload>)> {
    match packet.first()? >> 4 {
        4 => parse_ipv4_tcp_packet(packet, payload_limit),
        6 => parse_ipv6_tcp_packet(packet, payload_limit),
        _ => None,
    }
}

/// 解析 IPv4 packet 中的 TCP segment。
fn parse_ipv4_tcp_packet(
    packet: &[u8],
    payload_limit: Option<usize>,
) -> Option<(FlowKey, TcpSegmentMeta, Option<Payload>)> {
    if packet.len() < 20 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len || packet[9] != 6 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]])).min(packet.len());
    if total_len < header_len {
        return None;
    }

    let source = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));

    parse_tcp_segment(
        &packet[header_len..total_len],
        source,
        destination,
        payload_limit,
    )
}

/// 解析不带扩展头的 IPv6 TCP packet。
///
/// IPv6 extension header 需要单独 walker；当前版本先跳过，避免误解析。
fn parse_ipv6_tcp_packet(
    packet: &[u8],
    payload_limit: Option<usize>,
) -> Option<(FlowKey, TcpSegmentMeta, Option<Payload>)> {
    if packet.len() < 40 || packet[6] != 6 {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = (40 + payload_len).min(packet.len());
    if total_len < 40 {
        return None;
    }

    let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
    let destination = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));

    parse_tcp_segment(&packet[40..total_len], source, destination, payload_limit)
}

/// 从 TCP segment 中提取 flow 和 payload。
fn parse_tcp_segment(
    segment: &[u8],
    source_address: IpAddr,
    destination_address: IpAddr,
    payload_limit: Option<usize>,
) -> Option<(FlowKey, TcpSegmentMeta, Option<Payload>)> {
    if segment.len() < 20 {
        return None;
    }

    let source_port = u16::from_be_bytes([segment[0], segment[1]]);
    let destination_port = u16::from_be_bytes([segment[2], segment[3]]);
    let header_len = usize::from(segment[12] >> 4) * 4;
    if header_len < 20 || segment.len() < header_len {
        return None;
    }

    let payload = &segment[header_len..];
    let tcp = TcpSegmentMeta::from_flags_byte(segment[13]);

    Some((
        FlowKey {
            source: Endpoint {
                address: source_address,
                port: source_port,
            },
            destination: Endpoint {
                address: destination_address,
                port: destination_port,
            },
            transport: TransportProtocol::Tcp,
        },
        tcp,
        (!payload.is_empty()).then(|| Payload::from_bytes(payload, payload_limit)),
    ))
}

/// 将 pcap timeval 转成 Unix epoch 毫秒。
fn packet_timestamp_millis(header: &pcap::PacketHeader) -> u64 {
    let seconds = u64::try_from(header.ts.tv_sec).unwrap_or(0);
    let micros = u64::try_from(header.ts.tv_usec).unwrap_or(0);

    seconds.saturating_mul(1_000) + micros / 1_000
}

/// 当前系统时间，作为 synthetic event 的时间戳。
fn current_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_packet() {
        let packet = [
            0x45, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00, 192, 168, 0, 1, 192,
            168, 0, 2, 0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x50, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o',
        ];

        let (flow, tcp, payload) = parse_ip_packet(&packet, None).unwrap();

        assert_eq!(flow.source.port, 12_345);
        assert_eq!(flow.destination.port, 80);
        assert!(tcp.psh);
        assert!(tcp.ack);
        assert_eq!(payload.unwrap().preview.as_deref(), Some("hello"));
    }

    #[test]
    fn skips_non_tcp_ipv4_packet() {
        let packet = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00, 192, 168, 0, 1,
            192, 168, 0, 2,
        ];

        assert!(parse_ip_packet(&packet, None).is_none());
    }
}
