//! 抓包后端和内置 packet source。
//!
//! 当前 crate 先提供 pcap 网卡抓包能力，并把 packet 归一化成 core crate
//! 定义的 `CaptureEvent`。后续显式代理、TUN、文件回放也应该放在这一层。

use pcap::{Active, Capture, Linktype, Offline, Savefile};
use protolens_core::{
    CaptureEvent, CaptureEventKind, DnsResolution, Endpoint, Error, FlowKey, LinkLayerMeta,
    NetworkLayerMeta, PacketMeta, PacketSource, Payload, Result, TcpSegmentMeta,
    TransportLayerMeta, TransportProtocol,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// pcap 抓包源配置。
pub struct PcapSourceConfig {
    /// 要打开的网卡名。
    pub interface: String,
    /// BPF filter，例如 `tcp`、`tcp port 443` 或 `tcp or udp port 53`。
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
    /// 可选 pcap 文件输出路径，用于 Wireshark 等工具离线打开。
    pub output_path: Option<PathBuf>,
}

impl Default for PcapSourceConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            filter: Some("tcp or udp port 53".to_owned()),
            snaplen: 65_535,
            immediate_mode: true,
            promiscuous: false,
            read_timeout_ms: 1_000,
            payload_limit: Some(65_535),
            output_path: None,
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
    /// 可选 pcap savefile。保存的是原始链路层 packet，不受 payload_limit 影响。
    savefile: Option<Savefile>,
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
        let savefile = match &config.output_path {
            Some(path) => Some(
                capture
                    .savefile(path)
                    .map_err(map_pcap_error("failed to create pcap output file"))?,
            ),
            None => None,
        };

        Ok(Self {
            id: format!("pcap:{}", config.interface),
            capture,
            linktype,
            emitted_started: false,
            payload_limit: config.payload_limit,
            savefile,
        })
    }
}

pub struct PcapFileSource {
    /// 事件来源标识。
    id: String,
    /// 离线 pcap capture handle。
    capture: Capture<Offline>,
    /// pcap 文件中的链路层类型。
    linktype: Linktype,
    /// 用于确保只发送一次 `capture_started`。
    emitted_started: bool,
    /// payload 截断限制。
    payload_limit: Option<usize>,
}

impl PcapFileSource {
    /// 打开一个 pcap 文件作为离线回放源。
    pub fn new(path: PathBuf, payload_limit: Option<usize>) -> Result<Self> {
        let capture =
            Capture::from_file(&path).map_err(map_pcap_error("failed to open pcap file"))?;
        let linktype = capture.get_datalink();

        Ok(Self {
            id: format!("pcap-file:{}", path.display()),
            capture,
            linktype,
            emitted_started: false,
            payload_limit,
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

            if let Some(savefile) = self.savefile.as_mut() {
                savefile.write(&packet);
            }

            return Ok(Some(event_from_packet(
                self.linktype,
                packet_timestamp_millis(packet.header),
                &self.id,
                packet.data,
                self.payload_limit,
            )));
        }
    }
}

impl Drop for PcapSource {
    fn drop(&mut self) {
        if let Some(savefile) = self.savefile.as_mut() {
            let _ = savefile.flush();
        }
    }
}

impl PacketSource for PcapFileSource {
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
                    mode: "pcap_file".to_owned(),
                },
            }));
        }

        loop {
            let packet = match self.capture.next_packet() {
                Ok(packet) => packet,
                Err(pcap::Error::NoMorePackets) => return Ok(None),
                Err(error) => return Err(map_pcap_error("failed to read pcap file packet")(error)),
            };

            return Ok(Some(event_from_packet(
                self.linktype,
                packet_timestamp_millis(packet.header),
                &self.id,
                packet.data,
                self.payload_limit,
            )));
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

/// 从原始 pcap packet 生成 ProtoLens 事件。
fn event_from_packet(
    linktype: Linktype,
    timestamp: u64,
    source_id: &str,
    packet: &[u8],
    payload_limit: Option<usize>,
) -> CaptureEvent {
    // DNS 响应用于维护 IP -> 域名展示缓存，TCP packet 仍然是主要输出事件。
    let dns_resolutions = parse_dns_resolutions(linktype, packet);
    if !dns_resolutions.is_empty() {
        return CaptureEvent {
            timestamp,
            source_id: source_id.to_owned(),
            kind: CaptureEventKind::DnsResolved {
                resolutions: dns_resolutions,
            },
        };
    }

    if let Some(parsed) = parse_tcp_packet(linktype, packet, payload_limit) {
        return CaptureEvent {
            timestamp,
            source_id: source_id.to_owned(),
            kind: CaptureEventKind::InterfacePacket {
                packet: Some(parsed.meta),
                flow: Some(parsed.flow),
                tcp: parsed.tcp,
                payload: parsed.payload,
            },
        };
    }

    CaptureEvent {
        timestamp,
        source_id: source_id.to_owned(),
        kind: CaptureEventKind::UnsupportedPacket {
            link_type: format!("{linktype:?}"),
            frame_len: packet.len(),
            reason: unsupported_packet_reason(linktype, packet),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTcpPacket {
    flow: FlowKey,
    tcp: Option<TcpSegmentMeta>,
    payload: Option<Payload>,
    meta: PacketMeta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IpPacketView<'a> {
    packet: &'a [u8],
    link: LinkLayerMeta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedIpPacket {
    flow: FlowKey,
    tcp: Option<TcpSegmentMeta>,
    payload: Option<Payload>,
    network: NetworkLayerMeta,
    transport: TransportLayerMeta,
}

/// 根据链路层类型剥离链路层头，并尝试解析 TCP packet。
fn parse_tcp_packet(
    linktype: Linktype,
    packet: &[u8],
    payload_limit: Option<usize>,
) -> Option<ParsedTcpPacket> {
    let view = ip_packet_view(linktype, packet)?;
    let parsed = parse_ip_packet(view.packet, payload_limit)?;

    Some(ParsedTcpPacket {
        flow: parsed.flow,
        tcp: parsed.tcp,
        payload: parsed.payload,
        meta: PacketMeta {
            link: view.link,
            network: parsed.network,
            transport: parsed.transport,
        },
    })
}

fn unsupported_packet_reason(linktype: Linktype, packet: &[u8]) -> String {
    let Some(view) = ip_packet_view(linktype, packet) else {
        return format!("unsupported link type {linktype:?} or link-layer frame");
    };

    match view.packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            if view.packet.len() < 20 {
                return "truncated ipv4 packet".to_owned();
            }
            let protocol = view.packet[9];
            format!("unsupported ipv4 transport protocol {protocol}")
        }
        Some(6) => {
            if view.packet.len() < 40 {
                return "truncated ipv6 packet".to_owned();
            }
            let protocol = view.packet[6];
            format!("unsupported ipv6 next header {protocol}")
        }
        _ => "unsupported network packet".to_owned(),
    }
}

/// 根据链路层类型剥离链路层头，并尝试解析 DNS 响应里的 A/AAAA 记录。
fn parse_dns_resolutions(linktype: Linktype, packet: &[u8]) -> Vec<DnsResolution> {
    let Some(ip_packet) = (match linktype {
        Linktype::ETHERNET => ethernet_payload(packet).map(|view| view.packet),
        Linktype::IPV4 | Linktype::IPV6 | Linktype::RAW => Some(packet),
        Linktype::NULL | Linktype::LOOP => loopback_payload(packet).map(|view| view.packet),
        _ => None,
    }) else {
        return Vec::new();
    };

    parse_dns_resolutions_from_ip(ip_packet)
}

fn parse_dns_resolutions_from_ip(packet: &[u8]) -> Vec<DnsResolution> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => parse_ipv4_udp_dns(packet),
        Some(6) => parse_ipv6_udp_dns(packet),
        _ => Vec::new(),
    }
}

fn parse_ipv4_udp_dns(packet: &[u8]) -> Vec<DnsResolution> {
    if packet.len() < 20 {
        return Vec::new();
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len || packet[9] != 17 {
        return Vec::new();
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]])).min(packet.len());
    if total_len < header_len {
        return Vec::new();
    }

    parse_udp_dns_datagram(&packet[header_len..total_len])
}

/// 解析不带扩展头的 IPv6 UDP DNS packet。
fn parse_ipv6_udp_dns(packet: &[u8]) -> Vec<DnsResolution> {
    if packet.len() < 40 || packet[6] != 17 {
        return Vec::new();
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = (40 + payload_len).min(packet.len());
    if total_len < 40 {
        return Vec::new();
    }

    parse_udp_dns_datagram(&packet[40..total_len])
}

fn parse_udp_dns_datagram(datagram: &[u8]) -> Vec<DnsResolution> {
    if datagram.len() < 8 {
        return Vec::new();
    }

    let source_port = u16::from_be_bytes([datagram[0], datagram[1]]);
    let destination_port = u16::from_be_bytes([datagram[2], datagram[3]]);
    if source_port != 53 && destination_port != 53 {
        return Vec::new();
    }

    let udp_len = usize::from(u16::from_be_bytes([datagram[4], datagram[5]])).min(datagram.len());
    if udp_len < 8 {
        return Vec::new();
    }

    parse_dns_message(&datagram[8..udp_len])
}

fn parse_dns_message(message: &[u8]) -> Vec<DnsResolution> {
    if message.len() < 12 {
        return Vec::new();
    }

    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 {
        return Vec::new();
    }

    let question_count = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let answer_count = usize::from(u16::from_be_bytes([message[6], message[7]]));
    let mut offset = 12;

    for _ in 0..question_count {
        if read_dns_name(message, &mut offset).is_none() || message.len() < offset + 4 {
            return Vec::new();
        }
        offset += 4;
    }

    let mut resolutions = Vec::new();
    for _ in 0..answer_count {
        let Some(hostname) = read_dns_name(message, &mut offset) else {
            return resolutions;
        };
        if message.len() < offset + 10 {
            return resolutions;
        }

        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        let ttl_seconds = u32::from_be_bytes([
            message[offset + 4],
            message[offset + 5],
            message[offset + 6],
            message[offset + 7],
        ]);
        let data_len = usize::from(u16::from_be_bytes([
            message[offset + 8],
            message[offset + 9],
        ]));
        offset += 10;

        if message.len() < offset + data_len {
            return resolutions;
        }

        let data = &message[offset..offset + data_len];
        let address = match (record_type, class, data_len) {
            (1, 1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            (28, 1, 16) => Some(IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(data).expect("checked AAAA record length"),
            ))),
            _ => None,
        };

        if let Some(address) = address {
            resolutions.push(DnsResolution {
                hostname,
                address,
                ttl_seconds,
            });
        }

        offset += data_len;
    }

    resolutions
}

fn read_dns_name(message: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut cursor = *offset;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        let length = *message.get(cursor)?;
        if length & 0xc0 == 0xc0 {
            let next = *message.get(cursor + 1)?;
            let pointer = usize::from(u16::from_be_bytes([length & 0x3f, next]));
            if pointer >= message.len() || jumps > 16 {
                return None;
            }
            if !jumped {
                *offset = cursor + 2;
                jumped = true;
            }
            cursor = pointer;
            jumps += 1;
            continue;
        }

        if length & 0xc0 != 0 {
            return None;
        }

        cursor += 1;
        if length == 0 {
            if !jumped {
                *offset = cursor;
            }
            break;
        }

        let end = cursor + usize::from(length);
        if end > message.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&message[cursor..end])
                .ok()?
                .to_ascii_lowercase(),
        );
        cursor = end;
    }

    (!labels.is_empty()).then(|| labels.join("."))
}

/// 解析 Ethernet frame，返回 IPv4/IPv6 payload 和二层元数据。
fn ethernet_payload(packet: &[u8]) -> Option<IpPacketView<'_>> {
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

    let protocol = ethertype_name(ethertype)?;
    Some(IpPacketView {
        packet: &packet[offset..],
        link: LinkLayerMeta {
            medium: "ethernet".to_owned(),
            protocol: Some(protocol.to_owned()),
            header_len: offset,
            frame_len: packet.len(),
        },
    })
}

fn ethertype_name(ethertype: u16) -> Option<&'static str> {
    match ethertype {
        0x0800 => Some("ipv4"),
        0x86dd => Some("ipv6"),
        _ => None,
    }
}

/// 解析 BSD/macOS loopback header，返回其后的 IP packet 和二层元数据。
fn loopback_payload(packet: &[u8]) -> Option<IpPacketView<'_>> {
    if packet.len() < 5 {
        return None;
    }

    let protocol = match packet[4] >> 4 {
        4 => "ipv4",
        6 => "ipv6",
        _ => return None,
    };

    Some(IpPacketView {
        packet: &packet[4..],
        link: LinkLayerMeta {
            medium: "loopback".to_owned(),
            protocol: Some(protocol.to_owned()),
            header_len: 4,
            frame_len: packet.len(),
        },
    })
}

fn ip_packet_view(linktype: Linktype, packet: &[u8]) -> Option<IpPacketView<'_>> {
    match linktype {
        Linktype::ETHERNET => ethernet_payload(packet),
        Linktype::IPV4 | Linktype::IPV6 | Linktype::RAW => Some(IpPacketView {
            packet,
            link: LinkLayerMeta {
                medium: "raw".to_owned(),
                protocol: packet.first().and_then(|byte| match byte >> 4 {
                    4 => Some("ipv4".to_owned()),
                    6 => Some("ipv6".to_owned()),
                    _ => None,
                }),
                header_len: 0,
                frame_len: packet.len(),
            },
        }),
        Linktype::NULL | Linktype::LOOP => loopback_payload(packet),
        _ => None,
    }
}

/// 根据 IP version 分发到 IPv4 或 IPv6 TCP 解析。
fn parse_ip_packet(packet: &[u8], payload_limit: Option<usize>) -> Option<ParsedIpPacket> {
    match packet.first()? >> 4 {
        4 => parse_ipv4_tcp_packet(packet, payload_limit),
        6 => parse_ipv6_tcp_packet(packet, payload_limit),
        _ => None,
    }
}

/// 解析 IPv4 packet 中的 TCP segment 或 UDP datagram。
fn parse_ipv4_tcp_packet(packet: &[u8], payload_limit: Option<usize>) -> Option<ParsedIpPacket> {
    if packet.len() < 20 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
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

    let mut parsed = match packet[9] {
        6 => parse_tcp_segment(
            &packet[header_len..total_len],
            source,
            destination,
            payload_limit,
        )?,
        17 => parse_udp_datagram(
            &packet[header_len..total_len],
            source,
            destination,
            payload_limit,
        )?,
        _ => return None,
    };
    parsed.network = NetworkLayerMeta {
        protocol: "ipv4".to_owned(),
        header_len,
        packet_len: total_len,
        hop_limit: Some(packet[8]),
    };
    Some(parsed)
}

/// 解析不带扩展头的 IPv6 TCP packet 或 UDP datagram。
///
/// IPv6 extension header 需要单独 walker；当前版本先跳过，避免误解析。
fn parse_ipv6_tcp_packet(packet: &[u8], payload_limit: Option<usize>) -> Option<ParsedIpPacket> {
    if packet.len() < 40 {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = (40 + payload_len).min(packet.len());
    if total_len < 40 {
        return None;
    }

    let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
    let destination = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));

    let mut parsed = match packet[6] {
        6 => parse_tcp_segment(&packet[40..total_len], source, destination, payload_limit)?,
        17 => parse_udp_datagram(&packet[40..total_len], source, destination, payload_limit)?,
        _ => return None,
    };
    parsed.network = NetworkLayerMeta {
        protocol: "ipv6".to_owned(),
        header_len: 40,
        packet_len: total_len,
        hop_limit: Some(packet[7]),
    };
    Some(parsed)
}

/// 从 TCP segment 中提取 flow 和 payload。
fn parse_tcp_segment(
    segment: &[u8],
    source_address: IpAddr,
    destination_address: IpAddr,
    payload_limit: Option<usize>,
) -> Option<ParsedIpPacket> {
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
    let tcp = TcpSegmentMeta::from_header(
        u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]),
        u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]),
        segment[13],
    );

    Some(ParsedIpPacket {
        flow: FlowKey {
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
        tcp: Some(tcp),
        payload: (!payload.is_empty()).then(|| Payload::from_bytes(payload, payload_limit)),
        network: NetworkLayerMeta {
            protocol: "unknown".to_owned(),
            header_len: 0,
            packet_len: 0,
            hop_limit: None,
        },
        transport: TransportLayerMeta {
            protocol: TransportProtocol::Tcp,
            header_len,
            segment_len: segment.len(),
        },
    })
}

/// 从 UDP datagram 中提取 flow 和 payload。
fn parse_udp_datagram(
    datagram: &[u8],
    source_address: IpAddr,
    destination_address: IpAddr,
    payload_limit: Option<usize>,
) -> Option<ParsedIpPacket> {
    if datagram.len() < 8 {
        return None;
    }

    let source_port = u16::from_be_bytes([datagram[0], datagram[1]]);
    let destination_port = u16::from_be_bytes([datagram[2], datagram[3]]);
    let datagram_len =
        usize::from(u16::from_be_bytes([datagram[4], datagram[5]])).min(datagram.len());
    if datagram_len < 8 {
        return None;
    }

    let payload = &datagram[8..datagram_len];
    Some(ParsedIpPacket {
        flow: FlowKey {
            source: Endpoint {
                address: source_address,
                port: source_port,
            },
            destination: Endpoint {
                address: destination_address,
                port: destination_port,
            },
            transport: TransportProtocol::Udp,
        },
        tcp: None,
        payload: (!payload.is_empty()).then(|| Payload::from_bytes(payload, payload_limit)),
        network: NetworkLayerMeta {
            protocol: "unknown".to_owned(),
            header_len: 0,
            packet_len: 0,
            hop_limit: None,
        },
        transport: TransportLayerMeta {
            protocol: TransportProtocol::Udp,
            header_len: 8,
            segment_len: datagram_len,
        },
    })
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

        let parsed = parse_ip_packet(&packet, None).unwrap();

        assert_eq!(parsed.flow.source.port, 12_345);
        assert_eq!(parsed.flow.destination.port, 80);
        let tcp = parsed.tcp.unwrap();
        assert!(tcp.psh);
        assert!(tcp.ack);
        assert_eq!(parsed.payload.unwrap().preview.as_deref(), Some("hello"));
        assert_eq!(parsed.network.protocol, "ipv4");
        assert_eq!(parsed.network.header_len, 20);
        assert_eq!(parsed.transport.header_len, 20);
    }

    #[test]
    fn parses_ipv4_udp_packet() {
        let packet = [
            0x45, 0x00, 0x00, 0x21, 0x00, 0x00, 0x40, 0x00, 64, 17, 0x00, 0x00, 192, 168, 0, 1,
            192, 168, 0, 2, 0x30, 0x39, 0x01, 0xbb, 0x00, 0x0d, 0x00, 0x00, b'h', b'e', b'l', b'l',
            b'o',
        ];

        let parsed = parse_ip_packet(&packet, None).unwrap();

        assert_eq!(parsed.flow.source.port, 12_345);
        assert_eq!(parsed.flow.destination.port, 443);
        assert_eq!(parsed.flow.transport, TransportProtocol::Udp);
        assert!(parsed.tcp.is_none());
        assert_eq!(parsed.payload.unwrap().preview.as_deref(), Some("hello"));
        assert_eq!(parsed.transport.header_len, 8);
    }

    #[test]
    fn skips_unknown_ipv4_transport_packet() {
        let packet = [
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 64, 1, 0x00, 0x00, 192, 168, 0, 1, 192,
            168, 0, 2,
        ];

        assert!(parse_ip_packet(&packet, None).is_none());
    }

    #[test]
    fn parses_dns_a_response() {
        let message = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184,
            216, 34,
        ];

        let resolutions = parse_dns_message(&message);

        assert_eq!(resolutions.len(), 1);
        assert_eq!(resolutions[0].hostname, "example.com");
        assert_eq!(
            resolutions[0].address,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(resolutions[0].ttl_seconds, 60);
    }
}
