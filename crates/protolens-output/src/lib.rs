//! 事件输出 sink。
//!
//! 输出层只消费 `CaptureEvent`，不关心事件来自 pcap、代理还是 TUN。这样 CLI、
//! JSON Lines、未来桌面 UI 都可以复用同一套事件模型。

use protolens_core::{
    CaptureEvent, CaptureEventKind, Endpoint, EventSink, FlowKey, Payload, Result, TcpSegmentMeta,
};
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;

/// 面向终端的可读格式化输出 sink。
///
/// `W` 只要求实现 `Write`，因此既可以写 stdout，也可以在测试中写入内存 buffer。
pub struct FormattedEventSink<W> {
    /// 底层输出目标。
    writer: W,
    /// sink 标识。
    id: String,
    /// 从 DNS 响应中学习到的 IP -> 域名缓存。
    dns_names: HashMap<IpAddr, String>,
}

impl<W> FormattedEventSink<W> {
    /// 创建格式化输出 sink。
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            id: "formatted".to_owned(),
            dns_names: HashMap::new(),
        }
    }
}

impl<W: Write> EventSink for FormattedEventSink<W> {
    fn id(&self) -> &str {
        &self.id
    }

    fn write(&mut self, event: &CaptureEvent) -> Result<()> {
        match &event.kind {
            CaptureEventKind::CaptureStarted { mode } => {
                writeln!(
                    self.writer,
                    "[{}] capture started mode={mode}",
                    event.timestamp
                )?;
            }
            CaptureEventKind::InterfacePacket {
                flow, tcp, payload, ..
            } => {
                write!(self.writer, "[{}] packet", event.timestamp)?;

                if let Some(flow) = flow {
                    write!(self.writer, " {}", format_flow(flow, &self.dns_names))?;
                }

                if let Some(tcp) = tcp {
                    write!(self.writer, " flags={}", format_tcp_flags(tcp))?;
                }

                if let Some(payload) = payload {
                    write!(self.writer, " payload={}", format_payload(payload))?;
                } else {
                    write!(self.writer, " payload=none")?;
                }

                writeln!(self.writer)?;
            }
            CaptureEventKind::DnsResolved { resolutions } => {
                for resolution in resolutions {
                    self.dns_names
                        .insert(resolution.address, resolution.hostname.clone());
                    writeln!(
                        self.writer,
                        "[{}] dns {} -> {} ttl={}s",
                        event.timestamp,
                        resolution.hostname,
                        resolution.address,
                        resolution.ttl_seconds
                    )?;
                }
            }
            CaptureEventKind::UnsupportedPacket {
                link_type,
                frame_len,
                reason,
            } => {
                writeln!(
                    self.writer,
                    "[{}] unsupported packet link_type={} frame={}B reason={}",
                    event.timestamp, link_type, frame_len, reason
                )?;
            }
            CaptureEventKind::TcpSessionStarted { session } => {
                writeln!(
                    self.writer,
                    "[{}] tcp session started id={} {}",
                    event.timestamp,
                    session.id,
                    format_flow(&session.flow, &self.dns_names)
                )?;
            }
            CaptureEventKind::TcpBytes {
                session_id,
                direction,
                payload,
            } => {
                writeln!(
                    self.writer,
                    "[{}] tcp bytes session={} direction={direction:?} payload={}",
                    event.timestamp,
                    session_id,
                    format_payload(payload)
                )?;
            }
            CaptureEventKind::TcpSessionEnded { session_id, reason } => {
                writeln!(
                    self.writer,
                    "[{}] tcp session ended id={} reason={reason:?}",
                    event.timestamp, session_id
                )?;
            }
            CaptureEventKind::ProtocolObservation {
                analyzer_id,
                session_id,
                summary,
                ..
            } => {
                writeln!(
                    self.writer,
                    "[{}] observation analyzer={} session={} {}",
                    event.timestamp,
                    analyzer_id,
                    session_id.as_deref().unwrap_or("none"),
                    summary
                )?;
            }
            CaptureEventKind::Error { message } => {
                writeln!(self.writer, "[{}] error {message}", event.timestamp)?;
            }
        }

        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

/// 按双向 TCP 链路聚合的终端显示 sink。
///
/// 这个 sink 面向“我想看完整通信链路”的场景：它把方向相反但端点相同的 packet
/// 合并为一条 link，并只展示建连、数据传输和断开阶段。
pub struct LinkEventSink<W> {
    /// 底层输出目标。
    writer: W,
    /// sink 标识。
    id: String,
    /// 已观察到的链路状态。
    links: HashMap<LinkKey, LinkState>,
    /// 下一个展示用 link id。
    next_link_id: usize,
    /// 端点过滤条件；为空表示输出所有 link。
    endpoint_filters: Vec<String>,
    /// 从 DNS 响应中学习到的 IP -> 域名缓存。
    dns_names: HashMap<IpAddr, String>,
}

impl<W> LinkEventSink<W> {
    /// 创建链路聚合输出 sink。
    pub fn new(writer: W) -> Self {
        Self::new_with_filters(writer, Vec::new())
    }

    /// 创建带端点过滤的链路聚合输出 sink。
    pub fn new_with_filters(writer: W, endpoint_filters: Vec<String>) -> Self {
        Self {
            writer,
            id: "links".to_owned(),
            links: HashMap::new(),
            next_link_id: 1,
            endpoint_filters,
            dns_names: HashMap::new(),
        }
    }
}

impl<W: Write> EventSink for LinkEventSink<W> {
    fn id(&self) -> &str {
        &self.id
    }

    fn write(&mut self, event: &CaptureEvent) -> Result<()> {
        let (flow, tcp, payload) = match &event.kind {
            CaptureEventKind::DnsResolved { resolutions } => {
                for resolution in resolutions {
                    self.dns_names
                        .insert(resolution.address, resolution.hostname.clone());
                }
                return Ok(());
            }
            CaptureEventKind::InterfacePacket {
                flow: Some(flow),
                tcp: Some(tcp),
                payload,
                ..
            } => (flow, tcp, payload),
            _ => return Ok(()),
        };

        if !self.matches_filters(flow) {
            return Ok(());
        }

        let key = LinkKey::from_flow(flow);
        if !self.links.contains_key(&key) {
            let id = self.next_link_id;
            self.next_link_id += 1;
            self.links.insert(key.clone(), LinkState::new(id, flow));
        }

        let link = self.links.get_mut(&key).expect("link was just inserted");

        if !link.announced {
            writeln!(
                self.writer,
                "[{}] link {} new {} -> {}",
                event.timestamp,
                link.id,
                format_endpoint(&link.client, &self.dns_names),
                format_endpoint(&link.server, &self.dns_names)
            )?;
            link.announced = true;
        }

        let direction = link.direction(flow);

        if tcp.syn && !tcp.ack && !link.seen_syn {
            link.client = flow.source.clone();
            link.server = flow.destination.clone();
            link.seen_syn = true;
            writeln!(
                self.writer,
                "[{}] link {} connect syn {} -> {}",
                event.timestamp,
                link.id,
                format_endpoint(&link.client, &self.dns_names),
                format_endpoint(&link.server, &self.dns_names)
            )?;
        } else if tcp.syn && tcp.ack && !link.seen_syn_ack {
            link.seen_syn_ack = true;
            writeln!(
                self.writer,
                "[{}] link {} connect syn-ack {}",
                event.timestamp,
                link.id,
                direction.label()
            )?;
        } else if tcp.ack && link.seen_syn && link.seen_syn_ack && !link.established {
            link.established = true;
            writeln!(
                self.writer,
                "[{}] link {} established",
                event.timestamp, link.id
            )?;
        }

        if let Some(payload) = payload {
            link.add_bytes(direction, payload.original_len);
            writeln!(
                self.writer,
                "[{}] link {} data {} {} total c2s={}B s2c={}B",
                event.timestamp,
                link.id,
                direction.label(),
                format_payload(payload),
                link.client_to_server_bytes,
                link.server_to_client_bytes
            )?;
        }

        if tcp.rst {
            link.closed = true;
            writeln!(
                self.writer,
                "[{}] link {} reset {} total c2s={}B s2c={}B",
                event.timestamp,
                link.id,
                direction.label(),
                link.client_to_server_bytes,
                link.server_to_client_bytes
            )?;
        } else if tcp.fin {
            link.mark_fin(direction);
            writeln!(
                self.writer,
                "[{}] link {} close fin {}",
                event.timestamp,
                link.id,
                direction.label()
            )?;

            if link.client_fin && link.server_fin && !link.closed {
                link.closed = true;
                writeln!(
                    self.writer,
                    "[{}] link {} closed total c2s={}B s2c={}B",
                    event.timestamp,
                    link.id,
                    link.client_to_server_bytes,
                    link.server_to_client_bytes
                )?;
            }
        }

        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

impl<W> LinkEventSink<W> {
    fn matches_filters(&self, flow: &FlowKey) -> bool {
        if self.endpoint_filters.is_empty() {
            return true;
        }

        let source = format_endpoint(&flow.source, &self.dns_names);
        let destination = format_endpoint(&flow.destination, &self.dns_names);
        let link = format!("{source} -> {destination}");

        self.endpoint_filters.iter().any(|filter| {
            source.contains(filter) || destination.contains(filter) || link.contains(filter)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LinkKey {
    first: String,
    second: String,
}

impl LinkKey {
    fn from_flow(flow: &FlowKey) -> Self {
        let source = format_endpoint_key(&flow.source);
        let destination = format_endpoint_key(&flow.destination);

        if source <= destination {
            Self {
                first: source,
                second: destination,
            }
        } else {
            Self {
                first: destination,
                second: source,
            }
        }
    }
}

#[derive(Debug, Clone)]
struct LinkState {
    id: usize,
    client: Endpoint,
    server: Endpoint,
    announced: bool,
    seen_syn: bool,
    seen_syn_ack: bool,
    established: bool,
    client_fin: bool,
    server_fin: bool,
    closed: bool,
    client_to_server_bytes: usize,
    server_to_client_bytes: usize,
}

impl LinkState {
    fn new(id: usize, flow: &FlowKey) -> Self {
        Self {
            id,
            client: flow.source.clone(),
            server: flow.destination.clone(),
            announced: false,
            seen_syn: false,
            seen_syn_ack: false,
            established: false,
            client_fin: false,
            server_fin: false,
            closed: false,
            client_to_server_bytes: 0,
            server_to_client_bytes: 0,
        }
    }

    fn direction(&self, flow: &FlowKey) -> LinkDirection {
        if flow.source == self.client {
            LinkDirection::ClientToServer
        } else {
            LinkDirection::ServerToClient
        }
    }

    fn add_bytes(&mut self, direction: LinkDirection, bytes: usize) {
        match direction {
            LinkDirection::ClientToServer => self.client_to_server_bytes += bytes,
            LinkDirection::ServerToClient => self.server_to_client_bytes += bytes,
        }
    }

    fn mark_fin(&mut self, direction: LinkDirection) {
        match direction {
            LinkDirection::ClientToServer => self.client_fin = true,
            LinkDirection::ServerToClient => self.server_fin = true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum LinkDirection {
    ClientToServer,
    ServerToClient,
}

impl LinkDirection {
    fn label(self) -> &'static str {
        match self {
            LinkDirection::ClientToServer => "c->s",
            LinkDirection::ServerToClient => "s->c",
        }
    }
}

/// 将 flow 格式化成一行可读的五元组信息。
fn format_flow(flow: &FlowKey, dns_names: &HashMap<IpAddr, String>) -> String {
    format!(
        "{} -> {} {:?}",
        format_endpoint(&flow.source, dns_names),
        format_endpoint(&flow.destination, dns_names),
        flow.transport
    )
}

/// 将 TCP flags 格式化为短标签。
fn format_tcp_flags(tcp: &TcpSegmentMeta) -> String {
    let mut flags = Vec::new();

    if tcp.fin {
        flags.push("FIN");
    }
    if tcp.syn {
        flags.push("SYN");
    }
    if tcp.rst {
        flags.push("RST");
    }
    if tcp.psh {
        flags.push("PSH");
    }
    if tcp.ack {
        flags.push("ACK");
    }
    if tcp.urg {
        flags.push("URG");
    }

    if flags.is_empty() {
        "none".to_owned()
    } else {
        flags.join(",")
    }
}

/// 将 endpoint 格式化为稳定 key 和展示文本。
fn format_endpoint(endpoint: &Endpoint, dns_names: &HashMap<IpAddr, String>) -> String {
    if let Some(hostname) = dns_names.get(&endpoint.address) {
        format!("{}({}):{}", hostname, endpoint.address, endpoint.port)
    } else {
        format_endpoint_key(endpoint)
    }
}

fn format_endpoint_key(endpoint: &Endpoint) -> String {
    format!("{}:{}", endpoint.address, endpoint.port)
}

/// 将 payload 格式化成短摘要。
///
/// 注意 `stored` 是 base64 字符串长度，不是原始 bytes 长度；原始长度使用
/// `original_len` 展示。
fn format_payload(payload: &Payload) -> String {
    let preview = payload
        .preview
        .as_ref()
        .map(|preview| format!(" preview={preview:?}"))
        .unwrap_or_default();

    format!(
        "{}B stored={}B truncated={}{}",
        payload.original_len,
        payload.data.len(),
        payload.truncated,
        preview
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use protolens_core::{
        CaptureEventKind, DnsResolution, Endpoint, FlowKey, Payload, TcpSegmentMeta,
        TransportProtocol,
    };
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn formatted_sink_writes_capture_started() {
        let mut output = Vec::new();
        let mut sink = FormattedEventSink::new(&mut output);

        sink.write(&CaptureEvent {
            timestamp: 1,
            source_id: "test".to_owned(),
            kind: CaptureEventKind::CaptureStarted {
                mode: "pcap".to_owned(),
            },
        })
        .unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "[1] capture started mode=pcap\n"
        );
    }

    #[test]
    fn formatted_payload_includes_preview_when_readable() {
        let payload = Payload::from_bytes(b"hello", None);

        assert_eq!(
            format_payload(&payload),
            "5B stored=8B truncated=false preview=\"hello\""
        );
    }

    #[test]
    fn link_sink_groups_bidirectional_tcp_packets() {
        let mut output = Vec::new();
        let mut sink = LinkEventSink::new(&mut output);

        sink.write(&packet_event(
            1,
            flow(12_345, 80),
            TcpSegmentMeta::from_flags_byte(0x02),
            None,
        ))
        .unwrap();
        sink.write(&packet_event(
            2,
            flow(80, 12_345),
            TcpSegmentMeta::from_flags_byte(0x12),
            None,
        ))
        .unwrap();
        sink.write(&packet_event(
            3,
            flow(12_345, 80),
            TcpSegmentMeta::from_flags_byte(0x18),
            Some(Payload::from_bytes(b"GET / HTTP/1.1\r\n", None)),
        ))
        .unwrap();

        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("link 1 new 192.168.0.1:12345 -> 192.168.0.2:80"));
        assert!(output.contains("link 1 connect syn"));
        assert!(output.contains("link 1 connect syn-ack s->c"));
        assert!(output.contains("link 1 established"));
        assert!(output.contains("link 1 data c->s"));
    }

    #[test]
    fn link_sink_filters_by_endpoint_substring() {
        let mut output = Vec::new();
        let mut sink = LinkEventSink::new_with_filters(&mut output, vec![":443".to_owned()]);

        sink.write(&packet_event(
            1,
            flow(12_345, 80),
            TcpSegmentMeta::from_flags_byte(0x02),
            None,
        ))
        .unwrap();
        sink.write(&packet_event(
            2,
            flow(12_345, 443),
            TcpSegmentMeta::from_flags_byte(0x02),
            None,
        ))
        .unwrap();

        let output = String::from_utf8(output).unwrap();

        assert!(!output.contains("192.168.0.2:80"));
        assert!(output.contains("192.168.0.2:443"));
    }

    #[test]
    fn formatted_sink_uses_dns_names_for_later_packets() {
        let mut output = Vec::new();
        let mut sink = FormattedEventSink::new(&mut output);

        sink.write(&CaptureEvent {
            timestamp: 1,
            source_id: "test".to_owned(),
            kind: CaptureEventKind::DnsResolved {
                resolutions: vec![DnsResolution {
                    hostname: "example.com".to_owned(),
                    address: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)),
                    ttl_seconds: 60,
                }],
            },
        })
        .unwrap();
        sink.write(&packet_event(
            2,
            flow(12_345, 443),
            TcpSegmentMeta::from_flags_byte(0x02),
            None,
        ))
        .unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("dns example.com -> 192.168.0.2 ttl=60s"));
        assert!(output.contains("example.com(192.168.0.2):443"));
    }

    fn packet_event(
        timestamp: u64,
        flow: FlowKey,
        tcp: TcpSegmentMeta,
        payload: Option<Payload>,
    ) -> CaptureEvent {
        CaptureEvent {
            timestamp,
            source_id: "test".to_owned(),
            kind: CaptureEventKind::InterfacePacket {
                packet: None,
                flow: Some(flow),
                tcp: Some(tcp),
                payload,
            },
        }
    }

    fn flow(source_port: u16, destination_port: u16) -> FlowKey {
        let client = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let server = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2));
        let (source_address, destination_address) = if source_port == 80 {
            (server, client)
        } else {
            (client, server)
        };

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
        }
    }
}
