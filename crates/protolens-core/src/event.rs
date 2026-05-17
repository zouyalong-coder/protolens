use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// 事件时间戳，统一使用 Unix epoch 毫秒。
pub type TimestampMillis = u64;

/// ProtoLens 当前识别的传输层协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol, including QUIC/HTTP3 traffic.
    Udp,
}

/// 带端口的网络端点。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// IP 地址，支持 IPv4 和 IPv6。
    pub address: IpAddr,
    /// 传输层端口。
    pub port: u16,
}

/// 传输层 flow 标识。
///
/// 这里保留方向性，source/destination 表示当前 packet 的方向；后续 session
/// tracking 可以在更高层做双向归一化。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    /// 当前 packet 的源端点。
    pub source: Endpoint,
    /// 当前 packet 的目标端点。
    pub destination: Endpoint,
    /// 传输层协议。
    pub transport: TransportProtocol,
}

/// 从 DNS 响应中学习到的域名到地址映射。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResolution {
    /// 查询或响应中的域名。
    pub hostname: String,
    /// DNS A/AAAA 记录解析出的地址。
    pub address: IpAddr,
    /// DNS 响应 TTL，单位秒。
    pub ttl_seconds: u32,
}

/// TCP segment 元信息。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpSegmentMeta {
    /// TCP sequence number.
    pub sequence_number: u32,
    /// TCP acknowledgment number.
    pub acknowledgment_number: u32,
    /// FIN flag。
    pub fin: bool,
    /// SYN flag。
    pub syn: bool,
    /// RST flag。
    pub rst: bool,
    /// PSH flag。
    pub psh: bool,
    /// ACK flag。
    pub ack: bool,
    /// URG flag。
    pub urg: bool,
}

/// Link layer metadata extracted from the captured frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkLayerMeta {
    /// Capture link-layer medium, for example `ethernet` or `loopback`.
    pub medium: String,
    /// Encapsulated protocol carried by the link layer, when known.
    pub protocol: Option<String>,
    /// Link-layer header length in bytes.
    pub header_len: usize,
    /// Captured frame length in bytes.
    pub frame_len: usize,
}

/// Network layer metadata extracted from the packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkLayerMeta {
    /// Network-layer protocol, currently `ipv4` or `ipv6`.
    pub protocol: String,
    /// IP header length in bytes.
    pub header_len: usize,
    /// IP packet length in bytes.
    pub packet_len: usize,
    /// IPv4 TTL or IPv6 hop limit.
    pub hop_limit: Option<u8>,
}

/// Transport layer metadata extracted from the segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportLayerMeta {
    /// Transport protocol.
    pub protocol: TransportProtocol,
    /// Transport header length in bytes.
    pub header_len: usize,
    /// Transport segment length in bytes.
    pub segment_len: usize,
}

/// Per-packet display metadata grouped by protocol layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketMeta {
    /// Layer 2 metadata.
    pub link: LinkLayerMeta,
    /// Layer 3 metadata.
    pub network: NetworkLayerMeta,
    /// Layer 4 metadata.
    pub transport: TransportLayerMeta,
}

impl TcpSegmentMeta {
    /// 从 TCP header flags byte 创建元信息。
    pub fn from_header(sequence_number: u32, acknowledgment_number: u32, flags: u8) -> Self {
        Self {
            sequence_number,
            acknowledgment_number,
            fin: flags & 0x01 != 0,
            syn: flags & 0x02 != 0,
            rst: flags & 0x04 != 0,
            psh: flags & 0x08 != 0,
            ack: flags & 0x10 != 0,
            urg: flags & 0x20 != 0,
        }
    }
}

/// session 内部的字节方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// 客户端到服务端。
    ClientToServer,
    /// 服务端到客户端。
    ServerToClient,
    /// 尚未建立 session 方向判断时使用。
    Unknown,
}

/// payload 在结构化事件里的编码方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncoding {
    /// bytes 统一用 base64 保存，避免非 UTF-8 数据丢失。
    Base64,
}

/// 捕获到的原始负载。
///
/// `data` 永远表示 bytes 的编码结果；`preview` 只是可读文本辅助展示，不能作为
/// 协议解析的真实输入。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    /// `data` 字段的编码方式。
    pub encoding: PayloadEncoding,
    /// 编码后的 payload 数据。
    pub data: String,
    /// 原始 payload 字节长度。
    pub original_len: usize,
    /// 当前事件是否只保存了前缀数据。
    pub truncated: bool,
    /// UTF-8 可读时提供的展示预览。
    pub preview: Option<String>,
}

impl Payload {
    /// 从原始 bytes 创建结构化 payload。
    ///
    /// `max_len` 用于限制事件体大小；即使截断，`original_len` 也保留真实长度。
    pub fn from_bytes(bytes: &[u8], max_len: Option<usize>) -> Self {
        let limit = max_len.unwrap_or(bytes.len());
        let stored_len = bytes.len().min(limit);
        let stored = &bytes[..stored_len];

        Self {
            encoding: PayloadEncoding::Base64,
            data: base64::engine::general_purpose::STANDARD.encode(stored),
            original_len: bytes.len(),
            truncated: stored_len < bytes.len(),
            preview: std::str::from_utf8(stored).ok().map(ToOwned::to_owned),
        }
    }
}

/// TCP session 结束原因。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    /// 正常关闭。
    Closed,
    /// 超时关闭。
    Timeout,
    /// TCP reset。
    Reset,
    /// 抓包任务停止导致 session 结束。
    CaptureStopped,
    /// 结束原因未知。
    Unknown,
}

/// session 级元信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMeta {
    /// session 唯一标识。
    pub id: String,
    /// session 关联的 flow。
    pub flow: FlowKey,
    /// session 开始时间。
    pub started_at: TimestampMillis,
}

/// ProtoLens pipeline 中传递的统一事件 envelope。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureEvent {
    /// 事件发生时间。
    pub timestamp: TimestampMillis,
    /// 事件来源，例如 `pcap:en0`。
    pub source_id: String,
    /// 具体事件内容。
    pub kind: CaptureEventKind,
}

/// 捕获和分析过程中产生的事件类型。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CaptureEventKind {
    /// 抓包任务开始。
    CaptureStarted {
        /// 抓包模式，例如 `pcap`、未来的 `proxy` 或 `tun`。
        mode: String,
    },
    /// 网卡级 packet 事件。
    InterfacePacket {
        /// Layered packet metadata for display and analysis.
        packet: Option<PacketMeta>,
        /// 能解析出传输层信息时携带 flow。
        flow: Option<FlowKey>,
        /// TCP segment metadata；非 TCP packet 为空。
        tcp: Option<TcpSegmentMeta>,
        /// packet 中的 transport payload；纯 ACK 等无负载 packet 为空。
        payload: Option<Payload>,
    },
    /// pcap did receive a raw frame, but ProtoLens could not parse it into a
    /// supported packet event.
    UnsupportedPacket {
        /// Capture link-layer type reported by libpcap/Npcap.
        link_type: String,
        /// Captured frame length in bytes.
        frame_len: usize,
        /// Short reason for the parser skip.
        reason: String,
    },
    /// 从 DNS 响应包中提取出的解析结果。
    DnsResolved {
        /// 本次 DNS 响应中可用于展示的地址映射。
        resolutions: Vec<DnsResolution>,
    },
    /// TCP session 开始。
    TcpSessionStarted {
        /// 新 session 的元信息。
        session: SessionMeta,
    },
    /// TCP session 内的字节数据。
    TcpBytes {
        /// session 唯一标识。
        session_id: String,
        /// 字节方向。
        direction: Direction,
        /// 数据负载。
        payload: Payload,
    },
    /// TCP session 结束。
    TcpSessionEnded {
        /// session 唯一标识。
        session_id: String,
        /// 结束原因。
        reason: SessionEndReason,
    },
    /// 协议分析器输出的高层观察结果。
    ProtocolObservation {
        /// 分析器标识。
        analyzer_id: String,
        /// 关联 session；非 session 级观察可以为空。
        session_id: Option<String>,
        /// 面向人类的摘要。
        summary: String,
        /// 机器可读的扩展信息。
        metadata: serde_json::Value,
    },
    /// pipeline 内部错误事件。
    Error {
        /// 错误描述。
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_preserves_binary_as_base64() {
        let payload = Payload::from_bytes(&[0, 159, 146, 150], None);

        assert_eq!(payload.encoding, PayloadEncoding::Base64);
        assert_eq!(payload.data, "AJ+Slg==");
        assert_eq!(payload.original_len, 4);
        assert!(!payload.truncated);
        assert_eq!(payload.preview, None);
    }

    #[test]
    fn payload_can_be_truncated() {
        let payload = Payload::from_bytes(b"hello", Some(2));

        assert_eq!(payload.data, "aGU=");
        assert_eq!(payload.original_len, 5);
        assert!(payload.truncated);
        assert_eq!(payload.preview.as_deref(), Some("he"));
    }
}
