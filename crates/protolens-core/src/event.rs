use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub type TimestampMillis = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub source: Endpoint,
    pub destination: Endpoint,
    pub transport: TransportProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadEncoding {
    Base64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    pub encoding: PayloadEncoding,
    pub data: String,
    pub original_len: usize,
    pub truncated: bool,
    pub preview: Option<String>,
}

impl Payload {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    Closed,
    Timeout,
    Reset,
    CaptureStopped,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMeta {
    pub id: String,
    pub flow: FlowKey,
    pub started_at: TimestampMillis,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureEvent {
    pub timestamp: TimestampMillis,
    pub source_id: String,
    pub kind: CaptureEventKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CaptureEventKind {
    CaptureStarted {
        mode: String,
    },
    InterfacePacket {
        flow: Option<FlowKey>,
        payload: Option<Payload>,
    },
    TcpSessionStarted {
        session: SessionMeta,
    },
    TcpBytes {
        session_id: String,
        direction: Direction,
        payload: Payload,
    },
    TcpSessionEnded {
        session_id: String,
        reason: SessionEndReason,
    },
    ProtocolObservation {
        analyzer_id: String,
        session_id: Option<String>,
        summary: String,
        metadata: serde_json::Value,
    },
    Error {
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
