//! 协议分析器注册和内置静态插件。
//!
//! v1 只支持编译期静态注册，避免过早引入动态插件 ABI。后续外部进程或 WASM
//! 插件可以基于这里的注册/调度模型扩展。

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Nonce as AesNonce,
    aead::{Aead, Payload as AeadPayload},
    aes::{
        Aes128, Aes256,
        cipher::{BlockEncrypt, KeyInit as AesKeyInit, generic_array::GenericArray},
    },
};
use base64::Engine;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use protolens_core::{
    AnalysisSink, CaptureEvent, CaptureEventKind, Endpoint, Error, EventProtocolAnalyzer, FlowKey,
    Payload, ProtocolAnalyzer, Result, SessionMeta, TransportProtocol,
};
use sha2::{Sha256, Sha384};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct Http2FrameObservation {
    frame_type: String,
    type_id: u8,
    flags: u8,
    stream_id: u32,
    length: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct QuicPacketObservation {
    header_form: String,
    packet_type: String,
    version: Option<u32>,
    destination_connection_id_len: usize,
    source_connection_id_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum QuicSecretDirection {
    Client,
    Server,
}

#[derive(Debug, Clone)]
struct QuicTrafficSecret {
    direction: QuicSecretDirection,
    secret: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct QuicFrameObservation {
    frame_type: String,
    type_id: u8,
    stream_id: Option<u64>,
    offset: Option<u64>,
    length: Option<usize>,
    fin: Option<bool>,
}

#[derive(Debug, Clone)]
struct QuicFrameParsed {
    observation: QuicFrameObservation,
    stream_data: Option<QuicStreamFrameData>,
}

#[derive(Debug, Clone)]
struct QuicStreamFrameData {
    stream_id: u64,
    offset: u64,
    fin: bool,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct Http3FrameObservation {
    frame_type: String,
    type_id: u64,
    stream_id: u64,
    length: usize,
    headers: Option<Vec<HttpHeaderObservation>>,
    data_preview: Option<String>,
    data_len: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct HttpHeaderObservation {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
struct QuicHeaderProtectionKeys {
    key: Vec<u8>,
    iv: Vec<u8>,
    hp: Vec<u8>,
    cipher: QuicCipher,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicCipher {
    Aes128GcmSha256,
    Aes256GcmSha384,
}

#[derive(Debug, Default)]
struct QuicPluginFlowState {
    left_endpoint: Option<EndpointKey>,
    left_to_right_dcid_len: Option<usize>,
    right_to_left_dcid_len: Option<usize>,
    left_to_right_largest_pn: Option<u64>,
    right_to_left_largest_pn: Option<u64>,
    streams: HashMap<QuicStreamKey, QuicStreamState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct QuicStreamKey {
    direction: TlsDirection,
    stream_id: u64,
}

#[derive(Debug, Default)]
struct QuicStreamState {
    bytes: Vec<u8>,
    parsed_offset: usize,
    kind: Option<QuicStreamKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicStreamKind {
    Request,
    Control,
    Push,
    QpackEncoder,
    QpackDecoder,
    UnknownUni(u64),
}

/// 协议分析器注册表。
pub struct AnalyzerRegistry {
    /// 已注册的静态分析器。
    analyzers: Vec<Box<dyn ProtocolAnalyzer>>,
    /// Event-level static analyzers.
    event_analyzers: Vec<Box<dyn EventProtocolAnalyzer>>,
}

impl AnalyzerRegistry {
    /// 创建空注册表。
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
            event_analyzers: Vec::new(),
        }
    }

    /// 创建带默认内置分析器的注册表。
    pub fn with_default_analyzers() -> Self {
        Self::with_tls_key_log(None)
    }

    /// Create a registry with built-in analyzers and optional key log material.
    pub fn with_tls_key_log(key_log: Option<&TlsKeyLog>) -> Self {
        let mut registry = Self::new();
        registry.register(TcpMetadataAnalyzer);
        registry.register_event(Http2Analyzer);
        registry.register_event(QuicAnalyzer::new(key_log));
        registry
    }

    /// 注册一个静态协议分析器。
    pub fn register(&mut self, analyzer: impl ProtocolAnalyzer + 'static) {
        self.analyzers.push(Box::new(analyzer));
    }

    /// Register an event-level static protocol analyzer.
    pub fn register_event(&mut self, analyzer: impl EventProtocolAnalyzer + 'static) {
        self.event_analyzers.push(Box::new(analyzer));
    }

    /// 返回当前注册的分析器，主要用于测试和诊断。
    pub fn analyzers(&self) -> &[Box<dyn ProtocolAnalyzer>] {
        &self.analyzers
    }

    /// Return event-level analyzers for tests and diagnostics.
    pub fn event_analyzers(&self) -> &[Box<dyn EventProtocolAnalyzer>] {
        &self.event_analyzers
    }

    /// 对一个 session 相关事件运行所有匹配的分析器。
    pub fn analyze(
        &mut self,
        session: &SessionMeta,
        event: &CaptureEvent,
        sink: &mut dyn AnalysisSink,
    ) -> Result<()> {
        for analyzer in &mut self.analyzers {
            if analyzer.supports(session) {
                analyzer.analyze(event, sink)?;
            }
        }

        Ok(())
    }

    /// Run all event-level analyzers for one capture event.
    pub fn analyze_event(
        &mut self,
        event: &CaptureEvent,
        sink: &mut dyn AnalysisSink,
    ) -> Result<()> {
        for analyzer in &mut self.event_analyzers {
            analyzer.analyze(event, sink)?;
        }

        Ok(())
    }
}

impl Default for AnalyzerRegistry {
    fn default() -> Self {
        Self::with_default_analyzers()
    }
}

/// TCP metadata 分析器占位实现。
///
/// 当前只负责证明静态插件机制可用；后续会在这里输出 TCP 握手、字节数、时序等观察。
pub struct TcpMetadataAnalyzer;

impl ProtocolAnalyzer for TcpMetadataAnalyzer {
    fn id(&self) -> &'static str {
        "tcp.metadata"
    }

    fn supports(&self, session: &SessionMeta) -> bool {
        session.flow.transport == TransportProtocol::Tcp
    }

    fn analyze(&mut self, _event: &CaptureEvent, _sink: &mut dyn AnalysisSink) -> Result<()> {
        Ok(())
    }
}

/// HTTP/2 frame analyzer for decrypted HTTPS application data.
pub struct Http2Analyzer;

impl EventProtocolAnalyzer for Http2Analyzer {
    fn id(&self) -> &'static str {
        "http2.frames"
    }

    fn analyze(&mut self, event: &CaptureEvent, sink: &mut dyn AnalysisSink) -> Result<()> {
        let CaptureEventKind::ProtocolObservation {
            analyzer_id,
            metadata,
            ..
        } = &event.kind
        else {
            return Ok(());
        };

        if analyzer_id != "https.plaintext" {
            return Ok(());
        }

        let Some(payload) = metadata
            .get("payload")
            .and_then(|value| serde_json::from_value::<Payload>(value.clone()).ok())
        else {
            return Ok(());
        };
        let Some(bytes) = payload_bytes(&payload) else {
            return Ok(());
        };
        let Some(frames) = parse_http2_frames(&bytes) else {
            return Ok(());
        };
        if frames.is_empty() {
            return Ok(());
        }

        let direction = metadata
            .get("direction")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let frame_labels = frames
            .iter()
            .take(4)
            .map(|frame| frame.frame_type.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let summary = format!(
            "HTTP/2 {direction} {} frame{}: {frame_labels}",
            frames.len(),
            if frames.len() == 1 { "" } else { "s" }
        );

        sink.emit(protocol_event(
            event.timestamp,
            &event.source_id,
            self.id(),
            &summary,
            serde_json::json!({
                "flow": metadata.get("flow").cloned(),
                "direction": direction,
                "protocol": "http2",
                "frames": frames,
            }),
        ))
    }
}

/// QUIC packet metadata analyzer for UDP datagrams.
pub struct QuicAnalyzer {
    traffic_secrets: Vec<QuicTrafficSecret>,
    flows: HashMap<CanonicalFlow, QuicPluginFlowState>,
}

impl QuicAnalyzer {
    fn new(key_log: Option<&TlsKeyLog>) -> Self {
        let traffic_secrets = key_log
            .map(|key_log| {
                key_log
                    .entries
                    .iter()
                    .filter_map(|entry| {
                        let direction = match entry.label.as_str() {
                            "CLIENT_TRAFFIC_SECRET_0" => QuicSecretDirection::Client,
                            "SERVER_TRAFFIC_SECRET_0" => QuicSecretDirection::Server,
                            _ => return None,
                        };
                        Some(QuicTrafficSecret {
                            direction,
                            secret: entry.secret.clone(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Self {
            traffic_secrets,
            flows: HashMap::new(),
        }
    }
}

impl EventProtocolAnalyzer for QuicAnalyzer {
    fn id(&self) -> &'static str {
        "quic.packet"
    }

    fn analyze(&mut self, event: &CaptureEvent, sink: &mut dyn AnalysisSink) -> Result<()> {
        let CaptureEventKind::InterfacePacket {
            flow: Some(flow),
            payload: Some(payload),
            ..
        } = &event.kind
        else {
            return Ok(());
        };

        if flow.transport != TransportProtocol::Udp
            || (flow.source.port != 443 && flow.destination.port != 443)
        {
            return Ok(());
        }

        let Some(bytes) = payload_bytes(payload) else {
            return Ok(());
        };
        let Some(packet) = parse_quic_packet(&bytes) else {
            return Ok(());
        };

        let key = CanonicalFlow::from_flow(flow);
        let state = self.flows.entry(key).or_default();
        state.observe_header(flow, &packet);
        let plaintext = state.decrypt_short_packet(flow, &bytes, &self.traffic_secrets);
        let parsed_frames = plaintext
            .as_deref()
            .map(parse_quic_frames)
            .filter(|frames| !frames.is_empty());
        let frames = parsed_frames.as_ref().map(|frames| {
            frames
                .iter()
                .map(|frame| frame.observation.clone())
                .collect::<Vec<_>>()
        });
        let http3_events = parsed_frames
            .as_deref()
            .map(|frames| {
                state.consume_quic_frames(flow, event.timestamp, &event.source_id, frames)
            })
            .unwrap_or_default();

        let summary = format!(
            "QUIC {} {}B dcid={} scid={}{}",
            packet.packet_type,
            bytes.len(),
            packet.destination_connection_id_len,
            packet.source_connection_id_len,
            if plaintext.is_some() {
                " decrypted"
            } else {
                ""
            }
        );

        sink.emit(protocol_event(
            event.timestamp,
            &event.source_id,
            self.id(),
            &summary,
            serde_json::json!({
                "flow": flow_metadata(flow),
                "protocol": "quic",
                "packet": packet,
                "decryption": if plaintext.is_some() { "decrypted_1rtt" } else { "encrypted" },
                "plaintext": plaintext.as_ref().map(|bytes| Payload::from_bytes(bytes, Some(4096))),
                "frames": frames,
                "payload_len": bytes.len(),
            }),
        ))?;

        for event in http3_events {
            sink.emit(event)?;
        }

        Ok(())
    }
}

/// Parsed NSS SSLKEYLOGFILE contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsKeyLog {
    /// Accepted key log entries.
    pub entries: Vec<TlsKeyLogEntry>,
    /// Non-empty lines that were comments or malformed records.
    pub ignored_lines: usize,
}

/// One TLS key log record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsKeyLogEntry {
    /// NSS key log label, for example `CLIENT_RANDOM` or `CLIENT_TRAFFIC_SECRET_0`.
    pub label: String,
    /// Client random bytes used to match the TLS connection.
    pub client_random: Vec<u8>,
    /// Secret bytes for the matching TLS connection.
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone)]
struct TlsSecrets {
    values: HashMap<String, Vec<u8>>,
}

impl TlsKeyLog {
    /// Load and parse an NSS-compatible SSLKEYLOGFILE.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|error| {
            Error::InvalidConfig(format!(
                "failed to read TLS key log file {}: {error}",
                path.display()
            ))
        })?;

        Ok(Self::parse(&content))
    }

    /// Parse NSS SSLKEYLOGFILE text.
    pub fn parse(content: &str) -> Self {
        let mut entries = Vec::new();
        let mut ignored_lines = 0usize;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let mut parts = line.split_ascii_whitespace();
            let Some(label) = parts.next() else {
                continue;
            };
            let Some(client_random) = parts.next().and_then(decode_hex) else {
                ignored_lines += 1;
                continue;
            };
            let Some(secret) = parts.next().and_then(decode_hex) else {
                ignored_lines += 1;
                continue;
            };

            if parts.next().is_some() || client_random.len() != 32 || secret.is_empty() {
                ignored_lines += 1;
                continue;
            }

            entries.push(TlsKeyLogEntry {
                label: label.to_owned(),
                client_random,
                secret,
            });
        }

        Self {
            entries,
            ignored_lines,
        }
    }

    /// Count entries grouped by label for status messages and metadata.
    pub fn label_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for entry in &self.entries {
            *counts.entry(entry.label.clone()).or_insert(0) += 1;
        }
        counts
    }

    fn secret_map(&self) -> HashMap<Vec<u8>, TlsSecrets> {
        let mut by_random: HashMap<Vec<u8>, TlsSecrets> = HashMap::new();
        for entry in &self.entries {
            by_random
                .entry(entry.client_random.clone())
                .or_insert_with(|| TlsSecrets {
                    values: HashMap::new(),
                })
                .values
                .insert(entry.label.clone(), entry.secret.clone());
        }
        by_random
    }
}

/// Incremental TLS plaintext restorer backed by an NSS SSLKEYLOGFILE.
pub struct TlsPlaintextRestorer {
    key_log_path: Option<std::path::PathBuf>,
    key_log_mtime: Option<SystemTime>,
    secrets: HashMap<Vec<u8>, TlsSecrets>,
    flows: HashMap<CanonicalFlow, TlsFlowState>,
    payload_limit: Option<usize>,
}

impl TlsPlaintextRestorer {
    /// Build a restorer and load the key log once if a path was provided.
    pub fn new(
        key_log_path: Option<std::path::PathBuf>,
        payload_limit: Option<usize>,
    ) -> Result<Self> {
        let mut restorer = Self {
            key_log_path,
            key_log_mtime: None,
            secrets: HashMap::new(),
            flows: HashMap::new(),
            payload_limit,
        };
        restorer.reload_key_log_if_changed()?;
        Ok(restorer)
    }

    /// Consume a packet event and return decrypted TLS application data events.
    pub fn observe(&mut self, event: &CaptureEvent) -> Result<Vec<CaptureEvent>> {
        self.reload_key_log_if_changed()?;

        let CaptureEventKind::InterfacePacket {
            flow: Some(flow),
            tcp: Some(tcp),
            payload: Some(payload),
            ..
        } = &event.kind
        else {
            return Ok(Vec::new());
        };

        if flow.transport != TransportProtocol::Tcp || payload.truncated {
            return Ok(Vec::new());
        }

        let Some(bytes) = payload_bytes(payload) else {
            return Ok(Vec::new());
        };

        let key = CanonicalFlow::from_flow(flow);
        let state = self.flows.entry(key).or_default();
        let direction = state.direction_for(flow);
        let stream = match direction {
            TlsDirection::LeftToRight => &mut state.left_to_right,
            TlsDirection::RightToLeft => &mut state.right_to_left,
        };
        let contiguous = stream.push(tcp.sequence_number, &bytes);
        if contiguous.is_empty() {
            return Ok(Vec::new());
        }

        let observations = state.consume(
            direction,
            flow,
            event.timestamp,
            event.source_id.as_str(),
            &contiguous,
            &self.secrets,
            self.payload_limit,
        );
        Ok(observations)
    }

    fn reload_key_log_if_changed(&mut self) -> Result<()> {
        let Some(path) = &self.key_log_path else {
            return Ok(());
        };

        let mtime = fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok();
        if self.key_log_mtime.is_some() && mtime == self.key_log_mtime {
            return Ok(());
        }

        let key_log = TlsKeyLog::load(path)?;
        self.secrets = key_log.secret_map();
        self.key_log_mtime = mtime.or_else(|| Some(SystemTime::now()));
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TlsDirection {
    LeftToRight,
    RightToLeft,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CanonicalFlow {
    left: EndpointKey,
    right: EndpointKey,
}

impl CanonicalFlow {
    fn from_flow(flow: &FlowKey) -> Self {
        let source = EndpointKey::from_endpoint(&flow.source);
        let destination = EndpointKey::from_endpoint(&flow.destination);
        if source <= destination {
            Self {
                left: source,
                right: destination,
            }
        } else {
            Self {
                left: destination,
                right: source,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct EndpointKey {
    address: IpAddr,
    port: u16,
}

impl EndpointKey {
    fn from_endpoint(endpoint: &Endpoint) -> Self {
        Self {
            address: endpoint.address,
            port: endpoint.port,
        }
    }
}

#[derive(Debug, Default)]
struct TlsFlowState {
    left_to_right: TcpStreamBuffer,
    right_to_left: TcpStreamBuffer,
    left_endpoint: Option<EndpointKey>,
    client: Option<EndpointKey>,
    server: Option<EndpointKey>,
    client_random: Option<Vec<u8>>,
    cipher_suite: Option<u16>,
    client_records: TlsRecordReader,
    server_records: TlsRecordReader,
    client_decryptor: Option<RecordDecryptor>,
    server_decryptor: Option<RecordDecryptor>,
    warned_unsupported: bool,
}

impl TlsFlowState {
    fn direction_for(&mut self, flow: &FlowKey) -> TlsDirection {
        let source = EndpointKey::from_endpoint(&flow.source);
        let left = self.left_endpoint.get_or_insert_with(|| {
            let key = CanonicalFlow::from_flow(flow);
            key.left
        });
        if source == *left {
            TlsDirection::LeftToRight
        } else {
            TlsDirection::RightToLeft
        }
    }

    fn consume(
        &mut self,
        direction: TlsDirection,
        flow: &FlowKey,
        timestamp: u64,
        source_id: &str,
        bytes: &[u8],
        secrets: &HashMap<Vec<u8>, TlsSecrets>,
        payload_limit: Option<usize>,
    ) -> Vec<CaptureEvent> {
        let records = match direction {
            TlsDirection::LeftToRight => self.client_records.push(bytes),
            TlsDirection::RightToLeft => self.server_records.push(bytes),
        };

        let mut events = Vec::new();
        for record in records {
            match record.content_type {
                20 => {}
                22 => self.consume_handshake_record(
                    direction,
                    flow,
                    &record.payload,
                    secrets,
                    &mut events,
                    timestamp,
                    source_id,
                ),
                23 => {
                    self.configure_decryptors(secrets);
                    if let Some(event) = self.consume_application_record(
                        flow,
                        timestamp,
                        source_id,
                        &record,
                        payload_limit,
                    ) {
                        events.push(event);
                    }
                }
                _ => {}
            }
        }

        events
    }

    fn consume_handshake_record(
        &mut self,
        direction: TlsDirection,
        flow: &FlowKey,
        payload: &[u8],
        secrets: &HashMap<Vec<u8>, TlsSecrets>,
        events: &mut Vec<CaptureEvent>,
        timestamp: u64,
        source_id: &str,
    ) {
        let messages = match direction {
            TlsDirection::LeftToRight => self.client_records.push_handshake(payload),
            TlsDirection::RightToLeft => self.server_records.push_handshake(payload),
        };

        for message in messages {
            match message.kind {
                1 => {
                    if let Some(random) = parse_client_hello_random(&message.body) {
                        self.client_random = Some(random);
                        self.client = Some(EndpointKey::from_endpoint(&flow.source));
                        self.server = Some(EndpointKey::from_endpoint(&flow.destination));
                        self.configure_decryptors(secrets);
                    }
                }
                2 => {
                    self.cipher_suite = parse_server_hello_cipher_suite(&message.body);
                    self.configure_decryptors(secrets);
                    if self.cipher_suite.is_some()
                        && self.client_random.is_some()
                        && self.client_decryptor.is_none()
                        && !self.warned_unsupported
                    {
                        self.warned_unsupported = true;
                        events.push(protocol_event(
                            timestamp,
                            source_id,
                            "tls.decrypt",
                            "TLS session found, but no TLS 1.3 application traffic secrets matched yet",
                            serde_json::json!({
                                "flow": flow_metadata(flow),
                                "cipher_suite": self.cipher_suite.map(cipher_suite_name),
                                "status": "waiting_for_sslkeylogfile_secret"
                            }),
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    fn configure_decryptors(&mut self, secrets: &HashMap<Vec<u8>, TlsSecrets>) {
        if self.client_decryptor.is_some() && self.server_decryptor.is_some() {
            return;
        }

        let (Some(client_random), Some(cipher_suite)) = (&self.client_random, self.cipher_suite)
        else {
            return;
        };
        let Some(secrets) = secrets.get(client_random) else {
            return;
        };
        let Some(client_secret) = secrets.values.get("CLIENT_TRAFFIC_SECRET_0") else {
            return;
        };
        let Some(server_secret) = secrets.values.get("SERVER_TRAFFIC_SECRET_0") else {
            return;
        };

        if self.client_decryptor.is_none() {
            self.client_decryptor = RecordDecryptor::new(cipher_suite, client_secret);
        }
        if self.server_decryptor.is_none() {
            self.server_decryptor = RecordDecryptor::new(cipher_suite, server_secret);
        }
    }

    fn consume_application_record(
        &mut self,
        flow: &FlowKey,
        timestamp: u64,
        source_id: &str,
        record: &TlsRecord,
        payload_limit: Option<usize>,
    ) -> Option<CaptureEvent> {
        let from_client = Some(EndpointKey::from_endpoint(&flow.source)) == self.client;
        let decryptor = if from_client {
            self.client_decryptor.as_mut()
        } else {
            self.server_decryptor.as_mut()
        }?;

        let plaintext = decryptor.decrypt(record)?;
        if plaintext.content_type != 23 || plaintext.bytes.is_empty() {
            return None;
        }

        let payload = Payload::from_bytes(&plaintext.bytes, payload_limit);
        let direction_text = if from_client {
            "client_to_server"
        } else {
            "server_to_client"
        };
        let preview = payload.preview.clone().unwrap_or_default();
        let summary = if preview.is_empty() {
            format!("HTTPS plaintext {direction_text} {}B", payload.original_len)
        } else {
            format!(
                "HTTPS plaintext {direction_text} {}B {}",
                payload.original_len,
                preview
                    .replace(['\r', '\n'], " ")
                    .chars()
                    .take(96)
                    .collect::<String>()
            )
        };

        Some(protocol_event(
            timestamp,
            source_id,
            "https.plaintext",
            &summary,
            serde_json::json!({
                "flow": flow_metadata(flow),
                "direction": direction_text,
                "payload": payload,
                "cipher_suite": self.cipher_suite.map(cipher_suite_name),
            }),
        ))
    }
}

#[derive(Debug, Default)]
struct TcpStreamBuffer {
    next_sequence: Option<u32>,
    pending: BTreeMap<u32, Vec<u8>>,
}

impl TcpStreamBuffer {
    fn push(&mut self, sequence: u32, bytes: &[u8]) -> Vec<u8> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.pending
            .entry(sequence)
            .or_insert_with(|| bytes.to_vec());
        let mut output = Vec::new();
        let mut next = self.next_sequence.unwrap_or(sequence);

        while let Some(bytes) = self.pending.remove(&next) {
            next = next.wrapping_add(bytes.len() as u32);
            output.extend(bytes);
        }

        self.next_sequence = Some(next);
        output
    }
}

#[derive(Debug, Default)]
struct TlsRecordReader {
    buffer: Vec<u8>,
    handshake_buffer: Vec<u8>,
}

impl TlsRecordReader {
    fn push(&mut self, bytes: &[u8]) -> Vec<TlsRecord> {
        self.buffer.extend_from_slice(bytes);
        let mut records = Vec::new();

        loop {
            if self.buffer.len() < 5 {
                break;
            }
            let len = usize::from(u16::from_be_bytes([self.buffer[3], self.buffer[4]]));
            if self.buffer.len() < 5 + len {
                break;
            }

            let record = TlsRecord {
                content_type: self.buffer[0],
                version: [self.buffer[1], self.buffer[2]],
                payload: self.buffer[5..5 + len].to_vec(),
            };
            self.buffer.drain(..5 + len);
            records.push(record);
        }

        records
    }

    fn push_handshake(&mut self, bytes: &[u8]) -> Vec<TlsHandshakeMessage> {
        self.handshake_buffer.extend_from_slice(bytes);
        let mut messages = Vec::new();

        loop {
            if self.handshake_buffer.len() < 4 {
                break;
            }
            let len = ((usize::from(self.handshake_buffer[1])) << 16)
                | ((usize::from(self.handshake_buffer[2])) << 8)
                | usize::from(self.handshake_buffer[3]);
            if self.handshake_buffer.len() < 4 + len {
                break;
            }
            messages.push(TlsHandshakeMessage {
                kind: self.handshake_buffer[0],
                body: self.handshake_buffer[4..4 + len].to_vec(),
            });
            self.handshake_buffer.drain(..4 + len);
        }

        messages
    }
}

#[derive(Debug)]
struct TlsRecord {
    content_type: u8,
    version: [u8; 2],
    payload: Vec<u8>,
}

#[derive(Debug)]
struct TlsHandshakeMessage {
    kind: u8,
    body: Vec<u8>,
}

#[derive(Debug)]
struct TlsPlaintext {
    content_type: u8,
    bytes: Vec<u8>,
}

#[derive(Debug)]
enum RecordDecryptor {
    Aes128Gcm {
        key: Vec<u8>,
        iv: [u8; 12],
        sequence: u64,
    },
    Aes256Gcm {
        key: Vec<u8>,
        iv: [u8; 12],
        sequence: u64,
    },
    ChaCha20Poly1305 {
        key: Vec<u8>,
        iv: [u8; 12],
        sequence: u64,
    },
}

impl RecordDecryptor {
    fn new(cipher_suite: u16, secret: &[u8]) -> Option<Self> {
        match cipher_suite {
            0x1301 => Some(Self::Aes128Gcm {
                key: tls13_expand_label_sha256(secret, b"key", b"", 16)?,
                iv: tls13_iv(tls13_expand_label_sha256(secret, b"iv", b"", 12)?)?,
                sequence: 0,
            }),
            0x1302 => Some(Self::Aes256Gcm {
                key: tls13_expand_label_sha384(secret, b"key", b"", 32)?,
                iv: tls13_iv(tls13_expand_label_sha384(secret, b"iv", b"", 12)?)?,
                sequence: 0,
            }),
            0x1303 => Some(Self::ChaCha20Poly1305 {
                key: tls13_expand_label_sha256(secret, b"key", b"", 32)?,
                iv: tls13_iv(tls13_expand_label_sha256(secret, b"iv", b"", 12)?)?,
                sequence: 0,
            }),
            _ => None,
        }
    }

    fn decrypt(&mut self, record: &TlsRecord) -> Option<TlsPlaintext> {
        let header = record_header(record);
        let plaintext = match self {
            Self::Aes128Gcm { key, iv, sequence } => {
                let nonce = sequence_nonce(iv, *sequence);
                let cipher = Aes128Gcm::new_from_slice(key).ok()?;
                let result = cipher
                    .decrypt(
                        AesNonce::from_slice(&nonce),
                        AeadPayload {
                            msg: &record.payload,
                            aad: &header,
                        },
                    )
                    .ok()?;
                *sequence += 1;
                result
            }
            Self::Aes256Gcm { key, iv, sequence } => {
                let nonce = sequence_nonce(iv, *sequence);
                let cipher = Aes256Gcm::new_from_slice(key).ok()?;
                let result = cipher
                    .decrypt(
                        AesNonce::from_slice(&nonce),
                        AeadPayload {
                            msg: &record.payload,
                            aad: &header,
                        },
                    )
                    .ok()?;
                *sequence += 1;
                result
            }
            Self::ChaCha20Poly1305 { key, iv, sequence } => {
                let nonce = sequence_nonce(iv, *sequence);
                let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
                let result = cipher
                    .decrypt(
                        ChaChaNonce::from_slice(&nonce),
                        AeadPayload {
                            msg: &record.payload,
                            aad: &header,
                        },
                    )
                    .ok()?;
                *sequence += 1;
                result
            }
        };

        split_tls_inner_plaintext(plaintext)
    }
}

fn payload_bytes(payload: &Payload) -> Option<Vec<u8>> {
    match payload.encoding {
        protolens_core::PayloadEncoding::Base64 => base64::engine::general_purpose::STANDARD
            .decode(payload.data.as_bytes())
            .ok(),
    }
}

fn parse_http2_frames(bytes: &[u8]) -> Option<Vec<Http2FrameObservation>> {
    let mut offset = 0usize;
    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if bytes.starts_with(PREFACE) {
        offset = PREFACE.len();
    }

    let mut frames = Vec::new();
    while offset + 9 <= bytes.len() {
        let length = ((bytes[offset] as usize) << 16)
            | ((bytes[offset + 1] as usize) << 8)
            | bytes[offset + 2] as usize;
        let type_id = bytes[offset + 3];
        let flags = bytes[offset + 4];
        let stream_id = (((bytes[offset + 5] & 0x7f) as u32) << 24)
            | ((bytes[offset + 6] as u32) << 16)
            | ((bytes[offset + 7] as u32) << 8)
            | bytes[offset + 8] as u32;
        let frame_end = offset + 9 + length;
        if frame_end > bytes.len() {
            break;
        }

        if !is_plausible_http2_frame(type_id, length, stream_id) {
            return if frames.is_empty() {
                None
            } else {
                Some(frames)
            };
        }

        frames.push(Http2FrameObservation {
            frame_type: http2_frame_type(type_id).to_owned(),
            type_id,
            flags,
            stream_id,
            length,
        });
        offset = frame_end;

        if frames.len() >= 64 {
            break;
        }
    }

    if frames.is_empty() {
        None
    } else {
        Some(frames)
    }
}

fn is_plausible_http2_frame(type_id: u8, length: usize, stream_id: u32) -> bool {
    if length > 16_777_215 {
        return false;
    }

    match type_id {
        0x4 | 0x6 => stream_id == 0,
        0x7 => stream_id == 0,
        0x0 | 0x1 | 0x2 | 0x3 | 0x5 | 0x8 | 0x9 => true,
        _ => true,
    }
}

fn http2_frame_type(type_id: u8) -> &'static str {
    match type_id {
        0x0 => "DATA",
        0x1 => "HEADERS",
        0x2 => "PRIORITY",
        0x3 => "RST_STREAM",
        0x4 => "SETTINGS",
        0x5 => "PUSH_PROMISE",
        0x6 => "PING",
        0x7 => "GOAWAY",
        0x8 => "WINDOW_UPDATE",
        0x9 => "CONTINUATION",
        _ => "UNKNOWN",
    }
}

fn parse_quic_packet(bytes: &[u8]) -> Option<QuicPacketObservation> {
    let first = *bytes.first()?;
    if first & 0x40 == 0 {
        return None;
    }

    if first & 0x80 == 0 {
        return Some(QuicPacketObservation {
            header_form: "short".to_owned(),
            packet_type: "1-RTT".to_owned(),
            version: None,
            destination_connection_id_len: 0,
            source_connection_id_len: 0,
        });
    }

    if bytes.len() < 7 {
        return None;
    }
    let version = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    let dcid_len = bytes[5] as usize;
    if bytes.len() < 6 + dcid_len + 1 {
        return None;
    }
    let scid_len_offset = 6 + dcid_len;
    let scid_len = bytes[scid_len_offset] as usize;
    if bytes.len() < scid_len_offset + 1 + scid_len {
        return None;
    }

    let packet_type = match (first & 0x30) >> 4 {
        0x0 => "Initial",
        0x1 => "0-RTT",
        0x2 => "Handshake",
        0x3 => "Retry",
        _ => "Long",
    };

    Some(QuicPacketObservation {
        header_form: "long".to_owned(),
        packet_type: packet_type.to_owned(),
        version: Some(version),
        destination_connection_id_len: dcid_len,
        source_connection_id_len: scid_len,
    })
}

impl QuicPluginFlowState {
    fn direction_for(&mut self, flow: &FlowKey) -> TlsDirection {
        let source = EndpointKey::from_endpoint(&flow.source);
        let left = self.left_endpoint.get_or_insert_with(|| {
            let key = CanonicalFlow::from_flow(flow);
            key.left
        });
        if source == *left {
            TlsDirection::LeftToRight
        } else {
            TlsDirection::RightToLeft
        }
    }

    fn observe_header(&mut self, flow: &FlowKey, packet: &QuicPacketObservation) {
        if packet.header_form != "long" {
            return;
        }

        let direction = self.direction_for(flow);
        match direction {
            TlsDirection::LeftToRight => {
                if packet.source_connection_id_len > 0 {
                    self.right_to_left_dcid_len = Some(packet.source_connection_id_len);
                }
            }
            TlsDirection::RightToLeft => {
                if packet.source_connection_id_len > 0 {
                    self.left_to_right_dcid_len = Some(packet.source_connection_id_len);
                }
            }
        }
    }

    fn decrypt_short_packet(
        &mut self,
        flow: &FlowKey,
        bytes: &[u8],
        traffic_secrets: &[QuicTrafficSecret],
    ) -> Option<Vec<u8>> {
        if bytes.first().copied()? & 0x80 != 0 {
            return None;
        }

        let direction = self.direction_for(flow);
        let dcid_len = match direction {
            TlsDirection::LeftToRight => self.left_to_right_dcid_len.unwrap_or(0),
            TlsDirection::RightToLeft => self.right_to_left_dcid_len.unwrap_or(0),
        };
        let pn_offset = 1 + dcid_len;
        if bytes.len() < pn_offset + 5 {
            return None;
        }

        let secret_direction = if flow.source.port == 443 {
            QuicSecretDirection::Server
        } else {
            QuicSecretDirection::Client
        };
        let largest_pn = match direction {
            TlsDirection::LeftToRight => &mut self.left_to_right_largest_pn,
            TlsDirection::RightToLeft => &mut self.right_to_left_largest_pn,
        };

        for secret in traffic_secrets
            .iter()
            .filter(|secret| secret.direction == secret_direction)
        {
            for keys in quic_keys_for_secret(&secret.secret) {
                let Some(unprotected) = remove_quic_header_protection(bytes, pn_offset, &keys)
                else {
                    continue;
                };
                let pn_len = (unprotected[0] & 0x03) as usize + 1;
                if unprotected.len() < pn_offset + pn_len {
                    continue;
                }
                let truncated_pn =
                    decode_truncated_packet_number(&unprotected[pn_offset..pn_offset + pn_len]);
                let full_pn = reconstruct_packet_number(*largest_pn, truncated_pn, pn_len);
                let aad = &unprotected[..pn_offset + pn_len];
                let ciphertext = &bytes[pn_offset + pn_len..];
                let Some(plaintext) = decrypt_quic_payload(&keys, full_pn, aad, ciphertext) else {
                    continue;
                };
                if !is_plausible_quic_plaintext(&plaintext) {
                    continue;
                }
                *largest_pn = Some(largest_pn.map_or(full_pn, |largest| largest.max(full_pn)));
                return Some(plaintext);
            }
        }

        None
    }

    fn consume_quic_frames(
        &mut self,
        flow: &FlowKey,
        timestamp: u64,
        source_id: &str,
        frames: &[QuicFrameParsed],
    ) -> Vec<CaptureEvent> {
        let direction = self.direction_for(flow);
        let mut events = Vec::new();

        for frame in frames {
            let Some(stream) = &frame.stream_data else {
                continue;
            };
            let key = QuicStreamKey {
                direction,
                stream_id: stream.stream_id,
            };
            let state = self.streams.entry(key).or_default();
            state.push(stream.offset, &stream.bytes);
            events.extend(state.parse_http3_events(
                flow,
                timestamp,
                source_id,
                direction,
                stream.stream_id,
            ));
        }

        events
    }
}

impl QuicStreamState {
    fn push(&mut self, offset: u64, bytes: &[u8]) {
        let offset = offset as usize;
        if offset > self.bytes.len() {
            return;
        }
        if offset + bytes.len() <= self.bytes.len() {
            return;
        }
        let start = self.bytes.len().saturating_sub(offset);
        self.bytes.extend_from_slice(&bytes[start..]);
    }

    fn parse_http3_events(
        &mut self,
        flow: &FlowKey,
        timestamp: u64,
        source_id: &str,
        direction: TlsDirection,
        stream_id: u64,
    ) -> Vec<CaptureEvent> {
        let mut events = Vec::new();

        if self.kind.is_none() {
            if stream_id & 0x02 != 0 {
                let mut cursor = 0usize;
                let Some(stream_type) = read_quic_varint(&self.bytes, &mut cursor) else {
                    return events;
                };
                self.kind = Some(match stream_type {
                    0x00 => QuicStreamKind::Control,
                    0x01 => QuicStreamKind::Push,
                    0x02 => QuicStreamKind::QpackEncoder,
                    0x03 => QuicStreamKind::QpackDecoder,
                    value => QuicStreamKind::UnknownUni(value),
                });
                self.parsed_offset = cursor;
            } else {
                self.kind = Some(QuicStreamKind::Request);
            }
        }

        if self.kind != Some(QuicStreamKind::Request) {
            return events;
        }

        loop {
            let frame_start = self.parsed_offset;
            let mut cursor = frame_start;
            let Some(type_id) = read_quic_varint(&self.bytes, &mut cursor) else {
                break;
            };
            let Some(length) =
                read_quic_varint(&self.bytes, &mut cursor).map(|value| value as usize)
            else {
                break;
            };
            let Some(end) = cursor
                .checked_add(length)
                .filter(|end| *end <= self.bytes.len())
            else {
                break;
            };
            let payload = &self.bytes[cursor..end];
            self.parsed_offset = end;

            let frame = http3_frame_observation(type_id, stream_id, payload);
            if type_id == 0x01 || type_id == 0x00 {
                let direction_text = match direction {
                    TlsDirection::LeftToRight => "left_to_right",
                    TlsDirection::RightToLeft => "right_to_left",
                };
                let summary = match type_id {
                    0x01 => {
                        let header_text = frame
                            .headers
                            .as_ref()
                            .map(|headers| {
                                headers
                                    .iter()
                                    .take(4)
                                    .map(|header| format!("{}={}", header.name, header.value))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default();
                        format!("HTTP/3 headers stream={stream_id} {header_text}")
                    }
                    0x00 => {
                        let preview = frame.data_preview.as_deref().unwrap_or_default();
                        if preview.is_empty() {
                            format!("HTTP/3 data stream={stream_id} {}B", payload.len())
                        } else {
                            format!(
                                "HTTP/3 data stream={stream_id} {}B preview={}",
                                payload.len(),
                                preview.chars().take(160).collect::<String>()
                            )
                        }
                    }
                    _ => format!("HTTP/3 frame stream={stream_id}"),
                };

                events.push(protocol_event(
                    timestamp,
                    source_id,
                    "http3.frame",
                    &summary,
                    serde_json::json!({
                        "flow": flow_metadata(flow),
                        "direction": direction_text,
                        "stream_id": stream_id,
                        "frame": frame,
                    }),
                ));
            }
        }

        events
    }
}

fn quic_keys_for_secret(secret: &[u8]) -> Vec<QuicHeaderProtectionKeys> {
    let mut keys = Vec::new();

    if secret.len() == 32 {
        if let (Some(key), Some(iv), Some(hp)) = (
            tls13_expand_label_sha256(secret, b"quic key", b"", 16),
            tls13_expand_label_sha256(secret, b"quic iv", b"", 12),
            tls13_expand_label_sha256(secret, b"quic hp", b"", 16),
        ) {
            keys.push(QuicHeaderProtectionKeys {
                key,
                iv,
                hp,
                cipher: QuicCipher::Aes128GcmSha256,
            });
        }
    }

    if secret.len() == 48 {
        if let (Some(key), Some(iv), Some(hp)) = (
            tls13_expand_label_sha384(secret, b"quic key", b"", 32),
            tls13_expand_label_sha384(secret, b"quic iv", b"", 12),
            tls13_expand_label_sha384(secret, b"quic hp", b"", 32),
        ) {
            keys.push(QuicHeaderProtectionKeys {
                key,
                iv,
                hp,
                cipher: QuicCipher::Aes256GcmSha384,
            });
        }
    }

    keys
}

fn remove_quic_header_protection(
    bytes: &[u8],
    pn_offset: usize,
    keys: &QuicHeaderProtectionKeys,
) -> Option<Vec<u8>> {
    let sample_offset = pn_offset + 4;
    let sample = bytes.get(sample_offset..sample_offset + 16)?;
    let mask = quic_header_protection_mask(keys, sample)?;
    let mut unprotected = bytes.to_vec();
    unprotected[0] ^= mask[0] & 0x1f;
    let pn_len = (unprotected[0] & 0x03) as usize + 1;
    if unprotected.len() < pn_offset + pn_len {
        return None;
    }
    for index in 0..pn_len {
        unprotected[pn_offset + index] ^= mask[index + 1];
    }
    Some(unprotected)
}

fn quic_header_protection_mask(keys: &QuicHeaderProtectionKeys, sample: &[u8]) -> Option<[u8; 16]> {
    let mut block = GenericArray::clone_from_slice(sample);
    match keys.cipher {
        QuicCipher::Aes128GcmSha256 => {
            let cipher = Aes128::new_from_slice(&keys.hp).ok()?;
            cipher.encrypt_block(&mut block);
        }
        QuicCipher::Aes256GcmSha384 => {
            let cipher = Aes256::new_from_slice(&keys.hp).ok()?;
            cipher.encrypt_block(&mut block);
        }
    }
    Some(block.into())
}

fn decode_truncated_packet_number(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(0u64, |value, byte| (value << 8) | *byte as u64)
}

fn reconstruct_packet_number(largest_pn: Option<u64>, truncated_pn: u64, pn_len: usize) -> u64 {
    let expected = largest_pn.map_or(0, |largest| largest + 1);
    let pn_nbits = pn_len * 8;
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;
    let candidate = (expected & !pn_mask) | truncated_pn;

    if candidate + pn_hwin <= expected {
        candidate + pn_win
    } else if candidate > expected + pn_hwin && candidate >= pn_win {
        candidate - pn_win
    } else {
        candidate
    }
}

fn decrypt_quic_payload(
    keys: &QuicHeaderProtectionKeys,
    packet_number: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    let nonce = quic_nonce(&keys.iv, packet_number)?;
    match keys.cipher {
        QuicCipher::Aes128GcmSha256 => {
            let cipher = Aes128Gcm::new_from_slice(&keys.key).ok()?;
            cipher
                .decrypt(
                    AesNonce::from_slice(&nonce),
                    AeadPayload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .ok()
        }
        QuicCipher::Aes256GcmSha384 => {
            let cipher = Aes256Gcm::new_from_slice(&keys.key).ok()?;
            cipher
                .decrypt(
                    AesNonce::from_slice(&nonce),
                    AeadPayload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .ok()
        }
    }
}

fn quic_nonce(iv: &[u8], packet_number: u64) -> Option<[u8; 12]> {
    let mut nonce: [u8; 12] = iv.try_into().ok()?;
    for (index, byte) in packet_number.to_be_bytes().iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
    Some(nonce)
}

fn is_plausible_quic_plaintext(bytes: &[u8]) -> bool {
    !parse_quic_frames(bytes).is_empty()
}

fn parse_quic_frames(bytes: &[u8]) -> Vec<QuicFrameParsed> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() && frames.len() < 32 {
        let type_id = bytes[offset];
        let mut observation = QuicFrameObservation {
            frame_type: quic_frame_type(type_id).to_owned(),
            type_id,
            stream_id: None,
            offset: None,
            length: None,
            fin: None,
        };

        if type_id == 0x00 {
            frames.push(QuicFrameParsed {
                observation,
                stream_data: None,
            });
            offset += 1;
            continue;
        }

        let Some((next_offset, stream_data)) = parse_quic_frame(bytes, offset, type_id) else {
            break;
        };
        if next_offset <= offset {
            break;
        }
        if let Some(stream) = &stream_data {
            observation.stream_id = Some(stream.stream_id);
            observation.offset = Some(stream.offset);
            observation.length = Some(stream.bytes.len());
            observation.fin = Some(stream.fin);
        }
        frames.push(QuicFrameParsed {
            observation,
            stream_data,
        });
        offset = next_offset;
    }

    frames
}

fn quic_frame_type(type_id: u8) -> &'static str {
    match type_id {
        0x00 => "PADDING",
        0x01 => "PING",
        0x02 | 0x03 => "ACK",
        0x04 => "RESET_STREAM",
        0x05 => "STOP_SENDING",
        0x06 => "CRYPTO",
        0x07 => "NEW_TOKEN",
        0x08..=0x0f => "STREAM",
        0x10 => "MAX_DATA",
        0x11 => "MAX_STREAM_DATA",
        0x12 | 0x13 => "MAX_STREAMS",
        0x14 => "DATA_BLOCKED",
        0x15 => "STREAM_DATA_BLOCKED",
        0x16 | 0x17 => "STREAMS_BLOCKED",
        0x18 => "NEW_CONNECTION_ID",
        0x19 => "RETIRE_CONNECTION_ID",
        0x1a => "PATH_CHALLENGE",
        0x1b => "PATH_RESPONSE",
        0x1c | 0x1d => "CONNECTION_CLOSE",
        0x1e => "HANDSHAKE_DONE",
        _ => "UNKNOWN",
    }
}

fn parse_quic_frame(
    bytes: &[u8],
    offset: usize,
    type_id: u8,
) -> Option<(usize, Option<QuicStreamFrameData>)> {
    let mut cursor = offset + 1;
    match type_id {
        0x01 => Some((cursor, None)),
        0x02 | 0x03 => {
            for _ in 0..4 {
                read_quic_varint(bytes, &mut cursor)?;
            }
            let range_count = read_quic_varint(bytes, &mut cursor)?;
            if type_id == 0x03 {
                read_quic_varint(bytes, &mut cursor)?;
            }
            for _ in 0..range_count {
                read_quic_varint(bytes, &mut cursor)?;
                read_quic_varint(bytes, &mut cursor)?;
            }
            Some((cursor, None))
        }
        0x06 => {
            read_quic_varint(bytes, &mut cursor)?;
            let len = read_quic_varint(bytes, &mut cursor)? as usize;
            cursor
                .checked_add(len)
                .filter(|end| *end <= bytes.len())
                .map(|end| (end, None))
        }
        0x08..=0x0f => {
            let stream_id = read_quic_varint(bytes, &mut cursor)?;
            let stream_offset = if type_id & 0x04 != 0 {
                read_quic_varint(bytes, &mut cursor)?
            } else {
                0
            };
            let len = if type_id & 0x02 != 0 {
                read_quic_varint(bytes, &mut cursor)? as usize
            } else {
                bytes.len().saturating_sub(cursor)
            };
            let end = cursor.checked_add(len).filter(|end| *end <= bytes.len())?;
            Some((
                end,
                Some(QuicStreamFrameData {
                    stream_id,
                    offset: stream_offset,
                    fin: type_id & 0x01 != 0,
                    bytes: bytes[cursor..end].to_vec(),
                }),
            ))
        }
        _ => Some((bytes.len(), None)),
    }
}

fn http3_frame_observation(type_id: u64, stream_id: u64, payload: &[u8]) -> Http3FrameObservation {
    match type_id {
        0x00 => Http3FrameObservation {
            frame_type: "DATA".to_owned(),
            type_id,
            stream_id,
            length: payload.len(),
            headers: None,
            data_preview: Some(payload_preview(payload)),
            data_len: Some(payload.len()),
        },
        0x01 => Http3FrameObservation {
            frame_type: "HEADERS".to_owned(),
            type_id,
            stream_id,
            length: payload.len(),
            headers: Some(decode_qpack_header_block(payload)),
            data_preview: None,
            data_len: None,
        },
        0x04 => Http3FrameObservation {
            frame_type: "SETTINGS".to_owned(),
            type_id,
            stream_id,
            length: payload.len(),
            headers: None,
            data_preview: None,
            data_len: None,
        },
        _ => Http3FrameObservation {
            frame_type: format!("TYPE_{type_id}"),
            type_id,
            stream_id,
            length: payload.len(),
            headers: None,
            data_preview: None,
            data_len: None,
        },
    }
}

fn payload_preview(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(value) => value.chars().take(2048).collect(),
        Err(_) => bytes
            .iter()
            .take(128)
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn decode_qpack_header_block(bytes: &[u8]) -> Vec<HttpHeaderObservation> {
    let mut cursor = 0usize;
    if bytes.is_empty() {
        return Vec::new();
    }

    let _required_insert_count = read_prefixed_int(bytes, &mut cursor, 8);
    let _delta_base = read_prefixed_int(bytes, &mut cursor, 7);

    let mut headers = Vec::new();
    while cursor < bytes.len() && headers.len() < 64 {
        let byte = bytes[cursor];
        if byte & 0x80 != 0 {
            let is_static = byte & 0x40 != 0;
            let Some(index) = read_prefixed_int(bytes, &mut cursor, 6) else {
                break;
            };
            let (name, value) = if is_static {
                qpack_static(index).unwrap_or(("static", "<unknown>"))
            } else {
                ("dynamic", "<not decoded>")
            };
            headers.push(HttpHeaderObservation {
                name: name.to_owned(),
                value: value.to_owned(),
            });
            continue;
        }

        if byte & 0x40 != 0 {
            let name_static = byte & 0x10 != 0;
            let Some(name_index) = read_prefixed_int(bytes, &mut cursor, 4) else {
                break;
            };
            let name = if name_static {
                qpack_static(name_index)
                    .map(|(name, _)| name.to_owned())
                    .unwrap_or_else(|| "static".to_owned())
            } else {
                "dynamic".to_owned()
            };
            let value = read_qpack_string(bytes, &mut cursor)
                .unwrap_or_else(|| "<value not decoded>".to_owned());
            headers.push(HttpHeaderObservation { name, value });
            continue;
        }

        if byte & 0x20 != 0 {
            cursor += 1;
            let name = read_qpack_string(bytes, &mut cursor)
                .unwrap_or_else(|| "<name not decoded>".to_owned());
            let value = read_qpack_string(bytes, &mut cursor)
                .unwrap_or_else(|| "<value not decoded>".to_owned());
            headers.push(HttpHeaderObservation { name, value });
            continue;
        }

        break;
    }

    headers
}

fn read_prefixed_int(bytes: &[u8], cursor: &mut usize, prefix_bits: u8) -> Option<u64> {
    let first = *bytes.get(*cursor)?;
    let mask = if prefix_bits == 8 {
        0xff
    } else {
        (1u8 << prefix_bits) - 1
    };
    *cursor += 1;
    let mut value = (first & mask) as u64;
    if value < mask as u64 {
        return Some(value);
    }

    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*cursor)?;
        *cursor += 1;
        value += ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
}

fn read_qpack_string(bytes: &[u8], cursor: &mut usize) -> Option<String> {
    let huffman = *bytes.get(*cursor)? & 0x80 != 0;
    let len = read_prefixed_int(bytes, cursor, 7)? as usize;
    let end = cursor.checked_add(len)?;
    let value = bytes.get(*cursor..end)?;
    *cursor = end;

    if huffman {
        decode_hpack_huffman(value)
            .and_then(|decoded| visible_text(&decoded))
            .or_else(|| Some(format!("<huffman decode failed {len}B>")))
    } else {
        visible_text(value).or_else(|| Some(format!("<binary {len}B>")))
    }
}

fn visible_text(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    if text
        .chars()
        .all(|ch| ch == '\t' || ch == ' ' || !ch.is_control())
    {
        Some(text.into_owned())
    } else {
        None
    }
}

fn decode_hpack_huffman(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(bytes.len().saturating_mul(2));
    let mut code = 0u32;
    let mut code_len = 0usize;

    for byte in bytes {
        for bit_index in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit_index) & 1);
            code_len += 1;

            if let Some(symbol) = hpack_huffman_symbol(code, code_len) {
                if symbol == 256 {
                    return None;
                }
                output.push(symbol as u8);
                code = 0;
                code_len = 0;
            } else if code_len > 30 {
                return None;
            }
        }
    }

    if code_len == 0 {
        return Some(output);
    }

    if code_len <= 7 && code == ((1u32 << code_len) - 1) {
        Some(output)
    } else {
        None
    }
}

fn hpack_huffman_symbol(code: u32, code_len: usize) -> Option<usize> {
    HPACK_HUFFMAN_CODES
        .iter()
        .position(|(len, item_code)| usize::from(*len) == code_len && *item_code == code)
}

fn qpack_static(index: u64) -> Option<(&'static str, &'static str)> {
    Some(match index {
        0 => (":authority", ""),
        1 => (":path", "/"),
        2 => ("age", "0"),
        3 => ("content-disposition", ""),
        4 => ("content-length", "0"),
        5 => ("cookie", ""),
        6 => ("date", ""),
        7 => ("etag", ""),
        8 => ("if-modified-since", ""),
        9 => ("if-none-match", ""),
        10 => ("last-modified", ""),
        11 => ("link", ""),
        12 => ("location", ""),
        13 => ("referer", ""),
        14 => ("set-cookie", ""),
        15 => (":method", "CONNECT"),
        16 => (":method", "DELETE"),
        17 => (":method", "GET"),
        18 => (":method", "HEAD"),
        19 => (":method", "OPTIONS"),
        20 => (":method", "POST"),
        21 => (":method", "PUT"),
        22 => (":scheme", "http"),
        23 => (":scheme", "https"),
        24 => (":status", "103"),
        25 => (":status", "200"),
        26 => (":status", "304"),
        27 => (":status", "404"),
        28 => (":status", "503"),
        29 => ("accept", "*/*"),
        30 => ("accept", "application/dns-message"),
        31 => ("accept-encoding", "gzip, deflate, br"),
        32 => ("accept-ranges", "bytes"),
        33 => ("access-control-allow-headers", "cache-control"),
        34 => ("access-control-allow-headers", "content-type"),
        35 => ("access-control-allow-origin", "*"),
        36 => ("cache-control", "max-age=0"),
        37 => ("cache-control", "max-age=2592000"),
        38 => ("cache-control", "max-age=604800"),
        39 => ("cache-control", "no-cache"),
        40 => ("cache-control", "no-store"),
        41 => ("cache-control", "public, max-age=31536000"),
        42 => ("content-encoding", "br"),
        43 => ("content-encoding", "gzip"),
        44 => ("content-type", "application/dns-message"),
        45 => ("content-type", "application/javascript"),
        46 => ("content-type", "application/json"),
        47 => ("content-type", "application/x-www-form-urlencoded"),
        48 => ("content-type", "image/gif"),
        49 => ("content-type", "image/jpeg"),
        50 => ("content-type", "image/png"),
        51 => ("content-type", "text/css"),
        52 => ("content-type", "text/html; charset=utf-8"),
        53 => ("content-type", "text/plain"),
        54 => ("content-type", "text/plain;charset=utf-8"),
        55 => ("range", "bytes=0-"),
        56 => ("strict-transport-security", "max-age=31536000"),
        57 => (
            "strict-transport-security",
            "max-age=31536000; includesubdomains",
        ),
        58 => (
            "strict-transport-security",
            "max-age=31536000; includesubdomains; preload",
        ),
        59 => ("vary", "accept-encoding"),
        60 => ("vary", "origin"),
        61 => ("x-content-type-options", "nosniff"),
        62 => ("x-xss-protection", "1; mode=block"),
        63 => (":status", "100"),
        64 => (":status", "204"),
        65 => (":status", "206"),
        66 => (":status", "302"),
        67 => (":status", "400"),
        68 => (":status", "403"),
        69 => (":status", "421"),
        70 => (":status", "425"),
        71 => (":status", "500"),
        72 => ("accept-language", ""),
        73 => ("access-control-allow-credentials", "FALSE"),
        74 => ("access-control-allow-credentials", "TRUE"),
        75 => ("access-control-allow-headers", "*"),
        76 => ("access-control-allow-methods", "get"),
        77 => ("access-control-allow-methods", "get, post, options"),
        78 => ("access-control-allow-methods", "options"),
        79 => ("access-control-expose-headers", "content-length"),
        80 => ("access-control-request-headers", "content-type"),
        81 => ("access-control-request-method", "get"),
        82 => ("access-control-request-method", "post"),
        83 => ("alt-svc", "clear"),
        84 => ("authorization", ""),
        85 => (
            "content-security-policy",
            "script-src 'none'; object-src 'none'; base-uri 'none'",
        ),
        86 => ("early-data", "1"),
        87 => ("expect-ct", ""),
        88 => ("forwarded", ""),
        89 => ("if-range", ""),
        90 => ("origin", ""),
        91 => ("purpose", "prefetch"),
        92 => ("server", ""),
        93 => ("timing-allow-origin", "*"),
        94 => ("upgrade-insecure-requests", "1"),
        95 => ("user-agent", ""),
        96 => ("x-forwarded-for", ""),
        97 => ("x-frame-options", "deny"),
        98 => ("x-frame-options", "sameorigin"),
        _ => return None,
    })
}

const HPACK_HUFFMAN_CODES: [(u8, u32); 257] = [
    (13, 0x1ff8),
    (23, 0x007f_ffd8),
    (28, 0x0fff_ffe2),
    (28, 0x0fff_ffe3),
    (28, 0x0fff_ffe4),
    (28, 0x0fff_ffe5),
    (28, 0x0fff_ffe6),
    (28, 0x0fff_ffe7),
    (28, 0x0fff_ffe8),
    (24, 0x00ff_ffea),
    (30, 0x3fff_fffc),
    (28, 0x0fff_ffe9),
    (28, 0x0fff_ffea),
    (30, 0x3fff_fffd),
    (28, 0x0fff_ffeb),
    (28, 0x0fff_ffec),
    (28, 0x0fff_ffed),
    (28, 0x0fff_ffee),
    (28, 0x0fff_ffef),
    (28, 0x0fff_fff0),
    (28, 0x0fff_fff1),
    (28, 0x0fff_fff2),
    (30, 0x3fff_fffe),
    (28, 0x0fff_fff3),
    (28, 0x0fff_fff4),
    (28, 0x0fff_fff5),
    (28, 0x0fff_fff6),
    (28, 0x0fff_fff7),
    (28, 0x0fff_fff8),
    (28, 0x0fff_fff9),
    (28, 0x0fff_fffa),
    (28, 0x0fff_fffb),
    (6, 0x14),
    (10, 0x3f8),
    (10, 0x3f9),
    (12, 0xffa),
    (13, 0x1ff9),
    (6, 0x15),
    (8, 0xf8),
    (11, 0x7fa),
    (10, 0x3fa),
    (10, 0x3fb),
    (8, 0xf9),
    (11, 0x7fb),
    (8, 0xfa),
    (6, 0x16),
    (6, 0x17),
    (6, 0x18),
    (5, 0x0),
    (5, 0x1),
    (5, 0x2),
    (6, 0x19),
    (6, 0x1a),
    (6, 0x1b),
    (6, 0x1c),
    (6, 0x1d),
    (6, 0x1e),
    (6, 0x1f),
    (7, 0x5c),
    (8, 0xfb),
    (15, 0x7ffc),
    (6, 0x20),
    (12, 0xffb),
    (10, 0x3fc),
    (13, 0x1ffa),
    (6, 0x21),
    (7, 0x5d),
    (7, 0x5e),
    (7, 0x5f),
    (7, 0x60),
    (7, 0x61),
    (7, 0x62),
    (7, 0x63),
    (7, 0x64),
    (7, 0x65),
    (7, 0x66),
    (7, 0x67),
    (7, 0x68),
    (7, 0x69),
    (7, 0x6a),
    (7, 0x6b),
    (7, 0x6c),
    (7, 0x6d),
    (7, 0x6e),
    (7, 0x6f),
    (7, 0x70),
    (7, 0x71),
    (7, 0x72),
    (8, 0xfc),
    (7, 0x73),
    (8, 0xfd),
    (13, 0x1ffb),
    (19, 0x7fff0),
    (13, 0x1ffc),
    (14, 0x3ffc),
    (6, 0x22),
    (15, 0x7ffd),
    (5, 0x3),
    (6, 0x23),
    (5, 0x4),
    (6, 0x24),
    (5, 0x5),
    (6, 0x25),
    (6, 0x26),
    (6, 0x27),
    (5, 0x6),
    (7, 0x74),
    (7, 0x75),
    (6, 0x28),
    (6, 0x29),
    (6, 0x2a),
    (5, 0x7),
    (6, 0x2b),
    (7, 0x76),
    (6, 0x2c),
    (5, 0x8),
    (5, 0x9),
    (6, 0x2d),
    (7, 0x77),
    (7, 0x78),
    (7, 0x79),
    (7, 0x7a),
    (7, 0x7b),
    (15, 0x7ffe),
    (11, 0x7fc),
    (14, 0x3ffd),
    (13, 0x1ffd),
    (28, 0x0fff_fffc),
    (20, 0xfffe6),
    (22, 0x003f_ffd2),
    (20, 0xfffe7),
    (20, 0xfffe8),
    (22, 0x003f_ffd3),
    (22, 0x003f_ffd4),
    (22, 0x003f_ffd5),
    (23, 0x007f_ffd9),
    (22, 0x003f_ffd6),
    (23, 0x007f_ffda),
    (23, 0x007f_ffdb),
    (23, 0x007f_ffdc),
    (23, 0x007f_ffdd),
    (23, 0x007f_ffde),
    (24, 0x00ff_ffeb),
    (23, 0x007f_ffdf),
    (24, 0x00ff_ffec),
    (24, 0x00ff_ffed),
    (22, 0x003f_ffd7),
    (23, 0x007f_ffe0),
    (24, 0x00ff_ffee),
    (23, 0x007f_ffe1),
    (23, 0x007f_ffe2),
    (23, 0x007f_ffe3),
    (23, 0x007f_ffe4),
    (21, 0x001f_ffdc),
    (22, 0x003f_ffd8),
    (23, 0x007f_ffe5),
    (22, 0x003f_ffd9),
    (23, 0x007f_ffe6),
    (23, 0x007f_ffe7),
    (24, 0x00ff_ffef),
    (22, 0x003f_ffda),
    (21, 0x001f_ffdd),
    (20, 0xfffe9),
    (22, 0x003f_ffdb),
    (22, 0x003f_ffdc),
    (23, 0x007f_ffe8),
    (23, 0x007f_ffe9),
    (21, 0x001f_ffde),
    (23, 0x007f_ffea),
    (22, 0x003f_ffdd),
    (22, 0x003f_ffde),
    (24, 0x00ff_fff0),
    (21, 0x001f_ffdf),
    (22, 0x003f_ffdf),
    (23, 0x007f_ffeb),
    (23, 0x007f_ffec),
    (21, 0x001f_ffe0),
    (21, 0x001f_ffe1),
    (22, 0x003f_ffe0),
    (21, 0x001f_ffe2),
    (23, 0x007f_ffed),
    (22, 0x003f_ffe1),
    (23, 0x007f_ffee),
    (23, 0x007f_ffef),
    (20, 0xfffea),
    (22, 0x003f_ffe2),
    (22, 0x003f_ffe3),
    (22, 0x003f_ffe4),
    (23, 0x007f_fff0),
    (22, 0x003f_ffe5),
    (22, 0x003f_ffe6),
    (23, 0x007f_fff1),
    (26, 0x03ff_ffe0),
    (26, 0x03ff_ffe1),
    (20, 0xfffeb),
    (19, 0x7fff1),
    (22, 0x003f_ffe7),
    (23, 0x007f_fff2),
    (22, 0x003f_ffe8),
    (25, 0x01ff_ffec),
    (26, 0x03ff_ffe2),
    (26, 0x03ff_ffe3),
    (26, 0x03ff_ffe4),
    (27, 0x07ff_ffde),
    (27, 0x07ff_ffdf),
    (26, 0x03ff_ffe5),
    (24, 0x00ff_fff1),
    (25, 0x01ff_ffed),
    (19, 0x7fff2),
    (21, 0x001f_ffe3),
    (26, 0x03ff_ffe6),
    (27, 0x07ff_ffe0),
    (27, 0x07ff_ffe1),
    (26, 0x03ff_ffe7),
    (27, 0x07ff_ffe2),
    (24, 0x00ff_fff2),
    (21, 0x001f_ffe4),
    (21, 0x001f_ffe5),
    (26, 0x03ff_ffe8),
    (26, 0x03ff_ffe9),
    (28, 0x0fff_fffd),
    (27, 0x07ff_ffe3),
    (27, 0x07ff_ffe4),
    (27, 0x07ff_ffe5),
    (20, 0xfffec),
    (24, 0x00ff_fff3),
    (20, 0xfffed),
    (21, 0x001f_ffe6),
    (22, 0x003f_ffe9),
    (21, 0x001f_ffe7),
    (21, 0x001f_ffe8),
    (23, 0x007f_fff3),
    (22, 0x003f_ffea),
    (22, 0x003f_ffeb),
    (25, 0x01ff_ffee),
    (25, 0x01ff_ffef),
    (24, 0x00ff_fff4),
    (24, 0x00ff_fff5),
    (26, 0x03ff_ffea),
    (23, 0x007f_fff4),
    (26, 0x03ff_ffeb),
    (27, 0x07ff_ffe6),
    (26, 0x03ff_ffec),
    (26, 0x03ff_ffed),
    (27, 0x07ff_ffe7),
    (27, 0x07ff_ffe8),
    (27, 0x07ff_ffe9),
    (27, 0x07ff_ffea),
    (27, 0x07ff_ffeb),
    (28, 0x0fff_fffe),
    (27, 0x07ff_ffec),
    (27, 0x07ff_ffed),
    (27, 0x07ff_ffee),
    (27, 0x07ff_ffef),
    (27, 0x07ff_fff0),
    (26, 0x03ff_ffee),
    (30, 0x3fff_ffff),
];

fn read_quic_varint(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let first = *bytes.get(*cursor)?;
    let len = 1usize << (first >> 6);
    let end = cursor.checked_add(len)?;
    let slice = bytes.get(*cursor..end)?;
    let mut value = (slice[0] & 0x3f) as u64;
    for byte in &slice[1..] {
        value = (value << 8) | *byte as u64;
    }
    *cursor = end;
    Some(value)
}

fn parse_client_hello_random(body: &[u8]) -> Option<Vec<u8>> {
    if body.len() < 34 {
        return None;
    }
    Some(body[2..34].to_vec())
}

fn parse_server_hello_cipher_suite(body: &[u8]) -> Option<u16> {
    if body.len() < 38 {
        return None;
    }
    let session_id_len = usize::from(*body.get(34)?);
    let cipher_offset = 35 + session_id_len;
    if body.len() < cipher_offset + 2 {
        return None;
    }
    Some(u16::from_be_bytes([
        body[cipher_offset],
        body[cipher_offset + 1],
    ]))
}

fn tls13_expand_label_sha256(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Option<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::from_prk(secret).ok()?;
    let info = hkdf_label_info(label, context, len);
    let mut output = vec![0u8; len];
    hkdf.expand(&info, &mut output).ok()?;
    Some(output)
}

fn tls13_expand_label_sha384(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Option<Vec<u8>> {
    let hkdf = Hkdf::<Sha384>::from_prk(secret).ok()?;
    let info = hkdf_label_info(label, context, len);
    let mut output = vec![0u8; len];
    hkdf.expand(&info, &mut output).ok()?;
    Some(output)
}

fn hkdf_label_info(label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let full_label = [b"tls13 ".as_slice(), label].concat();
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info
}

fn tls13_iv(bytes: Vec<u8>) -> Option<[u8; 12]> {
    bytes.try_into().ok()
}

fn sequence_nonce(iv: &[u8; 12], sequence: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for (index, byte) in sequence.to_be_bytes().iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
    nonce
}

fn record_header(record: &TlsRecord) -> [u8; 5] {
    let len = record.payload.len() as u16;
    [
        record.content_type,
        record.version[0],
        record.version[1],
        (len >> 8) as u8,
        len as u8,
    ]
}

fn split_tls_inner_plaintext(mut plaintext: Vec<u8>) -> Option<TlsPlaintext> {
    while plaintext.last().copied() == Some(0) {
        plaintext.pop();
    }
    let content_type = plaintext.pop()?;
    Some(TlsPlaintext {
        content_type,
        bytes: plaintext,
    })
}

fn protocol_event(
    timestamp: u64,
    source_id: &str,
    analyzer_id: &str,
    summary: &str,
    metadata: serde_json::Value,
) -> CaptureEvent {
    CaptureEvent {
        timestamp,
        source_id: source_id.to_owned(),
        kind: CaptureEventKind::ProtocolObservation {
            analyzer_id: analyzer_id.to_owned(),
            session_id: None,
            summary: summary.to_owned(),
            metadata,
        },
    }
}

fn flow_metadata(flow: &FlowKey) -> serde_json::Value {
    serde_json::json!({
        "source": {
            "address": flow.source.address.to_string(),
            "port": flow.source.port,
        },
        "destination": {
            "address": flow.destination.address.to_string(),
            "port": flow.destination.port,
        },
        "transport": flow.transport,
    })
}

fn cipher_suite_name(cipher_suite: u16) -> String {
    match cipher_suite {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => "UNKNOWN",
    }
    .to_owned()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let high = hex_nibble(chunk[0])?;
            let low = hex_nibble(chunk[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_tcp_analyzer() {
        let registry = AnalyzerRegistry::default();

        assert_eq!(registry.analyzers().len(), 1);
        assert_eq!(registry.analyzers()[0].id(), "tcp.metadata");
        assert_eq!(registry.event_analyzers().len(), 2);
        assert_eq!(registry.event_analyzers()[0].id(), "http2.frames");
        assert_eq!(registry.event_analyzers()[1].id(), "quic.packet");
    }

    #[test]
    fn parses_http2_frames() {
        let bytes = [
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice(),
            &[0, 0, 0, 0x4, 0, 0, 0, 0, 0],
        ]
        .concat();

        let frames = parse_http2_frames(&bytes).unwrap();

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].frame_type, "SETTINGS");
        assert_eq!(frames[0].stream_id, 0);
    }

    #[test]
    fn parses_quic_long_header() {
        let packet =
            parse_quic_packet(&[0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 1, 2, 3, 4, 0x02, 5, 6])
                .unwrap();

        assert_eq!(packet.header_form, "long");
        assert_eq!(packet.packet_type, "Initial");
        assert_eq!(packet.version, Some(1));
        assert_eq!(packet.destination_connection_id_len, 4);
        assert_eq!(packet.source_connection_id_len, 2);
    }

    #[test]
    fn parses_nss_tls_key_log_lines() {
        let parsed = TlsKeyLog::parse(
            "\
# comment
CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 20212223
CLIENT_TRAFFIC_SECRET_0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbcc
broken line
",
        );

        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.ignored_lines, 1);
        assert_eq!(parsed.entries[0].label, "CLIENT_RANDOM");
        assert_eq!(
            parsed.entries[0].client_random,
            vec![
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
        assert_eq!(parsed.entries[0].secret, vec![32, 33, 34, 35]);
        assert_eq!(
            parsed.label_counts().get("CLIENT_TRAFFIC_SECRET_0"),
            Some(&1)
        );
    }

    #[test]
    fn rejects_malformed_hex_key_log_lines() {
        let parsed = TlsKeyLog::parse(
            "\
CLIENT_RANDOM abc 0011
CLIENT_RANDOM 0011 xx
CLIENT_RANDOM 0011 2233 extra
",
        );

        assert!(parsed.entries.is_empty());
        assert_eq!(parsed.ignored_lines, 3);
    }

    #[test]
    fn decrypts_tls13_aes_gcm_application_record() {
        let secret = [7u8; 32];
        let mut encryptor = RecordDecryptor::new(0x1301, &secret).unwrap();
        let mut decryptor = RecordDecryptor::new(0x1301, &secret).unwrap();
        let plaintext = b"GET / HTTP/1.1\r\n\r\n".to_vec();
        let record = encrypt_tls13_test_record(&mut encryptor, plaintext.clone());

        let decrypted = decryptor.decrypt(&record).unwrap();

        assert_eq!(decrypted.content_type, 23);
        assert_eq!(decrypted.bytes, plaintext);
    }

    fn encrypt_tls13_test_record(
        encryptor: &mut RecordDecryptor,
        mut plaintext: Vec<u8>,
    ) -> TlsRecord {
        plaintext.push(23);
        let (key, iv, sequence) = match encryptor {
            RecordDecryptor::Aes128Gcm { key, iv, sequence } => (key.clone(), *iv, sequence),
            _ => panic!("test expects AES-128-GCM"),
        };
        let nonce = sequence_nonce(&iv, *sequence);
        let plain_len = plaintext.len() + 16;
        let header = [23, 3, 3, (plain_len >> 8) as u8, plain_len as u8];
        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let encrypted = cipher
            .encrypt(
                AesNonce::from_slice(&nonce),
                AeadPayload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .unwrap();
        *sequence += 1;

        TlsRecord {
            content_type: 23,
            version: [3, 3],
            payload: encrypted,
        }
    }
}
