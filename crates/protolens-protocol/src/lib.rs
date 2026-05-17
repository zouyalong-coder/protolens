//! 协议分析器注册和内置静态插件。
//!
//! v1 只支持编译期静态注册，避免过早引入动态插件 ABI。后续外部进程或 WASM
//! 插件可以基于这里的注册/调度模型扩展。

use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Nonce as AesNonce,
    aead::{Aead, KeyInit, Payload as AeadPayload},
};
use base64::Engine;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use protolens_core::{
    AnalysisSink, CaptureEvent, CaptureEventKind, Endpoint, Error, FlowKey, Payload,
    ProtocolAnalyzer, Result, SessionMeta, TransportProtocol,
};
use sha2::{Sha256, Sha384};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::time::SystemTime;

/// 协议分析器注册表。
pub struct AnalyzerRegistry {
    /// 已注册的静态分析器。
    analyzers: Vec<Box<dyn ProtocolAnalyzer>>,
}

impl AnalyzerRegistry {
    /// 创建空注册表。
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
        }
    }

    /// 创建带默认内置分析器的注册表。
    pub fn with_default_analyzers() -> Self {
        let mut registry = Self::new();
        registry.register(TcpMetadataAnalyzer);
        registry
    }

    /// 注册一个静态协议分析器。
    pub fn register(&mut self, analyzer: impl ProtocolAnalyzer + 'static) {
        self.analyzers.push(Box::new(analyzer));
    }

    /// 返回当前注册的分析器，主要用于测试和诊断。
    pub fn analyzers(&self) -> &[Box<dyn ProtocolAnalyzer>] {
        &self.analyzers
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
