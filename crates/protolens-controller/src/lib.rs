//! Shared application controller for CLI, desktop, and future service entrypoints.
//!
//! This crate owns the high-level actions users can trigger. Product entrypoints
//! should translate UI/CLI input into these APIs instead of duplicating capture
//! loops or shelling out to another binary.

use protolens_capture::{
    CaptureInterface, PcapFileSource, PcapSource, PcapSourceConfig, list_interfaces,
};
use protolens_core::{CaptureEvent, CaptureEventKind, PacketSource, Result};
use protolens_protocol::{TlsKeyLog, TlsPlaintextRestorer};
use std::path::PathBuf;

/// Runtime capture options shared by CLI and desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRunConfig {
    /// Pcap source configuration.
    pub source: PcapSourceConfig,
    /// Stop after this many packet events. Control events are not counted.
    pub count: Option<usize>,
    /// Optional NSS SSLKEYLOGFILE path used by the TLS analyzer.
    pub tls_key_log_path: Option<PathBuf>,
}

impl CaptureRunConfig {
    /// Build a pcap capture config from common product-level options.
    pub fn pcap(
        interface: String,
        filter: String,
        count: Option<usize>,
        payload_limit: usize,
        output_path: Option<PathBuf>,
        tls_key_log_path: Option<PathBuf>,
    ) -> Self {
        Self {
            source: PcapSourceConfig {
                interface,
                filter: Some(filter),
                payload_limit: Some(payload_limit),
                output_path,
                ..PcapSourceConfig::default()
            },
            count,
            tls_key_log_path,
        }
    }
}

/// List pcap-discoverable capture interfaces.
pub fn capture_interfaces() -> Result<Vec<CaptureInterface>> {
    list_interfaces()
}

/// Run a pcap capture loop and emit each event to the provided callback.
///
/// `should_continue` is checked around non-blocking/timeout reads, allowing CLI
/// Ctrl-C and desktop stop buttons to share the same loop behavior.
pub fn run_capture<F, S>(
    config: CaptureRunConfig,
    mut on_event: F,
    should_continue: S,
) -> Result<()>
where
    F: FnMut(CaptureEvent) -> Result<()>,
    S: Fn() -> bool,
{
    emit_tls_key_log_status(config.tls_key_log_path.as_deref(), &mut on_event)?;
    let mut tls_restorer =
        TlsPlaintextRestorer::new(config.tls_key_log_path.clone(), config.source.payload_limit)?;

    let mut source = PcapSource::new(config.source)?;
    let mut emitted_packets = 0usize;

    while should_continue() {
        if let Some(event) = source.next_event()? {
            let is_packet = matches!(
                event.kind,
                CaptureEventKind::InterfacePacket { .. }
                    | CaptureEventKind::UnsupportedPacket { .. }
            );
            let tls_events = tls_restorer.observe(&event)?;
            on_event(event)?;
            for tls_event in tls_events {
                on_event(tls_event)?;
            }

            if is_packet {
                emitted_packets += 1;
                if config.count.is_some_and(|count| emitted_packets >= count) {
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Replay a pcap file through the same event model used by live capture.
pub fn replay_pcap_file<F>(
    path: PathBuf,
    payload_limit: usize,
    tls_key_log_path: Option<PathBuf>,
    mut on_event: F,
) -> Result<usize>
where
    F: FnMut(CaptureEvent) -> Result<()>,
{
    emit_tls_key_log_status(tls_key_log_path.as_deref(), &mut on_event)?;
    let mut tls_restorer = TlsPlaintextRestorer::new(tls_key_log_path, Some(payload_limit))?;

    let mut source = PcapFileSource::new(path, Some(payload_limit))?;
    let mut emitted_events = 0usize;

    while let Some(event) = source.next_event()? {
        let tls_events = tls_restorer.observe(&event)?;
        on_event(event)?;
        for tls_event in tls_events {
            on_event(tls_event)?;
        }
        emitted_events += 1;
    }

    Ok(emitted_events)
}

fn emit_tls_key_log_status<F>(path: Option<&std::path::Path>, on_event: &mut F) -> Result<()>
where
    F: FnMut(CaptureEvent) -> Result<()>,
{
    let Some(path) = path else {
        return Ok(());
    };

    let key_log = TlsKeyLog::load(path)?;
    let labels = key_log.label_counts();
    let entry_count = key_log.entries.len();

    on_event(CaptureEvent {
        timestamp: current_time_millis(),
        source_id: "tls-keylog".to_owned(),
        kind: CaptureEventKind::ProtocolObservation {
            analyzer_id: "tls.keylog".to_owned(),
            session_id: None,
            summary: format!(
                "loaded {entry_count} TLS key log entries from {}",
                path.display()
            ),
            metadata: serde_json::json!({
                "path": path.display().to_string(),
                "entry_count": entry_count,
                "ignored_lines": key_log.ignored_lines,
                "labels": labels,
                "status": "loaded",
                "decryption": "pending_tls_session_reassembly"
            }),
        },
    })?;

    Ok(())
}

fn current_time_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}
