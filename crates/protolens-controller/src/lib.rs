//! Shared application controller for CLI, desktop, and future service entrypoints.
//!
//! This crate owns the high-level actions users can trigger. Product entrypoints
//! should translate UI/CLI input into these APIs instead of duplicating capture
//! loops or shelling out to another binary.

use protolens_capture::{
    CaptureInterface, PcapFileSource, PcapSource, PcapSourceConfig, list_interfaces,
};
use protolens_core::{CaptureEvent, CaptureEventKind, PacketSource, Result};
use std::path::PathBuf;

/// Runtime capture options shared by CLI and desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRunConfig {
    /// Pcap source configuration.
    pub source: PcapSourceConfig,
    /// Stop after this many packet events. Control events are not counted.
    pub count: Option<usize>,
}

impl CaptureRunConfig {
    /// Build a pcap capture config from common product-level options.
    pub fn pcap(
        interface: String,
        filter: String,
        count: Option<usize>,
        payload_limit: usize,
        output_path: Option<PathBuf>,
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
    let mut source = PcapSource::new(config.source)?;
    let mut emitted_packets = 0usize;

    while should_continue() {
        if let Some(event) = source.next_event()? {
            let is_packet = matches!(
                event.kind,
                CaptureEventKind::InterfacePacket { .. }
                    | CaptureEventKind::UnsupportedPacket { .. }
            );
            on_event(event)?;

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
pub fn replay_pcap_file<F>(path: PathBuf, payload_limit: usize, mut on_event: F) -> Result<usize>
where
    F: FnMut(CaptureEvent) -> Result<()>,
{
    let mut source = PcapFileSource::new(path, Some(payload_limit))?;
    let mut emitted_events = 0usize;

    while let Some(event) = source.next_event()? {
        on_event(event)?;
        emitted_events += 1;
    }

    Ok(emitted_events)
}
