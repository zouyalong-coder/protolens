//! 事件输出 sink。
//!
//! 输出层只消费 `CaptureEvent`，不关心事件来自 pcap、代理还是 TUN。这样 CLI、
//! JSON Lines、未来桌面 UI 都可以复用同一套事件模型。

use protolens_core::{CaptureEvent, CaptureEventKind, EventSink, FlowKey, Payload, Result};
use std::io::Write;

/// 面向终端的可读格式化输出 sink。
///
/// `W` 只要求实现 `Write`，因此既可以写 stdout，也可以在测试中写入内存 buffer。
pub struct FormattedEventSink<W> {
    /// 底层输出目标。
    writer: W,
    /// sink 标识。
    id: String,
}

impl<W> FormattedEventSink<W> {
    /// 创建格式化输出 sink。
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            id: "formatted".to_owned(),
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
            CaptureEventKind::InterfacePacket { flow, payload } => {
                write!(self.writer, "[{}] packet", event.timestamp)?;

                if let Some(flow) = flow {
                    write!(self.writer, " {}", format_flow(flow))?;
                }

                if let Some(payload) = payload {
                    write!(self.writer, " payload={}", format_payload(payload))?;
                } else {
                    write!(self.writer, " payload=none")?;
                }

                writeln!(self.writer)?;
            }
            CaptureEventKind::TcpSessionStarted { session } => {
                writeln!(
                    self.writer,
                    "[{}] tcp session started id={} {}",
                    event.timestamp,
                    session.id,
                    format_flow(&session.flow)
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

/// 将 flow 格式化成一行可读的五元组信息。
fn format_flow(flow: &FlowKey) -> String {
    format!(
        "{}:{} -> {}:{} {:?}",
        flow.source.address,
        flow.source.port,
        flow.destination.address,
        flow.destination.port,
        flow.transport
    )
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
    use protolens_core::{CaptureEventKind, Payload};

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
}
