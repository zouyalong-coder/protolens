use crate::{CaptureEvent, Result, SessionMeta};

pub trait PacketSource {
    fn id(&self) -> &str;

    fn next_event(&mut self) -> Result<Option<CaptureEvent>>;
}

pub trait ProtocolAnalyzer {
    fn id(&self) -> &'static str;

    fn supports(&self, session: &SessionMeta) -> bool;

    fn analyze(&mut self, event: &CaptureEvent, sink: &mut dyn AnalysisSink) -> Result<()>;
}

pub trait AnalysisSink {
    fn emit(&mut self, event: CaptureEvent) -> Result<()>;
}

pub trait EventSink {
    fn id(&self) -> &str;

    fn write(&mut self, event: &CaptureEvent) -> Result<()>;

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
