use crate::{CaptureEvent, Result, SessionMeta};

/// 抓包来源统一接口。
///
/// pcap、显式代理、TUN、文件回放都应实现这个 trait，从而复用后续分析和输出管线。
pub trait PacketSource {
    /// source 的稳定标识，用于事件来源和日志。
    fn id(&self) -> &str;

    /// 读取下一个事件。
    ///
    /// 返回 `Ok(None)` 表示当前暂时没有事件，不代表 source 已结束。
    fn next_event(&mut self) -> Result<Option<CaptureEvent>>;
}

/// 协议分析器接口。
pub trait ProtocolAnalyzer {
    /// 分析器唯一标识，例如 `tcp.metadata`。
    fn id(&self) -> &'static str;

    /// 判断分析器是否支持当前 session。
    fn supports(&self, session: &SessionMeta) -> bool;

    /// 消费底层事件并通过 `AnalysisSink` 输出高层观察结果。
    fn analyze(&mut self, event: &CaptureEvent, sink: &mut dyn AnalysisSink) -> Result<()>;
}

/// 协议分析器输出观察事件的 sink。
pub trait AnalysisSink {
    /// 输出一个分析事件。
    fn emit(&mut self, event: CaptureEvent) -> Result<()>;
}

/// 最终事件输出接口。
///
/// CLI 格式化输出、JSON Lines、未来 SQLite 或桌面事件总线都应实现这个 trait。
pub trait EventSink {
    /// sink 的稳定标识。
    fn id(&self) -> &str;

    /// 写入一个事件。
    fn write(&mut self, event: &CaptureEvent) -> Result<()>;

    /// 刷新底层缓冲区。无缓冲 sink 可以使用默认实现。
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
