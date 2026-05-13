//! 协议分析器注册和内置静态插件。
//!
//! v1 只支持编译期静态注册，避免过早引入动态插件 ABI。后续外部进程或 WASM
//! 插件可以基于这里的注册/调度模型扩展。

use protolens_core::{
    AnalysisSink, CaptureEvent, ProtocolAnalyzer, Result, SessionMeta, TransportProtocol,
};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_tcp_analyzer() {
        let registry = AnalyzerRegistry::default();

        assert_eq!(registry.analyzers().len(), 1);
        assert_eq!(registry.analyzers()[0].id(), "tcp.metadata");
    }
}
