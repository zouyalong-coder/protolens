//! Protocol analyzer registration and built-in analyzers.

use protolens_core::{
    AnalysisSink, CaptureEvent, ProtocolAnalyzer, Result, SessionMeta, TransportProtocol,
};

pub struct AnalyzerRegistry {
    analyzers: Vec<Box<dyn ProtocolAnalyzer>>,
}

impl AnalyzerRegistry {
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
        }
    }

    pub fn with_default_analyzers() -> Self {
        let mut registry = Self::new();
        registry.register(TcpMetadataAnalyzer);
        registry
    }

    pub fn register(&mut self, analyzer: impl ProtocolAnalyzer + 'static) {
        self.analyzers.push(Box::new(analyzer));
    }

    pub fn analyzers(&self) -> &[Box<dyn ProtocolAnalyzer>] {
        &self.analyzers
    }

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
