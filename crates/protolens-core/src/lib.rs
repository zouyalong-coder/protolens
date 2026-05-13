//! Shared core types for ProtoLens.
//!
//! This crate is the stable boundary used by capture backends, protocol
//! analyzers, storage, CLI, and future UI integrations.

mod error;
mod event;
mod traits;

pub use error::{Error, Result};
pub use event::{
    CaptureEvent, CaptureEventKind, Direction, Endpoint, FlowKey, Payload, PayloadEncoding,
    SessionEndReason, SessionMeta, TimestampMillis, TransportProtocol,
};
pub use traits::{AnalysisSink, EventSink, PacketSource, ProtocolAnalyzer};
