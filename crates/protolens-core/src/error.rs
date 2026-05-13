use thiserror::Error;

/// ProtoLens 内部统一使用的结果类型。
pub type Result<T> = std::result::Result<T, Error>;

/// 跨 crate 共享的错误类型。
///
/// 公共 crate 不直接暴露第三方库错误，统一转换成这里的语义化错误，
/// 方便 CLI、未来桌面端和测试代码做一致处理。
#[derive(Debug, Error)]
pub enum Error {
    /// 用户配置或调用参数不合法。
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// 功能边界已经预留，但当前版本还未实现。
    #[error("unsupported operation: {0}")]
    Unsupported(String),

    /// 抓包后端错误，例如 pcap 打开失败、权限不足或读取失败。
    #[error("capture backend {source_id} failed: {message}")]
    Capture { source_id: String, message: String },

    /// 协议分析器错误。
    #[error("protocol analyzer {analyzer} failed: {message}")]
    Protocol { analyzer: String, message: String },

    /// 输出 sink 错误，例如写文件或写 stdout 失败。
    #[error("event sink {sink} failed: {message}")]
    Sink { sink: String, message: String },

    /// 标准 I/O 错误透传。
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON 序列化/反序列化错误透传。
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
