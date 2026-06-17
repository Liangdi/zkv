//! 统一错误类型,全 crate 共用(L0)。
//!
//! 所有模块返回 `crate::error::Result<T>`,错误变体覆盖:
//! - 加密/解密原语失败(`Crypto`)
//! - 口令错误或文件损坏(`BadPassphrase` / `CorruptFile` —— AEAD 校验失败时归为此类)
//! - 数据库错误(`Database`,包装 `rusqlite::Error`)
//! - 序列化错误(`Serialize`,包装 `serde_json::Error`)
//! - IO 错误(`Io`,包装 `std::io::Error`)
//! - TUI/渲染错误(`Tui`)
//! - 其他(`Other(String)`)

/// 全 crate 统一 `Result` 别名。
pub type Result<T> = std::result::Result<T, Error>;

/// zkv 的统一错误类型。
///
/// 分层(L0):本类型不引用任何上层模块,可被 crate 内任意模块使用。
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// 加密/解密原语层失败(如 Argon2 派生失败、AEAD 初始化失败等)。
    #[error("crypto error: {0}")]
    Crypto(String),

    /// 口令错误。AEAD(Poly1305)校验失败即归为此类:口令错误 ⇒ 派生密钥错误 ⇒ 校验失败。
    #[error("bad passphrase or corrupted data (authentication failed)")]
    BadPassphrase,

    /// 文件损坏:文件头/魔数/版本不匹配、长度不足等结构性损坏。
    #[error("corrupt file: {0}")]
    CorruptFile(String),

    /// 数据库错误,包装 `rusqlite::Error`。
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// 序列化/反序列化错误,包装 `serde_json::Error`。
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),

    /// IO 错误,包装 `std::io::Error`。
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// TUI / 终端渲染错误。
    #[error("tui error: {0}")]
    Tui(String),

    /// 其他未归类错误。
    #[error("{0}")]
    Other(String),
}
