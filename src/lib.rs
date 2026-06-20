//! zkv — Zero Knowledge Vault
//!
//! 本地优先、端到端加密的个人数据保险箱。详见 `docs/prd/zkv.md`。

pub mod app;
pub mod cli;
pub mod clipboard;
pub mod crypto;
pub mod db;
pub mod error;
pub mod model;
pub mod search;
pub mod store;
#[cfg(test)]
pub mod test_support;
pub mod totp;
pub mod ui;
pub mod vault;
