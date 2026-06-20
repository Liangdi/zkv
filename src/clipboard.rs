//! 剪贴板:复制 + 定时自动清空。对应 PRD §7(安全特性)。
//!
//! 对外接口:
//! - [`copy`][]:跨平台复制到系统剪贴板。
//! - [`copy_and_clear_after`]:复制后起后台线程,sleep `secs` 秒后清空剪贴板(写空串)。
//!
//! ## 后端选择
//! 默认走**系统命令**(不引入新依赖),运行时按以下顺序探测可用项:
//! - macOS:`pbcopy`
//! - Wayland:`wl-copy`
//! - X11:`xclip -selection clipboard` 或 `xsel -bi`
//!
//! 复制 = 把文本经 stdin 喂给命令;清空 = 把空串喂给同一通道。失败返回 [`Error::Other`]。
//!
//! 分层(L3):仅依赖 `crate::error` 与标准库,不引用 vault/app/ui。

use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

use crate::error::{Error, Result};

/// 剪贴板写入后端:首个可用的静态闭包引用(无捕获,可提升为 `'static`)。
type Backend = Option<&'static (dyn Fn(&str) -> Result<()> + Sync)>;

/// 缓存后的后端探测:首次调用执行实际探测(spawn),之后直接复用结果。
///
/// `OnceLock` 线程安全,多个 `copy` 并发首次调用也只会探测一次。
/// 已知可接受的权衡:缓存后若后端在运行时由「不可用」变为「可用」
/// (例如用户事后才启动 X server),不会被重新探测。保持简单、确定。
fn backend() -> Backend {
    static BACKEND: OnceLock<Backend> = OnceLock::new();
    *BACKEND.get_or_init(detect_backend_impl)
}

/// 命令成功执行后即认为该后端可用。返回首个可用后端的「写入函数」(闭包)。
///
/// 探测策略:对每个候选,尝试以空串实际运行一次;不报错即视为可用。
/// 这样避免依赖 `which`,且区分「装了但当前会话无显示服务器」等场景。
fn detect_backend_impl() -> Backend {
    // 用函数表 + cfg 选择候选,逐一探测。
    #[cfg(target_os = "macos")]
    {
        if probe(|t| run_pipe(&["pbcopy"], t)).is_ok() {
            return Some(&|t: &str| run_pipe(&["pbcopy"], t));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
    {
        // Wayland
        if std::env::var_os("WAYLAND_DISPLAY").is_some()
            && probe(|t| run_pipe(&["wl-copy"], t)).is_ok()
        {
            return Some(&|t: &str| run_pipe(&["wl-copy"], t));
        }
        // X11
        if std::env::var_os("DISPLAY").is_some()
            && probe(|t| run_pipe(&["xclip", "-selection", "clipboard"], t)).is_ok()
        {
            return Some(&|t: &str| run_pipe(&["xclip", "-selection", "clipboard"], t));
        }
        if std::env::var_os("DISPLAY").is_some()
            && probe(|t| run_pipe(&["xsel", "-bi"], t)).is_ok()
        {
            return Some(&|t: &str| run_pipe(&["xsel", "-bi"], t));
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows 无标准剪贴板 CLI,系统命令方案不可靠。返回 None,调用方得到 Err。
    }

    None
}

/// 探测:对候选后端用空串跑一次,不报错即视为可用。
fn probe<F>(f: F) -> Result<()>
where
    F: Fn(&str) -> Result<()>,
{
    f("")
}

/// 把 `text` 经 stdin 喂给 `cmd`(第一个元素为程序名,其余为参数)。
/// stdin/stdout/stderr 均接管道,避免向终端泄漏或挂起。
fn run_pipe(cmd: &[&str], text: &str) -> Result<()> {
    use std::io::Write;
    let mut child = Command::new(cmd[0])
        .args(&cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| Error::Other(format!("spawn {} failed: {e}", cmd[0])))?;

    {
        let stdin = child.stdin.as_mut().ok_or_else(|| {
            Error::Other(format!("could not open stdin for {}", cmd[0]))
        })?;
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| Error::Other(format!("write to {} failed: {e}", cmd[0])))?;
        // drop stdin 触发 EOF
    }

    let status = child
        .wait()
        .map_err(|e| Error::Other(format!("wait {} failed: {e}", cmd[0])))?;
    if !status.success() {
        return Err(Error::Other(format!(
            "{} exited with {status}",
            cmd[0]
        )));
    }
    Ok(())
}

/// 复制文本到系统剪贴板。
pub fn copy(text: &str) -> Result<()> {
    match backend() {
        Some(backend) => (backend)(text),
        None => Err(Error::Other(
            "no clipboard backend available (pbcopy/wl-copy/xclip/xsel)".into(),
        )),
    }
}

/// 复制文本到剪贴板,然后在后台线程中等待 `secs` 秒后清空剪贴板(写回空串)。
///
/// 清空使用与复制相同的底层通道。后台线程是 detached 的;若在此期间又复制了新内容,
/// 清空动作仍会执行(调用方应注意时序)。
pub fn copy_and_clear_after(text: &str, secs: u64) -> Result<()> {
    // 先复制(若失败则不安排清空)。
    copy(text)?;

    // 后台线程定时清空。清空调用 copy(""),复用 backend() 的缓存探测结果,不再重复 spawn 探测进程。
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(secs));
        let _ = copy("");
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 无可用后端时(如 CI 无 DISPLAY)应返回 Err,而非 panic。
    #[test]
    fn copy_returns_err_when_no_backend() {
        // 仅在没有剪贴板环境的 CI 容器里断言 Err;本机有环境时跳过该断言以免误报。
        let has_env = std::env::var_os("DISPLAY").is_some()
            || std::env::var_os("WAYLAND_DISPLAY").is_some()
            || cfg!(target_os = "macos");
        if has_env {
            return;
        }
        let res = copy("hello");
        assert!(res.is_err(), "expected Err when no clipboard backend, got {res:?}");
    }

    /// 手动测试(需真实剪贴板环境)。`cargo test copy_and_clear -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn copy_and_clear_manual() {
        // 复制后约 1 秒应被清空。观察剪贴板变化需人工确认。
        let res = copy_and_clear_after("zkv-test-token", 1);
        match res {
            Ok(()) => println!("copied; clipboard should clear in ~1s"),
            Err(e) => println!("backend unavailable in this env: {e}"),
        }
    }
}
