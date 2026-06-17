//! zkv 入口:CLI 解析 → 构造 App → 进入 TUI 主循环。对应 PRD §8 启动流程。
//!
//! panic 恢复:在 color_eyre 默认 panic hook 之前,先恢复终端(关闭 raw mode、
//! 离开备用屏),避免 panic 时终端卡在 raw mode 导致输出乱码。

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use zkv::app::App;
use zkv::ui;

/// Zero Knowledge Vault —— 本地优先、端到端加密的个人数据保险箱。
#[derive(Parser, Debug)]
#[command(
    name = "zkv",
    version,
    about = "Zero Knowledge Vault — local-first, end-to-end encrypted vault",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 创建新的加密库。
    New {
        /// 库文件路径。
        path: PathBuf,
    },
    /// 打开已有加密库。
    Open {
        /// 库文件路径。
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    // 先装 color_eyre(注册其默认 panic hook + 启用错误报告)。
    if let Err(e) = color_eyre::install() {
        // install() 在重复调用时会报错;忽略即可(测试/嵌入式场景)。
        eprintln!("warning: color_eyre already installed: {e}");
    }

    // 在 color_eyre 的 hook 之上包一层:panic 时先把终端恢复回来,
    // 再调用原 hook 打印报告。
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // 恢复终端:尽力而为,忽略错误。
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen
        );
        prev_hook(info);
    }));

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(report) => {
            eprintln!("{report:?}");
            ExitCode::FAILURE
        }
    }
}

/// 解析 CLI → 构造 App → 进入 TUI。
fn run() -> color_eyre::Result<()> {
    let cli = Cli::parse();
    let app = match cli.command {
        Command::New { path } => App::for_create(path),
        Command::Open { path } => App::for_open(path),
    };
    // App::for_* 进入口令输入态;ui::run 内部完成解锁交互。
    // ui::run 返回 crate::error::Result;Error: std::error::Error,
    // `?` 自动转换为 color_eyre::Report。
    ui::run(app)?;
    Ok(())
}
