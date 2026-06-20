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
    /// 创建新的加密库(进入 TUI)。
    New {
        /// 库文件路径。
        path: PathBuf,
    },
    /// 打开已有加密库(进入 TUI)。
    Open {
        /// 库文件路径。
        path: PathBuf,
    },
    /// 无头建库(不进入 TUI)。口令取自 ZKV_PASSPHRASE / --passfile / 交互提示;目标已存在则报错。
    Init {
        /// 库文件路径。
        path: PathBuf,
        /// 口令文件路径(env ZKV_PASSPHRASE 优先,无则交互)。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 列出库中的条目(无头,可脚本化)。
    Ls {
        /// 库文件路径。
        path: PathBuf,
        /// 仅列出该类型的条目(password|note|card)。
        #[arg(short, long, value_parser = clap::value_parser!(zkv::model::ItemType), value_name = "TYPE")]
        r#type: Option<zkv::model::ItemType>,
        /// 仅列出挂有该标签的条目(可重复)。
        #[arg(long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// 仅列出该分类名称下的条目。
        #[arg(long = "cat", value_name = "CATEGORY")]
        category: Option<String>,
        /// 全文检索串(命中标题与正文)。
        #[arg(short, long, value_name = "QUERY")]
        query: Option<String>,
        /// 以 JSON 输出。
        #[arg(long)]
        json: bool,
        /// 口令文件路径(优先级低于 ZKV_PASSPHRASE 环境变量)。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 打印单条条目或某字段原始值(无头)。
    Get {
        /// 库文件路径。
        path: PathBuf,
        /// 条目 id。
        id: i64,
        /// 仅打印该字段(title/username/password/url/totp/notes/format/content/holder/number/expiry/cvv/bank)。
        #[arg(short, long, value_name = "FIELD")]
        field: Option<String>,
        /// 以 JSON 输出整条条目(与 -f 互斥语义:--json 时忽略 -f)。
        #[arg(long)]
        json: bool,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 全文检索条目(无头)。
    Search {
        /// 库文件路径。
        path: PathBuf,
        /// 检索串。
        query: String,
        /// 以 JSON 输出。
        #[arg(long)]
        json: bool,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 打印当前 TOTP 验证码到 stdout(无头,脚本友好)。
    Otp {
        /// 库文件路径。
        path: PathBuf,
        /// 条目 id(须为 password 条目且含 totp_secret)。
        id: i64,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 复制某字段到剪贴板,定时自动清空(无头)。
    Cp {
        /// 库文件路径。
        path: PathBuf,
        /// 条目 id。
        id: i64,
        /// 要复制的字段(默认 password)。
        #[arg(short, long, value_name = "FIELD")]
        field: Option<String>,
        /// 自动清空剪贴板的秒数(默认 20)。
        #[arg(long, value_name = "SECS", default_value_t = 20)]
        clear: u64,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 新增一条条目(无头)。向 stdout 打印 `added item <id>: <title>`。
    Add {
        /// 库文件路径。
        path: PathBuf,
        /// 条目标题。
        #[arg(long, value_name = "TITLE")]
        title: String,
        /// 完整 ItemData JSON,含 `"type"` tag(如 `{"type":"password",...}`)。
        #[arg(long, value_name = "JSON")]
        data: String,
        /// 标签(可重复)。
        #[arg(long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// 标记为收藏。
        #[arg(long)]
        favorite: bool,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 修改已有条目的字段(无头)。至少提供 --title/--data/--tag/--favorite/--no-favorite 之一。
    Edit {
        /// 库文件路径。
        path: PathBuf,
        /// 条目 id。
        id: i64,
        /// 新标题。
        #[arg(long, value_name = "TITLE")]
        title: Option<String>,
        /// 完整 ItemData JSON,含 `"type"` tag(替换整块 data)。
        #[arg(long, value_name = "JSON")]
        data: Option<String>,
        /// 标签(可重复;整体覆盖)。
        #[arg(long = "tag", value_name = "TAG")]
        tags: Option<Vec<String>>,
        /// 设为收藏。
        #[arg(long)]
        favorite: bool,
        /// 取消收藏。
        #[arg(long = "no-favorite")]
        no_favorite: bool,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 删除条目(无头)。默认交互确认,`-y` 跳过。
    Rm {
        /// 库文件路径。
        path: PathBuf,
        /// 条目 id。
        id: i64,
        /// 跳过确认提示。
        #[arg(short = 'y', long)]
        yes: bool,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
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

/// 解析 CLI → 构造 App → 进入 TUI,或分发无头命令。
fn run() -> color_eyre::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        // TUI 路径(行为不变)。
        Command::New { path } => {
            let app = App::for_create(path);
            ui::run(app)?;
        }
        Command::Open { path } => {
            let app = App::for_open(path);
            ui::run(app)?;
        }
        // 无头建库:不进入 TUI。
        Command::Init { path, passfile } => {
            zkv::cli::run_init(&path, passfile.as_deref())?;
        }
        // 无头路径:解锁 → 调对应 cli::run_*。
        // crate::error::Error: std::error::Error,`?` 自动转 color_eyre::Report。
        Command::Ls {
            path,
            r#type,
            tags,
            category,
            query,
            json,
            passfile,
        } => {
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            let f = zkv::cli::ListFilter {
                item_type: r#type,
                tags,
                category,
                query,
            };
            zkv::cli::run_ls(&u, &f, json)?;
        }
        Command::Get {
            path,
            id,
            field,
            json,
            passfile,
        } => {
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            zkv::cli::run_get(&u, id, field.as_deref(), json)?;
        }
        Command::Search {
            path,
            query,
            json,
            passfile,
        } => {
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            zkv::cli::run_search(&u, &query, json)?;
        }
        Command::Otp {
            path,
            id,
            passfile,
        } => {
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            zkv::cli::run_otp(&u, id)?;
        }
        Command::Cp {
            path,
            id,
            field,
            clear,
            passfile,
        } => {
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            zkv::cli::run_cp(&u, id, field.as_deref(), clear)?;
        }
        Command::Add {
            path,
            title,
            data,
            tags,
            favorite,
            passfile,
        } => {
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            zkv::cli::run_add(&u, &title, &data, tags, favorite)?;
        }
        Command::Edit {
            path,
            id,
            title,
            data,
            tags,
            favorite,
            no_favorite,
            passfile,
        } => {
            // 两个独立 bool flag 合成 Option<bool>:--favorite → Some(true),
            // --no-favorite → Some(false);两者都给则后者(no)优先(语义:取消)。
            let fav = if no_favorite {
                Some(false)
            } else if favorite {
                Some(true)
            } else {
                None
            };
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            zkv::cli::run_edit(
                &u,
                id,
                title.as_deref(),
                data.as_deref(),
                tags,
                fav,
            )?;
        }
        Command::Rm {
            path,
            id,
            yes,
            passfile,
        } => {
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            zkv::cli::run_rm(&u, id, yes)?;
        }
    }
    Ok(())
}
