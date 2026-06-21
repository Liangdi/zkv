//! zkv 入口:CLI 解析 → 构造 App → 进入 TUI 主循环。对应 PRD §8 启动流程。
//!
//! panic 恢复:在 color_eyre 默认 panic hook 之前,先恢复终端(关闭 raw mode、
//! 离开备用屏),避免 panic 时终端卡在 raw mode 导致输出乱码。

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{CommandFactory, Parser, Subcommand};

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
    /// 禁用 agent 口令缓存:本进程及自动拉起的 agent 都不启用,每条命令都需口令。
    /// 等价于设环境变量 ZKV_NO_AGENT=1。global:可出现在任意子命令之后。
    #[arg(long, global = true)]
    no_agent: bool,
}

#[derive(Subcommand, Debug)]
// Edit 变体字段众多导致与其它子命令体积差异较大;但 Command 仅在启动时解析一次、
// 立即 destructure 分发,不会大量堆叠或移动,boxing 反而徒增复杂度,故允许。
#[allow(clippy::large_enum_variant)]
enum Command {
    /// 创建新的加密库(进入 TUI)。
    New {
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
    },
    /// 打开已有加密库(进入 TUI)。
    Open {
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
    },
    /// 无头建库(不进入 TUI)。口令取自 ZKV_PASSPHRASE / --passfile / 交互提示;目标已存在则报错。
    Init {
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 口令文件路径(env ZKV_PASSPHRASE 优先,无则交互)。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 修改主口令(验旧口令 → 用新口令 + 新 salt 重新加密整库)。
    Passwd {
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 旧口令文件(默认 ZKV_PASSPHRASE / 交互)。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
        /// 新口令文件(默认 ZKV_NEW_PASSPHRASE / 交互输两次)。
        #[arg(long = "new-passfile", value_name = "PATH")]
        new_passfile: Option<PathBuf>,
    },
    /// 列出库中的条目(无头,可脚本化)。
    Ls {
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 仅列出该模板 id 的条目(如 password/note/card/wifi/...)。
        #[arg(short, long, value_name = "TEMPLATE")]
        r#type: Option<String>,
        /// 仅列出挂有该标签的条目(可重复)。
        #[arg(long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// 仅列出该分类名称下的条目。
        #[arg(long = "cat", value_name = "CATEGORY")]
        category: Option<String>,
        /// 全文检索串(命中标题与正文)。
        #[arg(short, long, value_name = "QUERY")]
        query: Option<String>,
        /// 仅列出收藏项。
        #[arg(short = 'F', long)]
        favorite: bool,
        /// 以 JSON 输出。
        #[arg(long)]
        json: bool,
        /// 口令文件路径(优先级低于 ZKV_PASSPHRASE 环境变量)。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 打印单条条目或某字段原始值(无头)。
    Get {
        /// 条目 id(与 --find 至少给其一)。
        id: Option<i64>,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 仅打印该字段(按字段名,如 username/password/url/totp/notes;特殊:title/type)。
        #[arg(short, long, value_name = "FIELD")]
        field: Option<String>,
        /// 以 JSON 输出整条条目(与 -f 互斥语义:--json 时忽略 -f)。
        #[arg(long)]
        json: bool,
        /// 按标题定位条目(exact 优先,否则唯一前缀匹配)。
        #[arg(long, value_name = "TITLE")]
        find: Option<String>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 全文检索条目(无头)。
    Search {
        /// 检索串。
        query: String,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv;多位置参数时 path 在最后)。
        path: Option<PathBuf>,
        /// 以 JSON 输出。
        #[arg(long)]
        json: bool,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 打印当前 TOTP 验证码到 stdout(无头,脚本友好)。
    Otp {
        /// 条目 id(须为 password 条目且含 totp_secret;与 --find 至少给其一)。
        id: Option<i64>,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 按标题定位条目(exact 优先,否则唯一前缀匹配)。
        #[arg(long, value_name = "TITLE")]
        find: Option<String>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 复制某字段到剪贴板,定时自动清空(无头)。
    Cp {
        /// 条目 id(与 --find 至少给其一)。
        id: Option<i64>,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 要复制的字段(默认 password)。
        #[arg(short, long, value_name = "FIELD")]
        field: Option<String>,
        /// 自动清空剪贴板的秒数(默认 20)。
        #[arg(long, value_name = "SECS", default_value_t = 20)]
        clear: u64,
        /// 按标题定位条目(exact 优先,否则唯一前缀匹配)。
        #[arg(long, value_name = "TITLE")]
        find: Option<String>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 新增一条条目(无头)。向 stdout 打印 `added item <id>: <title>`。
    Add {
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 条目标题。
        #[arg(long, value_name = "TITLE")]
        title: String,
        /// 模板 id(默认 password)。与 --data 互斥使用时,data 决定最终模板。
        #[arg(long, value_name = "TEMPLATE", default_value = "password")]
        template: String,
        /// 可选:完整字段 JSON(新形状 Vec<Field>、新 Item JSON,或旧 ItemData 均可)。省略则用模板空字段。
        #[arg(long, value_name = "JSON")]
        data: Option<String>,
        /// 设置字段 `name=value`(可重复;按字段名写入,不存在则新增)。
        #[arg(long = "set", value_name = "NAME=VALUE")]
        sets: Vec<String>,
        /// 标签(可重复)。
        #[arg(long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// 标记为收藏。
        #[arg(long)]
        favorite: bool,
        /// 自动生成密码(作用于 name=="password" 的 Secret 字段;可带长度,如 --gen-password 24)。
        #[arg(long, value_name = "LEN", num_args = 0..=1, default_missing_value = "20")]
        gen_password: Option<usize>,
        /// otpauth:// URI:解析出 secret,覆盖首个 kind=Totp 字段。与 --gen-password 可共存。
        /// 与 --qr / --qr-url 互斥(三者都是 TOTP 来源,只能给一个)。
        #[arg(long, value_name = "URI", conflicts_with_all = ["qr", "qr_url"])]
        otpauth: Option<String>,
        /// 二维码图片本地路径:解码出 otpauth:// URI 后写入首个 Totp 字段。
        #[arg(long, value_name = "PATH", conflicts_with_all = ["otpauth", "qr_url"])]
        qr: Option<PathBuf>,
        /// 二维码图片 URL(http/https,或 data:):取图解码出 otpauth:// URI。
        #[arg(long, value_name = "URL", conflicts_with_all = ["otpauth", "qr"])]
        qr_url: Option<String>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 生成强随机密码(打印到 stdout)。不解锁库、不需要口令。
    Gen {
        /// 密码长度(默认 20)。
        #[arg(default_value_t = 20)]
        length: usize,
        /// 关闭符号(默认含符号)。
        #[arg(long = "no-symbols")]
        no_symbols: bool,
        /// 去除易混字符(0/O/o/1/l/I 等)。
        #[arg(long = "no-ambiguous")]
        no_ambiguous: bool,
    },
    /// 打印指定 shell 的补全脚本到 stdout(供 source 或安装到补全目录)。不解锁库、不需要口令。
    Completions {
        /// 目标 shell:bash / zsh / fish / elvish / powershell。
        shell: clap_complete::Shell,
    },
    /// 修改已有条目的字段(无头)。至少提供 --title/--data/--tag/--favorite/--no-favorite/--set/--add-tag/--rm-tag/--otpauth 之一。
    Edit {
        /// 条目 id(与 --find 至少给其一)。
        id: Option<i64>,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 新标题。
        #[arg(long, value_name = "TITLE")]
        title: Option<String>,
        /// 完整字段 JSON(新形状 Vec<Field>、新 Item JSON,或旧 ItemData;替换整块 fields)。与 --set 互斥。
        #[arg(long, value_name = "JSON")]
        data: Option<String>,
        /// 标签(可重复;整体覆盖)。与 --add-tag/--rm-tag 互斥。
        #[arg(long = "tag", value_name = "TAG")]
        tags: Option<Vec<String>>,
        /// 设为收藏。
        #[arg(long)]
        favorite: bool,
        /// 取消收藏。
        #[arg(long = "no-favorite")]
        no_favorite: bool,
        /// 设置分类(按名称;不存在则报错)。
        #[arg(long, value_name = "CATEGORY")]
        cat: Option<String>,
        /// 设置字段 `name=value`(可重复;按字段名更新,不存在则新增)。与 --data 互斥。
        #[arg(long = "set", value_name = "NAME=VALUE")]
        sets: Vec<String>,
        // --- 标签增删(与 --tag 整体覆盖互斥)---
        /// 追加标签(可重复;去重)。
        #[arg(long = "add-tag", value_name = "TAG")]
        add_tags: Vec<String>,
        /// 移除标签(可重复)。
        #[arg(long = "rm-tag", value_name = "TAG")]
        rm_tags: Vec<String>,
        /// otpauth:// URI:解析出 secret,覆盖首个 kind=Totp 字段。
        /// 与 --qr / --qr-url 互斥(三者都是 TOTP 来源,只能给一个)。
        #[arg(long, value_name = "URI", conflicts_with_all = ["qr", "qr_url"])]
        otpauth: Option<String>,
        /// 二维码图片本地路径:解码出 otpauth:// URI 后写入首个 Totp 字段。
        #[arg(long, value_name = "PATH", conflicts_with_all = ["otpauth", "qr_url"])]
        qr: Option<PathBuf>,
        /// 二维码图片 URL(http/https,或 data:):取图解码出 otpauth:// URI。
        #[arg(long, value_name = "URL", conflicts_with_all = ["otpauth", "qr"])]
        qr_url: Option<String>,
        /// 按标题定位条目(exact 优先,否则唯一前缀匹配)。
        #[arg(long, value_name = "TITLE")]
        find: Option<String>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 删除条目(无头)。默认交互确认,`-y` 跳过。
    Rm {
        /// 条目 id(与 --find 至少给其一)。
        id: Option<i64>,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 跳过确认提示。
        #[arg(short = 'y', long)]
        yes: bool,
        /// 按标题定位条目(exact 优先,否则唯一前缀匹配)。
        #[arg(long, value_name = "TITLE")]
        find: Option<String>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 分类管理。
    Cat {
        #[command(subcommand)]
        action: CatCmd,
    },
    /// 标签管理。
    Tag {
        #[command(subcommand)]
        action: TagCmd,
    },
    /// 附件管理。
    Attach {
        #[command(subcommand)]
        action: AttachCmd,
    },
    /// 导出全部条目(明文!stdout 或 -o 文件)。json 无损;csv 仅 password。
    Export {
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 导出格式(json 无损;csv 仅 password)。
        #[arg(long, value_enum, default_value_t = zkv::cli::Format::Json)]
        format: zkv::cli::Format,
        /// 输出文件路径(省略则写 stdout)。**输出为明文,文件建议 0600**。
        #[arg(short = 'o', long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 从文件或 stdin 导入条目(--format,默认 json)。
    ///
    /// 总是新建 id(不覆盖);重复导入会创建重复条目。
    Import {
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 输入文件路径(省略则读 stdin)。
        #[arg(short = 'i', long, value_name = "PATH")]
        input: Option<PathBuf>,
        /// 导入格式(同 export)。
        #[arg(long, value_enum, default_value_t = zkv::cli::Format::Json)]
        format: zkv::cli::Format,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// agent 口令缓存守护进程管理(查看状态 / 停止)。
    Agent {
        #[command(subcommand)]
        action: AgentCmd,
    },
    /// 清空 agent 缓存的所有密钥(让所有已解锁库立即"忘记"口令,需重新输入)。
    Lock,
}

/// `agent` 子命令组(口令缓存守护进程管理)。
#[derive(Subcommand, Debug)]
enum AgentCmd {
    /// 显示 agent 运行状态(pid / socket / 已缓存库 / 剩余空闲)。
    Status,
    /// 停止运行中的 agent(清空缓存密钥并退出进程)。
    Stop,
    /// 【内部】以前台服务模式运行 agent(由首次需要口令的命令自动拉起,一般无需手动调用)。
    #[command(hide = true)]
    Serve {
        /// socket 路径。
        #[arg(long, value_name = "PATH")]
        socket: PathBuf,
        /// 闲置 TTL(秒);超过即自退出。默认取 ZKV_LOCK_SECS(同 TUI 自动锁)。
        #[arg(long, default_value_t = zkv::agent::ttl_secs())]
        ttl: u64,
    },
}

/// `cat` 子命令组(分类管理)。
#[derive(Subcommand, Debug)]
enum CatCmd {
    /// 新增分类(`--parent` 指定父分类名,可选)。
    Add {
        /// 分类名。
        name: String,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 父分类名(可选)。
        #[arg(long, value_name = "PARENT")]
        parent: Option<String>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 删除分类(by id 或名)。子条目 category_id 置空。
    Rm {
        /// 分类 id(数字)或名称。
        target: String,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 列出全部分类。
    Ls {
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
}

/// `tag` 子命令组(标签管理)。
#[derive(Subcommand, Debug)]
enum TagCmd {
    /// 列出全部标签。
    Ls {
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 删除标签(by 名)。
    Rm {
        /// 标签名。
        name: String,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 改标签名。
    Mv {
        /// 原标签名。
        from: String,
        /// 新标签名。
        to: String,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
}

/// `attach` 子命令组(附件管理)。
#[derive(Subcommand, Debug)]
enum AttachCmd {
    /// 给条目挂一个文件附件(读取文件 → 加密内嵌)。
    Add {
        /// 条目 id。
        item: i64,
        /// 要挂载的本地文件路径。
        file: PathBuf,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 覆盖 MIME 类型推断(可选)。
        #[arg(long, value_name = "MIME")]
        mime: Option<String>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 列出条目的附件(不输出 blob)。
    Ls {
        /// 条目 id。
        item: i64,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 导出附件 blob 到文件或 stdout。
    Get {
        /// 条目 id(用于校验附件归属)。
        item: i64,
        /// 附件 id。
        att: i64,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 输出文件路径(缺省则写 stdout,二进制安全)。
        #[arg(short = 'o', long, value_name = "PATH")]
        output: Option<PathBuf>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
    /// 删除附件。
    Rm {
        /// 条目 id(用于校验附件归属)。
        item: i64,
        /// 附件 id。
        att: i64,
        /// 库文件路径(省略则用默认库 ~/.zkv/default.zkv)。
        path: Option<PathBuf>,
        /// 口令文件路径。
        #[arg(long, value_name = "PATH")]
        passfile: Option<PathBuf>,
    },
}

/// 解析 `name=value` 字符串列表为 `(name, value)` 有序对。
///
/// 无 `=` 的项按「值为空」处理(即设置该字段为空串)。重复 name 保留全部(后者覆盖前者)。
fn parse_sets(items: &[String]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|s| match s.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (s.clone(), String::new()),
        })
        .collect()
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
            // 预期内的业务错误(条目不存在、缺参数、口令错误等)只打印一行人话,
            // 不把内部的 Location / Backtrace 报告吐给最终用户。需要完整调试报告
            // (调用位置 + backtrace)时设 RUST_BACKTRACE=1,走 color_eyre 的 Debug 格式。
            if std::env::var_os("RUST_BACKTRACE").is_some() {
                eprintln!("{report:?}");
            } else {
                // 仅着色单行的 `error:` 标签;多行 report 正文保持纯净,避免每行 reset 掉色。
                eprintln!("{} {report}", zkv::style::err("error:"));
            }
            ExitCode::FAILURE
        }
    }
}

/// 确保库文件的父目录存在(`init`/`new` 用);并在 Unix 下把新建的 `~/.zkv`
/// 目录设为 0700(仅对**新建**的目录,已存在不动)。
fn ensure_parent_dir(path: &Path) -> color_eyre::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 仅在目录原本不存在(本次新建)时收紧到 0700;已存在的不动。
        let did_not_exist = !parent.exists();
        std::fs::create_dir_all(parent)
            .map_err(|e| color_eyre::eyre::eyre!("failed to create {}: {e}", parent.display()))?;
        if did_not_exist {
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| color_eyre::eyre::eyre!("failed to chmod {}: {e}", parent.display()),
            )?;
        }
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| color_eyre::eyre::eyre!("failed to create {}: {e}", parent.display()))?;
    }
    Ok(())
}

/// 读命令友好检查:若解析出的是默认库(用户未显式给 path)且文件不存在,
/// 给出带 `zkv init` 提示的友好错误。显式给的 path 不在此拦截(走 unlock 的 IO 错误)。
fn require_default_exists(path: &Path, was_default: bool) -> color_eyre::Result<()> {
    if was_default && !path.exists() {
        return Err(color_eyre::eyre::eyre!(
            "no vault at {}; run `zkv init` to create it (or `zkv <cmd> <file>`)",
            path.display()
        ));
    }
    Ok(())
}

/// 解析 CLI → 构造 App → 进入 TUI,或分发无头命令。
fn run() -> color_eyre::Result<()> {
    let cli = Cli::parse();
    // --no-agent:镜像 ui 模块的 env 模式,使 agent::enabled() 成为唯一 opt-out 闸门,
    // 无需把 bool 穿透 13 个 Unlocked::unlock 调用点。
    if cli.no_agent {
        // 安全性:set_var 在多线程下不安全(Rust 2024 标记为 unsafe)。zkv 的 CLI 主线程
        // 在解析后、派发命令前单线程执行此变更,且仅设进程内 env,无并发访问,故安全。
        unsafe {
            std::env::set_var("ZKV_NO_AGENT", "1");
        }
    }
    match cli.command {
        // TUI 路径(行为不变)。
        Command::New { path } => {
            let path = zkv::cli::resolve_vault_path(path)?;
            ensure_parent_dir(&path)?;
            let app = App::for_create(path);
            ui::run(app)?;
        }
        Command::Open { path } => {
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let app = App::for_open(path);
            ui::run(app)?;
        }
        // 无头建库:不进入 TUI。
        Command::Init { path, passfile } => {
            let path = zkv::cli::resolve_vault_path(path)?;
            ensure_parent_dir(&path)?;
            zkv::cli::run_init(&path, passfile.as_deref())?;
        }
        Command::Passwd {
            path,
            passfile,
            new_passfile,
        } => {
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            if was_default && !path.exists() {
                return Err(color_eyre::eyre::eyre!(
                    "no vault at {}; run `zkv init` to create it",
                    path.display()
                ));
            }
            zkv::cli::run_passwd(&path, passfile.as_deref(), new_passfile.as_deref())?;
        }
        // 无头路径:解锁 → 调对应 cli::run_*。
        // crate::error::Error: std::error::Error,`?` 自动转 color_eyre::Report。
        Command::Ls {
            path,
            r#type,
            tags,
            category,
            query,
            favorite,
            json,
            passfile,
        } => {
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            let f = zkv::cli::ListFilter {
                template_id: r#type,
                tags,
                category,
                query,
                favorite_only: false,
            };
            zkv::cli::run_ls(&u, &f, favorite, json)?;
        }
        Command::Get {
            path,
            id,
            field,
            json,
            find,
            passfile,
        } => {
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            let id = zkv::cli::resolve_id(u.db.conn(), id, find.as_deref())?;
            zkv::cli::run_get(&u, id, field.as_deref(), json)?;
        }
        Command::Search {
            path,
            query,
            json,
            passfile,
        } => {
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            zkv::cli::run_search(&u, &query, json)?;
        }
        Command::Otp {
            path,
            id,
            find,
            passfile,
        } => {
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            let id = zkv::cli::resolve_id(u.db.conn(), id, find.as_deref())?;
            zkv::cli::run_otp(&u, id)?;
        }
        Command::Cp {
            path,
            id,
            field,
            clear,
            find,
            passfile,
        } => {
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            let id = zkv::cli::resolve_id(u.db.conn(), id, find.as_deref())?;
            zkv::cli::run_cp(&u, id, field.as_deref(), clear)?;
        }
        Command::Add {
            path,
            title,
            template,
            data,
            sets,
            tags,
            favorite,
            gen_password,
            otpauth,
            qr,
            qr_url,
            passfile,
        } => {
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            // 把 --otpauth / --qr / --qr-url 三者(clap 保证互斥)解析成单条 otpauth URI。
            let otpauth_arg = zkv::cli::resolve_totp_source(
                otpauth.as_deref(),
                qr.as_deref(),
                qr_url.as_deref(),
            )?;
            let fields = zkv::cli::EditFields {
                sets: parse_sets(&sets),
            };
            zkv::cli::run_add(
                &u,
                &title,
                &template,
                data.as_deref(),
                &fields,
                tags,
                favorite,
                gen_password,
                otpauth_arg.as_deref(),
            )?;
        }
        // gen:纯生成,不解锁库、不需要口令。
        Command::Gen {
            length,
            no_symbols,
            no_ambiguous,
        } => {
            zkv::cli::run_gen(length, !no_symbols, !no_ambiguous)?;
        }
        // completions:打印 shell 补全脚本到 stdout。不解锁库、不需要口令。
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let mut out = std::io::stdout();
            clap_complete::generate(shell, &mut cmd, "zkv", &mut out);
        }
        Command::Edit {
            path,
            id,
            title,
            data,
            tags,
            favorite,
            no_favorite,
            cat,
            sets,
            add_tags,
            rm_tags,
            otpauth,
            qr,
            qr_url,
            find,
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
            let fields = zkv::cli::EditFields {
                sets: parse_sets(&sets),
            };
            let tag_delta = zkv::cli::TagDelta {
                add: add_tags,
                remove: rm_tags,
            };
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            let id = zkv::cli::resolve_id(u.db.conn(), id, find.as_deref())?;
            // 把 --otpauth / --qr / --qr-url 三者(clap 保证互斥)解析成单条 otpauth URI。
            let otpauth_arg = zkv::cli::resolve_totp_source(
                otpauth.as_deref(),
                qr.as_deref(),
                qr_url.as_deref(),
            )?;
            zkv::cli::run_edit(
                &u,
                id,
                title.as_deref(),
                data.as_deref(),
                tags,
                fav,
                cat.as_deref(),
                &fields,
                &tag_delta,
                otpauth_arg.as_deref(),
            )?;
        }
        Command::Rm {
            path,
            id,
            yes,
            find,
            passfile,
        } => {
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            let id = zkv::cli::resolve_id(u.db.conn(), id, find.as_deref())?;
            zkv::cli::run_rm(&u, id, yes)?;
        }
        // 嵌套子命令:先从 action 中取出 path + passfile → unlock → 交给 cli 层的
        // run_cat/run_tag(已解锁的 &Unlocked + action 引用)。
        Command::Cat { action } => {
            let (path, passfile) = cat_path_passfile(&action);
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            run_cat(&u, &action)?;
        }
        Command::Tag { action } => {
            let (path, passfile) = tag_path_passfile(&action);
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            run_tag(&u, &action)?;
        }
        Command::Attach { action } => {
            let (path, passfile) = attach_path_passfile(&action);
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            run_attach(&u, &action)?;
        }
        Command::Export {
            path,
            format,
            output,
            passfile,
        } => {
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            zkv::cli::run_export(&u, format, output.as_deref())?;
        }
        Command::Import {
            path,
            input,
            format,
            passfile,
        } => {
            let was_default = path.is_none();
            let path = zkv::cli::resolve_vault_path(path)?;
            require_default_exists(&path, was_default)?;
            let u = zkv::cli::Unlocked::unlock(&path, passfile.as_deref())?;
            zkv::cli::run_import(&u, format, input.as_deref())?;
        }
        Command::Agent { action } => match action {
            AgentCmd::Status => match zkv::agent::status() {
                Some(s) => {
                    println!("agent running: pid={} socket={}", s.pid, s.socket);
                    println!(
                        "cached vaults ({}): {}",
                        s.vaults.len(),
                        if s.vaults.is_empty() {
                            "(none)".to_string()
                        } else {
                            s.vaults.join(", ")
                        }
                    );
                    println!("idle: {}/{}s", s.idle_secs, s.ttl_secs);
                }
                None => println!("agent not running"),
            },
            AgentCmd::Stop => {
                zkv::agent::stop();
                println!("agent stop requested");
            }
            AgentCmd::Serve { socket, ttl } => {
                zkv::agent::serve(&socket, std::time::Duration::from_secs(ttl))?;
            }
        },
        Command::Lock => {
            zkv::agent::lock_all();
            println!("cleared cached keys");
        }
    }
    Ok(())
}

/// 从 `CatCmd` 提取 (path, passfile)。
fn cat_path_passfile(action: &CatCmd) -> (Option<PathBuf>, Option<PathBuf>) {
    match action {
        CatCmd::Add {
            path, passfile, ..
        }
        | CatCmd::Rm {
            path, passfile, ..
        }
        | CatCmd::Ls {
            path, passfile, ..
        } => (path.clone(), passfile.clone()),
    }
}

/// 分发 `cat` 子命令(已解锁)。
fn run_cat(u: &zkv::cli::Unlocked, action: &CatCmd) -> color_eyre::Result<()> {
    match action {
        CatCmd::Add {
            name, parent, ..
        } => {
            zkv::cli::run_cat_add(u, name, parent.as_deref())?;
        }
        CatCmd::Rm { target, .. } => {
            zkv::cli::run_cat_rm(u, target)?;
        }
        CatCmd::Ls { .. } => {
            zkv::cli::run_cat_ls(u)?;
        }
    }
    Ok(())
}

/// 从 `TagCmd` 提取 (path, passfile)。
fn tag_path_passfile(action: &TagCmd) -> (Option<PathBuf>, Option<PathBuf>) {
    match action {
        TagCmd::Ls {
            path, passfile, ..
        }
        | TagCmd::Rm {
            path, passfile, ..
        }
        | TagCmd::Mv {
            path, passfile, ..
        } => (path.clone(), passfile.clone()),
    }
}

/// 分发 `tag` 子命令(已解锁)。
fn run_tag(u: &zkv::cli::Unlocked, action: &TagCmd) -> color_eyre::Result<()> {
    match action {
        TagCmd::Ls { .. } => {
            zkv::cli::run_tag_ls(u)?;
        }
        TagCmd::Rm { name, .. } => {
            zkv::cli::run_tag_rm(u, name)?;
        }
        TagCmd::Mv { from, to, .. } => {
            zkv::cli::run_tag_mv(u, from, to)?;
        }
    }
    Ok(())
}

/// 从 `AttachCmd` 提取 (path, passfile)。
fn attach_path_passfile(action: &AttachCmd) -> (Option<PathBuf>, Option<PathBuf>) {
    match action {
        AttachCmd::Add {
            path, passfile, ..
        }
        | AttachCmd::Ls {
            path, passfile, ..
        }
        | AttachCmd::Get {
            path, passfile, ..
        }
        | AttachCmd::Rm {
            path, passfile, ..
        } => (path.clone(), passfile.clone()),
    }
}

/// 分发 `attach` 子命令(已解锁)。
fn run_attach(u: &zkv::cli::Unlocked, action: &AttachCmd) -> color_eyre::Result<()> {
    match action {
        AttachCmd::Add {
            item, file, mime, ..
        } => {
            zkv::cli::run_attach_add(u, *item, file, mime.as_deref())?;
        }
        AttachCmd::Ls { item, .. } => {
            zkv::cli::run_attach_ls(u, *item)?;
        }
        AttachCmd::Get {
            item, att, output, ..
        } => {
            zkv::cli::run_attach_get(u, *item, *att, output.as_deref())?;
        }
        AttachCmd::Rm { item, att, .. } => {
            zkv::cli::run_attach_rm(u, *item, *att)?;
        }
    }
    Ok(())
}
