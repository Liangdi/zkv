//! 无头(headless)CLI 命令层。对应 PRD §8(可脚本化命令行)。
//!
//! 与 TUI 路径完全解耦:不引用 `app`/`ui`,直接调用 L2/L3 层
//! ([`crate::vault`] / [`crate::store`] / [`crate::search`] / [`crate::clipboard`])。
//!
//! ## 口令来源
//! [`read_passphrase`] 按以下优先级解析口令,全部用 [`zeroize::Zeroizing`] 包裹以避免明文残留:
//! 1. 环境变量 `ZKV_PASSPHRASE`
//! 2. `--passfile <path>` 指定的文件(去掉末尾单个 `\n` / `\r\n`)
//! 3. TTY 交互式提示(`rpassword`)
//!
//! ## 解锁包装
//! [`Unlocked`] 在解锁后持有 `Database` + 派生 `MasterKey` + `KdfParams` + salt,
//! 通过 [`Unlocked::save`] 用已派生 key 落盘(不重跑 Argon2)。
//!
//! ## 命令分层
//! 本模块提供**只读**命令(`ls`/`get`/`search`/`cp`)与**写**命令(`add`/`edit`/`rm`)
//! 的纯函数实现。每个 `run_*` 接收**已类型化**的参数(非 clap 的 `ArgMatches`),
//! 便于单测与 `main.rs` 分发。写命令在变更后立即 `save` 落盘。

use std::io::Write;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::clipboard;
use crate::crypto::{KdfParams, MasterKey};
use crate::db::Database;
use crate::error::{Error, Result};
use crate::model::{Attachment, Category, Item, ItemData, ItemType};
use crate::search::{self, Filter};
use crate::store;
use crate::vault;

/// 解析口令的三种来源,按优先级:环境变量 `ZKV_PASSPHRASE` > `--passfile` > TTY 提示。
///
/// 返回 [`Zeroizing<String>`],避免明文口令在堆上长期残留。
pub fn read_passphrase(passfile: Option<&Path>) -> Result<Zeroizing<String>> {
    // 1. 环境变量(优先级最高,便于 CI/脚本注入)。
    // NOTE: 环境变量本身由调用方负责安全;这里仅在进程内复制一份并 zeroize 包裹。
    if let Some(val) = std::env::var_os("ZKV_PASSPHRASE") {
        let s = val
            .into_string()
            .map_err(|_| Error::Other("ZKV_PASSPHRASE is not valid UTF-8".into()))?;
        return Ok(Zeroizing::new(s));
    }

    // 2. --passfile:读取整个文件,去掉末尾单个换行。
    if let Some(p) = passfile {
        let raw = std::fs::read_to_string(p)
            .map_err(|e| Error::Other(format!("failed to read passfile {}: {e}", p.display())))?;
        return Ok(Zeroizing::new(strip_trailing_newline(raw)));
    }

    // 3. TTY 交互式提示。
    let pass = rpassword::prompt_password("passphrase: ")?;
    Ok(Zeroizing::new(pass))
}

/// 去掉末尾的单个 `\n` 或 `\r\n`。多换行/中间换行保留。
fn strip_trailing_newline(mut s: String) -> String {
    if s.ends_with("\r\n") {
        s.truncate(s.len() - 2);
    } else if s.ends_with('\n') {
        s.pop();
    }
    s
}

/// 解锁后的库包装:持有 db + 派生 key/kdf/salt,`save` 用已派生 key 落盘。
///
/// `key`/`kdf`/`salt` 设为私有:仅通过 [`Unlocked::save`] 暴露写回能力,
/// 避免调用方误用裸 key。
pub struct Unlocked {
    /// 底层数据库(可借用连接做查询)。
    pub db: Database,
    /// 库文件路径。
    pub path: PathBuf,
    key: MasterKey,
    kdf: KdfParams,
    salt: [u8; 16],
}

/// 无头建库:用口令(env `ZKV_PASSPHRASE`/`--passfile`/交互)创建一个新的空 `.zkv` 库,
/// 不进入 TUI。目标已存在则报错(不覆盖)。
///
/// 与 `new`/`open` 的 TUI 路径完全解耦:适用于 CI/脚本/远程无 TTY 环境。
pub fn run_init(path: &Path, passfile: Option<&Path>) -> Result<()> {
    // 先判重:在派生/加密之前给出清晰错误,而非依赖底层 IO 报错。
    if path.exists() {
        return Err(Error::Other(format!(
            "vault already exists: {} (refusing to overwrite)",
            path.display()
        )));
    }
    let pass = read_passphrase(passfile)?;
    // 默认 KDF(Argon2id 64MiB/3/4),生产级强度;建空库。
    vault::create(path, pass.as_str())?;
    println!("created vault at {}", path.display());
    Ok(())
}

impl Unlocked {
    /// 解锁 `path`,缓存 key/kdf/salt。
    pub fn unlock(path: &Path, passfile: Option<&Path>) -> Result<Unlocked> {
        let pass = read_passphrase(passfile)?;
        let (db, key, kdf, salt) = vault::unlock_full(path, pass.as_str())?;
        Ok(Unlocked {
            db,
            path: path.to_path_buf(),
            key,
            kdf,
            salt,
        })
    }

    /// 用已派生 key 落盘(不重跑 Argon2)。
    pub fn save(&self) -> Result<()> {
        vault::save_with_key(&self.path, &self.key, &self.kdf, self.salt, &self.db)
    }
}

/// `ls`/`search` 的过滤参数(已类型化)。`category` 按分类**名称**(运行时解析成 id)。
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    /// 仅列出该类型。
    pub item_type: Option<ItemType>,
    /// 仅列出挂有这些标签中任意一个的条目。
    pub tags: Vec<String>,
    /// 仅列出该分类名称下的条目(`None` 表示不限)。
    pub category: Option<String>,
    /// FTS5 全文检索串(`None` 表示不限)。
    pub query: Option<String>,
    /// 仅列出收藏(`true` 时透传给 [`search::Filter::favorite_only`])。
    pub favorite_only: bool,
}

/// 把 `ListFilter` + 已解析的 `category_id` 转成 [`search::Filter`]。
fn to_search_filter(list: &ListFilter, category_id: Option<i64>) -> Filter {
    Filter {
        query: list.query.clone(),
        category: category_id,
        tags: list.tags.clone(),
        item_type: list.item_type,
        favorite_only: list.favorite_only,
    }
}

/// 根据分类名解析其 id;找不到返回 `None`(调用方可决定报错或空结果)。
fn category_id_by_name(conn: &rusqlite::Connection, name: &str) -> Result<Option<i64>> {
    let cats = store::list_categories(conn)?;
    Ok(cats.into_iter().find(|c| c.name == name).and_then(|c| c.id))
}

/// 根据标签名解析其 id;找不到返回 `None`(调用方可决定报错或空结果)。
fn tag_id_by_name(conn: &rusqlite::Connection, name: &str) -> Result<Option<i64>> {
    let tags = store::list_tags(conn)?;
    Ok(tags.into_iter().find(|t| t.name == name).map(|t| t.id))
}

/// `ls`/`search` 公用:把条目列表格式化后写到 `out`。
///
/// - `json = true`:`serde_json::to_string_pretty`(`Item` 已 derive `Serialize`)。
/// - 否则:人类可读,每行 `id\ttype\ttitle\t[tags]\tupdated`。
fn write_items<W: Write>(out: &mut W, items: &[Item], json: bool) -> Result<()> {
    if json {
        let s = serde_json::to_string_pretty(items)?;
        writeln!(out, "{s}")?;
        return Ok(());
    }
    if items.is_empty() {
        writeln!(out, "(no items)")?;
        return Ok(());
    }
    for it in items {
        let id = it.id.unwrap_or(-1);
        let tags = if it.tags.is_empty() {
            String::from("-")
        } else {
            it.tags.join(",")
        };
        writeln!(
            out,
            "{}\t{}\t{}\t[{}]\t{}",
            id,
            it.item_type.as_str(),
            it.title,
            tags,
            it.updated_at
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 字段提取(供 get/cp 复用)
// ---------------------------------------------------------------------------

/// 按 `field` 名提取条目的原始字段值。
///
/// 字段名映射:
/// - 通用:`title`
/// - password:`username`/`password`/`url`/`totp`/`notes`
/// - note:`format`/`content`
/// - card:`holder`/`number`/`expiry`/`cvv`/`bank`/`notes`
///
/// 未知字段名或类型不匹配返回 [`Error::Other`]。
pub fn item_field(item: &Item, field: &str) -> Result<String> {
    use crate::model::ItemData::*;
    // 通用字段优先。
    if field == "title" {
        return Ok(item.title.clone());
    }
    let val = match (&item.data, field) {
        (Password { username, .. }, "username") => username.clone(),
        (Password { password, .. }, "password") => password.clone(),
        (Password { url, .. }, "url") => url.clone(),
        (Password { totp_secret, .. }, "totp") => totp_secret.clone(),
        (Password { notes, .. }, "notes") => notes.clone(),
        (Note { format, .. }, "format") => format.clone(),
        (Note { content, .. }, "content") => content.clone(),
        (Card { holder, .. }, "holder") => holder.clone(),
        (Card { number, .. }, "number") => number.clone(),
        (Card { expiry, .. }, "expiry") => expiry.clone(),
        (Card { cvv, .. }, "cvv") => cvv.clone(),
        (Card { bank, .. }, "bank") => bank.clone(),
        (Card { notes, .. }, "notes") => notes.clone(),
        _ => {
            return Err(Error::Other(format!(
                "field '{field}' not valid for {} item",
                item.item_type.as_str()
            )));
        }
    };
    Ok(val)
}

// ---------------------------------------------------------------------------
// 写命令(add/edit/rm)
// ---------------------------------------------------------------------------

/// 由 [`ItemData`] 的变体推导对应的 [`ItemType`],保证 `Item.item_type` 与 data 一致。
fn item_type_of(data: &ItemData) -> ItemType {
    use crate::model::ItemData::*;
    match data {
        Password { .. } => ItemType::Password,
        Note { .. } => ItemType::Note,
        Card { .. } => ItemType::Card,
    }
}

/// `add`:新增一条条目。`data_json` 是**完整** [`ItemData`] JSON(含 `"type"` tag)。
///
/// `gen_password = Some(len)` 时,`data_json` 必须是 `ItemData::Password`,其 `password` 字段
/// 会被 `generate_password(len, true, true)` 生成的强密码**覆盖**。
///
/// 成功后向 stdout 打印 `added item <id>: <title>` 并返回新 id。
/// 若用了 `--gen-password`,生成的明文密码打到 **stderr**(`generated password for item <id>: <pw>`),
/// 不污染 stdout 的 id 行,但用户能拿到。
pub fn run_add(
    u: &Unlocked,
    title: &str,
    data_json: &str,
    tags: Vec<String>,
    favorite: bool,
    gen_password: Option<usize>,
) -> Result<i64> {
    let mut data: ItemData = serde_json::from_str(data_json)?;

    // 若指定 --gen-password:必须是 Password 条目,覆盖其 password 字段。
    let generated = if let Some(len) = gen_password {
        match &mut data {
            ItemData::Password { password, .. } => {
                let pw = generate_password(len, true, true)?;
                *password = pw.clone();
                Some(pw)
            }
            _ => return Err(Error::Other("--gen-password only applies to password items".into())),
        }
    } else {
        None
    };

    let item_type = item_type_of(&data);
    let mut item = Item {
        id: None,
        item_type,
        title: title.into(),
        category_id: None,
        data,
        favorite,
        tags,
        created_at: 0,
        updated_at: 0,
    };
    let id = store::insert_item(u.db.conn(), &mut item)?;
    u.save()?;
    println!("added item {id}: {title}");
    // 生成密码打到 stderr:用户主动要生成,理应看到;又不污染 stdout 的 id 行。
    if let Some(pw) = generated {
        eprintln!("generated password for item {id}: {pw}");
    }
    Ok(id)
}

// ---------------------------------------------------------------------------
// 密码生成
// ---------------------------------------------------------------------------

/// 易混字符集(肉眼难分辨),`--no-ambiguous` 时从字符池剔除。
const AMBIGUOUS_CHARS: &[u8] = b"0Oo1lI|5S2ZB8";

/// 安全可见符号集(避免引号/反斜杠/空格,降低 shell/复制问题)。
const SYMBOL_CHARS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";

/// 用 CSPRNG(getrandom)生成强随机密码。
///
/// - `symbols = true` → 含 [`SYMBOL_CHARS`] 符号;`false` 仅字母 + 数字。
/// - `avoid_ambiguous = true` → 从池中剔除 [`AMBIGUOUS_CHARS`] 中的易混字符。
/// - 每个字符用**拒绝采样**(rejection sampling)从池中取,避免模偏:
///   随机字节 `>= floor(256/pool.len())*pool.len()` 时丢弃、重取。
/// - `length < 4` 或 `> 1024` 报 [`Error::Other`]。
pub fn generate_password(length: usize, symbols: bool, avoid_ambiguous: bool) -> Result<String> {
    if length < 4 {
        return Err(Error::Other("password length too short (min 4)".into()));
    }
    if length > 1024 {
        return Err(Error::Other("password length too long (max 1024)".into()));
    }

    // 构建字符池:a-z A-Z 0-9,(可选)符号。
    let mut pool: Vec<u8> = Vec::with_capacity(26 * 2 + 10 + SYMBOL_CHARS.len());
    pool.extend(b'a'..=b'z');
    pool.extend(b'A'..=b'Z');
    pool.extend(b'0'..=b'9');
    if symbols {
        pool.extend_from_slice(SYMBOL_CHARS);
    }
    if avoid_ambiguous {
        pool.retain(|c| !AMBIGUOUS_CHARS.contains(c));
    }

    let pool_len = pool.len();
    // 256 内能均匀覆盖的最大倍数:超过此阈值的字节丢弃,消除模偏。
    let limit = 256 - (256 % pool_len);

    let mut out: Vec<u8> = Vec::with_capacity(length);
    // 缓冲区:一次取一小批随机字节,逐个消费(拒绝则跳过),耗尽则补取。
    let mut buf = vec![0u8; 64];
    let mut pos = buf.len(); // 起始即耗尽,触发首次 fill
    while out.len() < length {
        if pos >= buf.len() {
            getrandom::fill(&mut buf)
                .map_err(|e| Error::Other(format!("getrandom failed: {e}")))?;
            pos = 0;
        }
        let byte = buf[pos] as usize;
        pos += 1;
        if byte < limit {
            out.push(pool[byte % pool_len]);
        }
    }
    // SAFETY: 池内均为 ASCII 字符,pool 字节即合法 UTF-8。
    String::from_utf8(out)
        .map_err(|e| Error::Other(format!("generated password not utf-8: {e}")))
}

/// `gen`:生成强随机密码并打印到 **stdout**(末尾换行),脚本友好:`pw=$(zkv gen)`。
///
/// 纯生成,不解锁库、不需要口令。
pub fn run_gen(length: usize, symbols: bool, avoid_ambiguous: bool) -> Result<()> {
    let pw = generate_password(length, symbols, avoid_ambiguous)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{pw}")?;
    Ok(())
}

/// `edit`:修改已存在条目的若干字段。每个参数为 `None` 表示「不改」。
///
/// 至少要改一处(title/data/tags/favorite/category 之一);全 `None` 报错。
/// `category = Some("name")` 按分类名解析成 id 并设置(找不到报错);
/// `category = None` 表示「不动」(本期不支持清除,清除需后续 `--clear-cat`)。
/// 替换 data 时同步 `item_type`,保持与 data tag 一致。成功打印 `updated item <id>`。
pub fn run_edit(
    u: &Unlocked,
    id: i64,
    title: Option<&str>,
    data_json: Option<&str>,
    tags: Option<Vec<String>>,
    favorite: Option<bool>,
    category: Option<&str>,
) -> Result<()> {
    let conn = u.db.conn();
    let mut item = store::get_item(conn, id)?
        .ok_or_else(|| Error::Other(format!("item {id} not found")))?;

    let mut changed = false;
    if let Some(t) = title {
        item.title = t.into();
        changed = true;
    }
    if let Some(j) = data_json {
        let d: ItemData = serde_json::from_str(j)?;
        item.item_type = item_type_of(&d);
        item.data = d;
        changed = true;
    }
    if let Some(tg) = tags {
        item.tags = tg;
        changed = true;
    }
    if let Some(f) = favorite {
        item.favorite = f;
        changed = true;
    }
    if let Some(cat) = category {
        let cid = category_id_by_name(conn, cat)?
            .ok_or_else(|| Error::Other(format!("category '{cat}' not found")))?;
        item.category_id = Some(cid);
        changed = true;
    }
    if !changed {
        return Err(Error::Other("edit: nothing to change".into()));
    }

    store::update_item(conn, &item)?;
    u.save()?;
    println!("updated item {id}");
    Ok(())
}

/// `rm`:删除条目。`yes = false` 时向 stderr 提示 `y/N` 确认。
///
/// 确认读首字符;非 `y`/`Y`(含 EOF/读失败)按「否」处理,打印 `aborted` 并返回 `Ok(())`。
/// 成功打印 `deleted item <id>`。
pub fn run_rm(u: &Unlocked, id: i64, yes: bool) -> Result<()> {
    use std::io::BufRead;
    let conn = u.db.conn();
    let item = store::get_item(conn, id)?
        .ok_or_else(|| Error::Other(format!("item {id} not found")))?;

    if !yes {
        let mut stderr = std::io::stderr();
        write!(stderr, "delete \"{}\"? [y/N] ", item.title)?;
        stderr.flush()?;
        let stdin = std::io::stdin();
        let lock = stdin.lock();
        // EOF/读失败按「否」处理。
        let confirm = lock
            .lines()
            .next()
            .unwrap_or(Ok(String::new()))
            .unwrap_or_default();
        let first = confirm.trim_start().chars().next();
        if !matches!(first, Some('y' | 'Y')) {
            println!("aborted");
            return Ok(());
        }
    }

    store::delete_item(conn, id)?;
    u.save()?;
    println!("deleted item {id}");
    Ok(())
}

// ---------------------------------------------------------------------------
// 分类/标签管理命令(cat/tag)
// ---------------------------------------------------------------------------

/// `cat add`:新增分类。`parent` 为父分类名(可选,找不到报错);成功打印
/// `added category <id>: <name>`。
pub fn run_cat_add(u: &Unlocked, name: &str, parent: Option<&str>) -> Result<i64> {
    let conn = u.db.conn();
    let parent_id = match parent {
        Some(pn) => Some(
            category_id_by_name(conn, pn)?
                .ok_or_else(|| Error::Other(format!("parent category '{pn}' not found")))?,
        ),
        None => None,
    };
    let mut cat = Category {
        id: None,
        name: name.into(),
        parent_id,
        sort_order: 0,
    };
    let id = store::insert_category(conn, &mut cat)?;
    u.save()?;
    println!("added category {id}: {name}");
    Ok(id)
}

/// `cat rm`:删除分类(by id 或名)。子条目 `category_id` 由外键 `ON DELETE SET NULL` 置空。
/// 成功打印 `deleted category <id>`。
pub fn run_cat_rm(u: &Unlocked, target: &str) -> Result<()> {
    let conn = u.db.conn();
    let id = resolve_category(conn, target)?;
    store::delete_category(conn, id)?;
    u.save()?;
    println!("deleted category {id}");
    Ok(())
}

/// `cat ls`:列出全部分类。每行 `id\tname\tparent\tparent`(`—` 表示无父)。
pub fn run_cat_ls(u: &Unlocked) -> Result<()> {
    let conn = u.db.conn();
    let cats = store::list_categories(conn)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if cats.is_empty() {
        writeln!(out, "(no categories)")?;
        return Ok(());
    }
    // 构一个 id→name 映射,便于把 parent_id 渲染成父分类名。
    let id_to_name: std::collections::HashMap<i64, String> = cats
        .iter()
        .filter_map(|c| c.id.map(|i| (i, c.name.clone())))
        .collect();
    for c in &cats {
        let id = c.id.unwrap_or(-1);
        let parent = c
            .parent_id
            .and_then(|pid| id_to_name.get(&pid).cloned())
            .unwrap_or_else(|| "-".into());
        writeln!(out, "{id}\t{}\t{parent}\t{}", c.name, c.sort_order)?;
    }
    Ok(())
}

/// 把 target(数字 id 或分类名)解析成分类 id。两者都失败报错。
fn resolve_category(conn: &rusqlite::Connection, target: &str) -> Result<i64> {
    // 优先按数字 id 解析。
    if let Ok(n) = target.parse::<i64>() {
        return Ok(n);
    }
    // 否则按名匹配。
    category_id_by_name(conn, target)?
        .ok_or_else(|| Error::Other(format!("category '{target}' not found")))
}

/// `tag ls`:列出全部标签。每行 `id\tname`。
pub fn run_tag_ls(u: &Unlocked) -> Result<()> {
    let conn = u.db.conn();
    let tags = store::list_tags(conn)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if tags.is_empty() {
        writeln!(out, "(no tags)")?;
        return Ok(());
    }
    for t in tags {
        writeln!(out, "{}\t{}", t.id, t.name)?;
    }
    Ok(())
}

/// `tag rm`:删除标签(by 名)。成功打印 `deleted tag <name>`。
pub fn run_tag_rm(u: &Unlocked, name: &str) -> Result<()> {
    let conn = u.db.conn();
    let id = tag_id_by_name(conn, name)?
        .ok_or_else(|| Error::Other(format!("tag '{name}' not found")))?;
    store::delete_tag(conn, id)?;
    u.save()?;
    println!("deleted tag {name}");
    Ok(())
}

/// `tag mv`:改标签名。成功打印 `renamed tag <from> -> <to>`。
pub fn run_tag_mv(u: &Unlocked, from: &str, to: &str) -> Result<()> {
    let conn = u.db.conn();
    let id = tag_id_by_name(conn, from)?
        .ok_or_else(|| Error::Other(format!("tag '{from}' not found")))?;
    store::update_tag(conn, id, to)?;
    u.save()?;
    println!("renamed tag {from} -> {to}");
    Ok(())
}

// ---------------------------------------------------------------------------
// 附件管理命令(attach add/ls/get/rm)
// ---------------------------------------------------------------------------

/// 按扩展名做轻量 MIME 推断。未知扩展名返回 `None`,由调用方决定是否给默认值。
///
/// 覆盖常见办公/图片/文本格式;不引入 mime_guess crate,保持依赖最小。
fn guess_mime(path: &Path) -> Option<String> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    let mime = match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "txt" | "log" | "md" => "text/plain",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "json" => "application/json",
        "xml" => "application/xml",
        "zip" => "application/zip",
        "gz" | "tgz" => "application/gzip",
        "tar" => "application/x-tar",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "doc" => "application/msword",
        "xls" => "application/vnd.ms-excel",
        "ppt" => "application/vnd.ms-powerpoint",
        "bin" | "dat" => "application/octet-stream",
        _ => return None,
    };
    Some(mime.to_string())
}

/// 判断附件 `att` 是否属于条目 `item`。
///
/// 查 `SELECT item_id FROM attachments WHERE id=?1`;附件不存在返回 `Ok(false)`。
fn attachment_belongs_to(conn: &rusqlite::Connection, att: i64, item: i64) -> Result<bool> {
    let row: Option<i64> = conn
        .query_row(
            "SELECT item_id FROM attachments WHERE id = ?1",
            rusqlite::params![att],
            |r| r.get::<_, i64>(0),
        )
        .ok();
    Ok(row == Some(item))
}

/// `attach add`:把本地文件读入内存,作为加密内嵌附件挂到 `item` 上。
///
/// 校验 item 存在 → 读文件 → 推断 filename/mime → insert → save。
/// 打印 `attached <id>: <filename> (<size> bytes)` 并返回新附件 id。
pub fn run_attach_add(
    u: &Unlocked,
    item: i64,
    file: &Path,
    mime: Option<&str>,
) -> Result<i64> {
    let conn = u.db.conn();
    // 校验 item 存在(不存在给清晰错误,而非依赖外键)。
    if store::get_item(conn, item)?.is_none() {
        return Err(Error::Other(format!("item {item} not found")));
    }
    let blob = std::fs::read(file)?;
    let filename = file
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "attachment".to_string());
    let mime_type = mime.map(|s| s.to_string()).or_else(|| guess_mime(file));

    let mut att = Attachment {
        id: None,
        item_id: item,
        filename,
        mime_type,
        size: 0, // insert_attachment 会用 blob.len() 回填
        blob,
    };
    let id = store::insert_attachment(conn, &mut att)?;
    u.save()?;
    println!(
        "attached {}: {} ({} bytes)",
        id,
        att.filename,
        att.size
    );
    Ok(id)
}

/// `attach ls`:列出 item 的附件元数据(**不读 blob**)。每行
/// `id\tfilename\tmime\tsize`,无附件时打印 `(no attachments)`。
pub fn run_attach_ls(u: &Unlocked, item: i64) -> Result<()> {
    let conn = u.db.conn();
    // 自己写查询,避免 list_attachments 把 blob 也读出来。
    let mut stmt = conn.prepare(
        "SELECT id, filename, mime_type, size FROM attachments
         WHERE item_id = ?1 ORDER BY id ASC",
    )?;
    let rows: Vec<(i64, String, Option<String>, i64)> = stmt
        .query_map(rusqlite::params![item], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if rows.is_empty() {
        writeln!(out, "(no attachments)")?;
        return Ok(());
    }
    for (id, filename, mime, size) in rows {
        let mime = mime.unwrap_or_else(|| "-".into());
        writeln!(out, "{id}\t{filename}\t{mime}\t{size}")?;
    }
    Ok(())
}

/// `attach get`:导出附件 blob 到文件(`-o`)或 stdout。
///
/// - `output = Some(p)`:写文件(`std::fs::write`)。
/// - `output = None`:二进制安全地 `write_all` 到 stdout。
///
/// 元信息(filename/mime/size)打到 stderr,stdout 只出 blob。
/// 校验附件存在且归属 `item`,否则 `Error::Other`。
pub fn run_attach_get(
    u: &Unlocked,
    item: i64,
    att: i64,
    output: Option<&Path>,
) -> Result<()> {
    let conn = u.db.conn();
    let attachment = store::get_attachment(conn, att)?
        .ok_or_else(|| Error::Other(format!("attachment {att} not found")))?;
    if !attachment_belongs_to(conn, att, item)? {
        return Err(Error::Other(format!(
            "attachment {att} does not belong to item {item}"
        )));
    }

    let mime = attachment.mime_type.clone().unwrap_or_else(|| "-".into());
    eprintln!(
        "{}\t{}\t{} bytes",
        attachment.filename, mime, attachment.size
    );

    match output {
        Some(p) => {
            std::fs::write(p, &attachment.blob)?;
            eprintln!("wrote {}", p.display());
        }
        None => {
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            out.write_all(&attachment.blob)?;
        }
    }
    Ok(())
}

/// `attach rm`:删除附件(校验归属后)。打印 `deleted attachment <att>`。
pub fn run_attach_rm(u: &Unlocked, item: i64, att: i64) -> Result<()> {
    let conn = u.db.conn();
    // 先校验存在 + 归属,避免误删不相关附件。
    if store::get_attachment(conn, att)?.is_none() {
        return Err(Error::Other(format!("attachment {att} not found")));
    }
    if !attachment_belongs_to(conn, att, item)? {
        return Err(Error::Other(format!(
            "attachment {att} does not belong to item {item}"
        )));
    }
    store::delete_attachment(conn, att)?;
    u.save()?;
    println!("deleted attachment {att}");
    Ok(())
}

// ---------------------------------------------------------------------------
// 只读命令
// ---------------------------------------------------------------------------

/// `ls`:按过滤条件列出条目。`favorite = true` 时仅返回收藏项(透传到 `ListFilter`)。
pub fn run_ls(u: &Unlocked, f: &ListFilter, favorite: bool, json: bool) -> Result<()> {
    let mut f = f.clone();
    if favorite {
        f.favorite_only = true;
    }
    let conn = u.db.conn();
    let category_id = match &f.category {
        Some(name) => Some(
            category_id_by_name(conn, name)?
                .ok_or_else(|| Error::Other(format!("category '{name}' not found")))?,
        ),
        None => None,
    };
    let sf = to_search_filter(&f, category_id);
    let items = search::search(conn, &sf)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    write_items(&mut out, &items, json)
}

/// `get`:打印单条条目,或某字段原始值(末尾加换行)。
pub fn run_get(u: &Unlocked, id: i64, field: Option<&str>, json: bool) -> Result<()> {
    let conn = u.db.conn();
    let item = store::get_item(conn, id)?
        .ok_or_else(|| Error::Other(format!("item {id} not found")))?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    match field {
        // 字段模式:打印原始值(便于管道,如 `$(zkv get ... -f password)`)。
        Some(name) => {
            let val = item_field(&item, name)?;
            writeln!(out, "{val}")?;
        }
        // 整条模式。
        None => {
            if json {
                let s = serde_json::to_string_pretty(&item)?;
                writeln!(out, "{s}")?;
            } else {
                write_item_human(&mut out, &item)?;
            }
        }
    }
    Ok(())
}

/// `search`:全文检索,复用 `write_items` 格式化。
pub fn run_search(u: &Unlocked, query: &str, json: bool) -> Result<()> {
    let sf = Filter {
        query: Some(query.to_string()),
        category: None,
        tags: vec![],
        item_type: None,
        favorite_only: false,
    };
    let items = search::search(u.db.conn(), &sf)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    write_items(&mut out, &items, json)
}

/// `cp`:复制某字段到剪贴板,`secs` 秒后自动清空。
///
/// `field` 默认为 `password`。打印 `copied <field> (clears in <n>s)` 提示。
/// 特例:`field == "otp"` 时复制**实时 TOTP 验证码**(而非 `totp` 字段返回的原始 secret),
/// 提示语相应改为 `copied otp code (...)`。
pub fn run_cp(u: &Unlocked, id: i64, field: Option<&str>, clear_secs: u64) -> Result<()> {
    let conn = u.db.conn();
    let item = store::get_item(conn, id)?
        .ok_or_else(|| Error::Other(format!("item {id} not found")))?;
    let name = field.unwrap_or("password");

    // otp 特例:复制实时验证码。
    if name == "otp" {
        let code = otp_of_item(&item)?;
        clipboard::copy_and_clear_after(&code, clear_secs)?;
        println!("copied otp code (clears in {clear_secs}s)");
        return Ok(());
    }

    let val = item_field(&item, name)?;
    clipboard::copy_and_clear_after(&val, clear_secs)?;
    println!("copied {name} (clears in {clear_secs}s)");
    Ok(())
}

/// 计算单条条目的实时 TOTP 验证码(6 位)。供 `run_otp`/`run_cp` 复用。
///
/// 仅 `ItemData::Password { totp_secret, .. }` 且 secret 非空时可生成;否则 [`Error::Other`]。
pub fn otp_of_item(item: &Item) -> Result<String> {
    let secret = match &item.data {
        ItemData::Password { totp_secret, .. } => totp_secret,
        _ => return Err(Error::Other("item has no totp secret".into())),
    };
    if secret.trim().is_empty() {
        return Err(Error::Other("item has no totp secret".into()));
    }
    crate::totp::current_totp(secret)
}

/// `otp`:打印条目的当前 TOTP 验证码(6 位 + 换行)到 stdout,脚本友好。
///
/// 仅 password 条目且 `totp_secret` 非空可生成。可选向 stderr 打印剩余有效秒数。
pub fn run_otp(u: &Unlocked, id: i64) -> Result<()> {
    let conn = u.db.conn();
    let item = store::get_item(conn, id)?
        .ok_or_else(|| Error::Other(format!("item {id} not found")))?;
    let code = otp_of_item(&item)?;

    // stdout 仅 6 位码 + 换行,便于 `code=$(zkv otp vault 3)`。
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out, "{code}")?;

    // 可选:向 stderr 提示当前窗口剩余秒数(不打扰 stdout 脚本捕获)。
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!("(valid ~{}s)", 30 - secs % 30);
    Ok(())
}

/// 人类可读地打印单条条目(字段表)。
fn write_item_human<W: Write>(out: &mut W, item: &Item) -> Result<()> {
    use crate::model::ItemData::*;
    let id = item.id.unwrap_or(-1);
    writeln!(out, "id:       {id}")?;
    writeln!(out, "type:     {}", item.item_type.as_str())?;
    writeln!(out, "title:    {}", item.title)?;
    if item.favorite {
        writeln!(out, "favorite: yes")?;
    }
    if !item.tags.is_empty() {
        writeln!(out, "tags:     {}", item.tags.join(", "))?;
    }
    match &item.data {
        Password {
            username,
            password,
            url,
            totp_secret,
            notes,
        } => {
            writeln!(out, "username: {username}")?;
            writeln!(out, "password: {password}")?;
            writeln!(out, "url:      {url}")?;
            writeln!(out, "totp:     {totp_secret}")?;
            if !notes.is_empty() {
                writeln!(out, "notes:    {notes}")?;
            }
        }
        Note { format, content } => {
            writeln!(out, "format:   {format}")?;
            writeln!(out, "content:")?;
            writeln!(out, "{content}")?;
        }
        Card {
            holder,
            number,
            expiry,
            cvv,
            bank,
            notes,
        } => {
            writeln!(out, "holder:   {holder}")?;
            writeln!(out, "number:   {number}")?;
            writeln!(out, "expiry:   {expiry}")?;
            writeln!(out, "cvv:      {cvv}")?;
            writeln!(out, "bank:     {bank}")?;
            if !notes.is_empty() {
                writeln!(out, "notes:    {notes}")?;
            }
        }
    }
    writeln!(out, "updated:  {}", item.updated_at)?;
    Ok(())
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Item, ItemData};
    use crate::store;

    /// 串行化所有读写 `ZKV_PASSPHRASE` 的测试(默认并行运行器下 env 非线程隔离)。
    /// 任何会 set/remove 或语义上依赖该 env 是否存在的测试,都先拿这把锁。
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        // unwrap:仅 panic( poison)时失败,测试本身已失败,可接受。
        LOCK.lock().unwrap()
    }

    /// 测试用小 KDF 参数,加速派生。
    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_kib: 4_096,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// 唯一临时库路径。
    fn tmp_path(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("zkv_cli_{tag}_{}_{}", std::process::id(), n));
        p
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_file(p);
        let mut t = p.as_os_str().to_owned();
        t.push(".tmp");
        let _ = std::fs::remove_file(PathBuf::from(t));
    }

    /// 写一个口令文件(内容 "pw\n"),供 `Unlocked::unlock` 的 `--passfile` 路径,
    /// 避免在无 TTY 的测试环境里落到 `rpassword` 提示。
    fn write_passfile(tag: &str) -> PathBuf {
        let p = tmp_path(&format!("pf_{tag}"));
        std::fs::write(&p, "pw\n").unwrap();
        p
    }    /// 构建一个含已知条目(password + note,带标签)的临时库,返回路径与口令。
    fn make_vault(tag: &str) -> PathBuf {
        let p = tmp_path(tag);
        cleanup(&p);
        let kdf = fast_kdf();
        vault::create_with_params(&p, "pw", &kdf).unwrap();
        // 解锁 → 插条目 → 落盘。
        let (db, key, kdf2, salt) = vault::unlock_full(&p, "pw").unwrap();
        {
            let conn = db.conn();
            let mut pw = Item {
                id: None,
                item_type: ItemType::Password,
                title: "GitHub".into(),
                category_id: None,
                data: ItemData::Password {
                    username: "alice".into(),
                    password: "s3cret".into(),
                    url: "https://github.com".into(),
                    totp_secret: "JBSWY3DPEHPK3PXP".into(),
                    notes: "main".into(),
                },
                favorite: false,
                tags: vec!["work".into(), "vip".into()],
                created_at: 0,
                updated_at: 0,
            };
            store::insert_item(conn, &mut pw).unwrap();

            let mut note = Item {
                id: None,
                item_type: ItemType::Note,
                title: "Ideas".into(),
                category_id: None,
                data: ItemData::Note {
                    format: "markdown".into(),
                    content: "# hello world".into(),
                },
                favorite: false,
                tags: vec!["work".into()],
                created_at: 0,
                updated_at: 0,
            };
            store::insert_item(conn, &mut note).unwrap();
        }
        vault::save_with_key(&p, &key, &kdf2, salt, &db).unwrap();
        // borrow checker:db drop 在 save 之后。
        drop(db);
        p
    }

    // --- 纯函数测试 ---

    #[test]
    fn strip_trailing_newline_both_styles() {
        assert_eq!(strip_trailing_newline("abc\n".into()), "abc");
        assert_eq!(strip_trailing_newline("abc\r\n".into()), "abc");
        assert_eq!(strip_trailing_newline("abc".into()), "abc");
        // 只去末尾单个换行,中间保留。
        assert_eq!(strip_trailing_newline("a\nb\n".into()), "a\nb");
    }

    #[test]
    fn item_field_password_mapping() {
        let item = Item {
            id: Some(1),
            item_type: ItemType::Password,
            title: "T".into(),
            category_id: None,
            data: ItemData::Password {
                username: "u".into(),
                password: "p".into(),
                url: "https://x".into(),
                totp_secret: "TOTP".into(),
                notes: "n".into(),
            },
            favorite: false,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };
        assert_eq!(item_field(&item, "title").unwrap(), "T");
        assert_eq!(item_field(&item, "username").unwrap(), "u");
        assert_eq!(item_field(&item, "password").unwrap(), "p");
        assert_eq!(item_field(&item, "url").unwrap(), "https://x");
        assert_eq!(item_field(&item, "totp").unwrap(), "TOTP");
        assert_eq!(item_field(&item, "notes").unwrap(), "n");
    }

    #[test]
    fn item_field_note_and_card_mapping() {
        let note = Item {
            id: Some(1),
            item_type: ItemType::Note,
            title: "N".into(),
            category_id: None,
            data: ItemData::Note {
                format: "markdown".into(),
                content: "body".into(),
            },
            favorite: false,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };
        assert_eq!(item_field(&note, "format").unwrap(), "markdown");
        assert_eq!(item_field(&note, "content").unwrap(), "body");

        let card = Item {
            id: Some(2),
            item_type: ItemType::Card,
            title: "C".into(),
            category_id: None,
            data: ItemData::Card {
                holder: "H".into(),
                number: "4111".into(),
                expiry: "12/29".into(),
                cvv: "123".into(),
                bank: "B".into(),
                notes: "cn".into(),
            },
            favorite: false,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };
        assert_eq!(item_field(&card, "holder").unwrap(), "H");
        assert_eq!(item_field(&card, "number").unwrap(), "4111");
        assert_eq!(item_field(&card, "expiry").unwrap(), "12/29");
        assert_eq!(item_field(&card, "cvv").unwrap(), "123");
        assert_eq!(item_field(&card, "bank").unwrap(), "B");
        assert_eq!(item_field(&card, "notes").unwrap(), "cn");
    }

    #[test]
    fn item_field_unknown_field_errors() {
        let item = Item {
            id: Some(1),
            item_type: ItemType::Note,
            title: "N".into(),
            category_id: None,
            data: ItemData::Note {
                format: "text".into(),
                content: "c".into(),
            },
            favorite: false,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };
        // note 条目请求 password 字段 → 类型不匹配。
        assert!(item_field(&item, "password").is_err());
        // 完全未知字段。
        assert!(item_field(&item, "nope").is_err());
    }

    #[test]
    fn to_search_filter_maps_fields() {
        let lf = ListFilter {
            item_type: Some(ItemType::Password),
            tags: vec!["a".into()],
            category: Some("Personal".into()),
            query: Some("q".into()),
            favorite_only: true,
        };
        let sf = to_search_filter(&lf, Some(7));
        assert_eq!(sf.item_type, Some(ItemType::Password));
        assert_eq!(sf.tags, vec!["a".to_string()]);
        assert_eq!(sf.category, Some(7));
        assert_eq!(sf.query.as_deref(), Some("q"));
        assert!(sf.favorite_only);
    }

    // --- 端到端(只读命令返回 Ok/Err 路径) ---

    #[test]
    fn run_ls_returns_ok() {
        let p = make_vault("ls");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        let f = ListFilter::default();
        assert!(run_ls(&u, &f, false, false).is_ok());
        assert!(run_ls(&u, &f, false, true).is_ok());
        cleanup(&p);
    }

    #[test]
    fn run_ls_filter_by_type_and_tag() {
        let p = make_vault("lsfilt");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        let f = ListFilter {
            item_type: Some(ItemType::Note),
            ..Default::default()
        };
        // 直接查 search 验证过滤语义(避免依赖 stdout 捕获)。
        let sf = to_search_filter(&f, None);
        let items = search::search(u.db.conn(), &sf).unwrap();
        assert!(items.iter().all(|i| i.item_type == ItemType::Note));

        let f2 = ListFilter {
            tags: vec!["vip".into()],
            ..Default::default()
        };
        let sf2 = to_search_filter(&f2, None);
        let items2 = search::search(u.db.conn(), &sf2).unwrap();
        assert!(items2.iter().all(|i| i.tags.contains(&"vip".to_string())));
        cleanup(&p);
    }

    #[test]
    fn run_ls_unknown_category_errors() {
        let p = make_vault("lscat");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        let f = ListFilter {
            category: Some("Nonexistent".into()),
            ..Default::default()
        };
        let err = run_ls(&u, &f, false, false);
        assert!(matches!(err, Err(Error::Other(_))));
        cleanup(&p);
    }

    #[test]
    fn run_get_found_and_missing() {
        let p = make_vault("get");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // id=1 存在(GitHub)。
        assert!(run_get(&u, 1, Some("password"), false).is_ok());
        assert!(run_get(&u, 1, None, false).is_ok());
        assert!(run_get(&u, 1, None, true).is_ok());
        // 不存在的 id。
        assert!(matches!(
            run_get(&u, 9999, None, false),
            Err(Error::Other(_))
        ));
        // 未知字段。
        assert!(matches!(
            run_get(&u, 1, Some("nope"), false),
            Err(Error::Other(_))
        ));
        cleanup(&p);
    }

    #[test]
    fn run_search_ok() {
        let p = make_vault("search");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        assert!(run_search(&u, "hello", false).is_ok());
        assert!(run_search(&u, "hello", true).is_ok());
        cleanup(&p);
    }

    #[test]
    fn run_cp_missing_item_errors() {
        let p = make_vault("cp");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // 不存在的 item → 报错(在剪贴板调用之前)。
        assert!(matches!(
            run_cp(&u, 9999, None, 1),
            Err(Error::Other(_))
        ));
        cleanup(&p);
    }

    #[test]
    fn otp_of_item_returns_six_digits() {
        // id=1 是 GitHub password,totp_secret = "JBSWY3DPEHPK3PXP"。
        let p = make_vault("otp");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        let conn = u.db.conn();
        let item = store::get_item(conn, 1).unwrap().unwrap();
        let code = otp_of_item(&item).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        cleanup(&p);
    }

    #[test]
    fn otp_of_item_no_secret_errors() {
        // note 条目无 totp_secret。
        let note = Item {
            id: Some(2),
            item_type: ItemType::Note,
            title: "N".into(),
            category_id: None,
            data: ItemData::Note {
                format: "text".into(),
                content: "c".into(),
            },
            favorite: false,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };
        assert!(matches!(otp_of_item(&note), Err(Error::Other(_))));

        // 空 secret 也报错。
        let pw = Item {
            id: Some(3),
            item_type: ItemType::Password,
            title: "P".into(),
            category_id: None,
            data: ItemData::Password {
                username: "u".into(),
                password: "p".into(),
                url: "".into(),
                totp_secret: "   ".into(),
                notes: "".into(),
            },
            favorite: false,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };
        assert!(matches!(otp_of_item(&pw), Err(Error::Other(_))));
    }

    #[test]
    fn run_otp_ok_and_missing_errors() {
        let p = make_vault("runotp");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // id=1 存在且有 secret → Ok。
        assert!(run_otp(&u, 1).is_ok());
        // 不存在的 id → 报错。
        assert!(matches!(run_otp(&u, 9999), Err(Error::Other(_))));
        cleanup(&p);
    }

    // --- 无头建库(init) ---

    #[test]
    fn run_init_creates_unlockable_empty_vault() {
        // 默认 KDF(64MiB)一次派生约 0.3–1s;这是唯一一个默认 KDF 的 init 测试,可接受。
        // 用 ZKV_PASSPHRASE 绕开 rpassword(无 TTY 测试环境)。
        let _g = env_lock();
        let p = tmp_path("init_ok");
        cleanup(&p);

        // SAFETY: 持 env_lock,本函数内串行 set/remove,无并发竞态。
        unsafe {
            std::env::set_var("ZKV_PASSPHRASE", "pw");
        }
        let res = run_init(&p, None);
        // SAFETY: 同上。
        unsafe {
            std::env::remove_var("ZKV_PASSPHRASE");
        }

        res.unwrap();
        assert!(p.exists(), "vault file should exist after init");

        // 空库可解锁,items 为 0。
        let db = vault::unlock(&p, "pw").unwrap();
        let items = search::search(db.conn(), &Filter::default()).unwrap();
        assert!(items.is_empty());
        cleanup(&p);
    }

    #[test]
    fn run_init_refuses_existing_vault() {
        // 先用 fast KDF 建一个库,再 init 同路径 → 报错且信息含 "already exists"。
        let p = tmp_path("init_exists");
        cleanup(&p);
        vault::create_with_params(&p, "pw", &fast_kdf()).unwrap();
        assert!(p.exists());

        let pf = write_passfile("init_exists");
        let err = run_init(&p, Some(&pf));
        assert!(matches!(err, Err(Error::Other(_))));
        let msg = match err {
            Err(Error::Other(m)) => m,
            _ => String::new(),
        };
        assert!(
            msg.contains("already exists"),
            "expected 'already exists' in error, got: {msg}"
        );
        cleanup(&p);
    }

    // --- 口令来源 ---
    //
    // 涉及 `ZKV_PASSPHRASE` 环境变量的用例合并到单个测试中,避免默认并行测试运行器下
    // 多个测试并发 set/remove 同一环境变量造成的竞态(env 非线程隔离)。
    // passfile/纯函数用例不受影响,保持独立。

    #[test]
    fn read_passphrase_env_paths() {
        let _g = env_lock();
        // 1. 环境变量优先级最高。
        // SAFETY: 该测试独占对 ZKV_PASSPHRASE 的 set/remove(本函数内串行)。
        unsafe {
            std::env::set_var("ZKV_PASSPHRASE", "env-secret");
        }
        let got = read_passphrase(None).unwrap();
        assert_eq!(got.as_str(), "env-secret");

        // 2. 环境变量优先级高于 passfile。
        let pf = tmp_path("passfile_prec");
        std::fs::write(&pf, "file-loses\n").unwrap();
        let got = read_passphrase(Some(&pf)).unwrap();
        assert_eq!(got.as_str(), "env-secret");
        cleanup(&pf);

        // 清理:之后走 passfile/TTY 路径。
        // SAFETY: 同上。
        unsafe {
            std::env::remove_var("ZKV_PASSPHRASE");
        }

        // 3. passfile 路径(去末尾换行,LF 与 CRLF)。
        let p = tmp_path("passfile");
        std::fs::write(&p, "file-secret\n").unwrap();
        let got = read_passphrase(Some(&p)).unwrap();
        assert_eq!(got.as_str(), "file-secret");
        cleanup(&p);

        let p2 = tmp_path("passfile2");
        std::fs::write(&p2, "crlf-secret\r\n").unwrap();
        let got2 = read_passphrase(Some(&p2)).unwrap();
        assert_eq!(got2.as_str(), "crlf-secret");
        cleanup(&p2);
    }

    #[test]
    fn read_passphrase_missing_passfile_errors() {
        // 必须串行:若并行测试此刻设置了 ZKV_PASSPHRASE,本测试会错误地走 env 路径。
        let _g = env_lock();
        // 兜底:确保本测试开始时 env 未设置。
        // SAFETY: 已持 env_lock,无并发访问。
        unsafe {
            std::env::remove_var("ZKV_PASSPHRASE");
        }
        let p = tmp_path("nope_passfile");
        cleanup(&p);
        assert!(read_passphrase(Some(&p)).is_err());
    }

    #[test]
    fn unlocked_save_roundtrips() {
        let p = make_vault("save");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // 再保存一次(用已派生 key)应成功。
        assert!(u.save().is_ok());
        // 再次解锁仍可读。
        let pf2 = write_passfile("u2");
        let u2 = Unlocked::unlock(&p, Some(&pf2)).unwrap();
        let items = search::search(u2.db.conn(), &Filter::default()).unwrap();
        assert_eq!(items.len(), 2);
        cleanup(&p);
    }

    // --- 写命令(add/edit/rm) ---

    #[test]
    fn run_add_inserts_and_persists() {
        let p = make_vault("add");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        let data = r#"{"type":"password","username":"bob","password":"pw1","url":"https://x","totp_secret":"","notes":""}"#;
        let id = run_add(&u, "Server", data, vec!["ops".into()], true, None).unwrap();
        assert!(id > 0);

        // 内存中能取到正确字段。
        let got = store::get_item(u.db.conn(), id).unwrap().unwrap();
        assert_eq!(got.title, "Server");
        assert_eq!(got.item_type, ItemType::Password);
        assert!(got.favorite);
        assert_eq!(got.tags, vec!["ops".to_string()]);
        assert_eq!(item_field(&got, "username").unwrap(), "bob");

        // 落盘后重新解锁读回(原 2 条 + 新增 1 条)。
        drop(u);
        let pf2 = write_passfile("u2");
        let u2 = Unlocked::unlock(&p, Some(&pf2)).unwrap();
        let got2 = store::get_item(u2.db.conn(), id).unwrap().unwrap();
        assert_eq!(got2.title, "Server");
        assert_eq!(got2.item_type, ItemType::Password);
        let items = search::search(u2.db.conn(), &Filter::default()).unwrap();
        assert_eq!(items.len(), 3);
        cleanup(&p);
    }

    #[test]
    fn run_add_bad_data_json_errors() {
        let p = make_vault("addbad");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // 缺 type tag → serde 报错(非 Error::Other,但仍是 Err)。
        assert!(run_add(&u, "X", "{ not json", vec![], false, None).is_err());
        cleanup(&p);
    }

    #[test]
    fn run_edit_updates_fields_and_type() {
        let p = make_vault("edit");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // id=1 是 GitHub password。
        let new_data =
            r#"{"type":"note","format":"text","content":"moved"}"#;
        run_edit(
            &u,
            1,
            Some("Renamed"),
            Some(new_data),
            Some(vec!["archive".into()]),
            Some(false),
            None,
        )
        .unwrap();

        let got = store::get_item(u.db.conn(), 1).unwrap().unwrap();
        assert_eq!(got.title, "Renamed");
        assert_eq!(got.item_type, ItemType::Note); // 随 data 同步
        assert_eq!(got.tags, vec!["archive".to_string()]);
        assert!(!got.favorite);
        assert_eq!(item_field(&got, "content").unwrap(), "moved");

        // 落盘读回。
        drop(u);
        let pf2 = write_passfile("u2");
        let u2 = Unlocked::unlock(&p, Some(&pf2)).unwrap();
        let got2 = store::get_item(u2.db.conn(), 1).unwrap().unwrap();
        assert_eq!(got2.title, "Renamed");
        assert_eq!(got2.item_type, ItemType::Note);
        cleanup(&p);
    }

    #[test]
    fn run_edit_partial_title_only() {
        let p = make_vault("edit2");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        run_edit(&u, 1, Some("JustTitle"), None, None, None, None).unwrap();
        let got = store::get_item(u.db.conn(), 1).unwrap().unwrap();
        assert_eq!(got.title, "JustTitle");
        // data 未动,仍是 password。
        assert_eq!(got.item_type, ItemType::Password);
        cleanup(&p);
    }

    #[test]
    fn run_edit_nothing_to_change_errors() {
        let p = make_vault("editnone");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        let err = run_edit(&u, 1, None, None, None, None, None);
        assert!(matches!(err, Err(Error::Other(_))));
    }

    #[test]
    fn run_edit_missing_item_errors() {
        let p = make_vault("editmissing");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        let err = run_edit(&u, 9999, Some("x"), None, None, None, None);
        assert!(matches!(err, Err(Error::Other(_))));
    }

    #[test]
    fn run_rm_yes_deletes() {
        let p = make_vault("rmyes");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        run_rm(&u, 1, true).unwrap();
        // 删除后取不到。
        assert!(store::get_item(u.db.conn(), 1).unwrap().is_none());

        // 落盘读回:仅剩 1 条。
        drop(u);
        let pf2 = write_passfile("u2");
        let u2 = Unlocked::unlock(&p, Some(&pf2)).unwrap();
        assert!(store::get_item(u2.db.conn(), 1).unwrap().is_none());
        let items = search::search(u2.db.conn(), &Filter::default()).unwrap();
        assert_eq!(items.len(), 1);
        cleanup(&p);
    }

    #[test]
    fn run_rm_missing_item_errors() {
        let p = make_vault("rmmissing");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // yes=true 仍要先确认 item 存在 → 报错。
        let err = run_rm(&u, 9999, true);
        assert!(matches!(err, Err(Error::Other(_))));
        cleanup(&p);
    }

    // --- 分类/标签管理(cat/tag)+ edit --cat + ls -F ---

    #[test]
    fn run_cat_add_ls_rm_roundtrip() {
        let p = make_vault("cat");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();

        // add 一个顶层分类。
        let cid = run_cat_add(&u, "Personal", None).unwrap();
        assert!(cid > 0);
        // add 一个带父分类的子分类。
        let sub = run_cat_add(&u, "Banking", Some("Personal")).unwrap();
        assert!(sub > 0);

        // ls 不报错且能看到两个分类(直接查 store 验证,避免依赖 stdout 捕获)。
        assert!(run_cat_ls(&u).is_ok());
        let cats = store::list_categories(u.db.conn()).unwrap();
        assert_eq!(cats.len(), 2);
        assert!(cats.iter().any(|c| c.name == "Personal"));
        assert!(cats.iter().any(|c| c.name == "Banking" && c.parent_id == Some(cid)));

        // rm by 名。
        run_cat_rm(&u, "Banking").unwrap();
        assert_eq!(store::list_categories(u.db.conn()).unwrap().len(), 1);
        // rm by id。
        run_cat_rm(&u, &cid.to_string()).unwrap();
        assert!(store::list_categories(u.db.conn()).unwrap().is_empty());

        // rm 不存在的分类 → 报错。
        assert!(run_cat_rm(&u, "Nope").is_err());

        // 落盘读回:分类确实删除持久化。
        drop(u);
        let pf2 = write_passfile("u2");
        let u2 = Unlocked::unlock(&p, Some(&pf2)).unwrap();
        assert!(store::list_categories(u2.db.conn()).unwrap().is_empty());
        cleanup(&p);
    }

    #[test]
    fn run_cat_add_bad_parent_errors() {
        let p = make_vault("catbad");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // 父分类不存在 → 报错。
        assert!(run_cat_add(&u, "X", Some("Nope")).is_err());
        cleanup(&p);
    }

    #[test]
    fn run_tag_ls_rm_mv_roundtrip() {
        let p = make_vault("tag");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();

        // 初始库已含 work / vip 标签(make_vault 注入)。
        assert!(run_tag_ls(&u).is_ok());
        let tags = store::list_tags(u.db.conn()).unwrap();
        assert!(tags.iter().any(|t| t.name == "work"));
        assert!(tags.iter().any(|t| t.name == "vip"));

        // mv:work → work2。
        run_tag_mv(&u, "work", "work2").unwrap();
        let tags = store::list_tags(u.db.conn()).unwrap();
        assert!(tags.iter().any(|t| t.name == "work2"));
        assert!(!tags.iter().any(|t| t.name == "work"));

        // rm:删除 work2。
        run_tag_rm(&u, "work2").unwrap();
        let tags = store::list_tags(u.db.conn()).unwrap();
        assert!(!tags.iter().any(|t| t.name == "work2"));

        // rm 不存在的标签 → 报错。
        assert!(run_tag_rm(&u, "ghost").is_err());
        // mv 不存在的标签 → 报错。
        assert!(run_tag_mv(&u, "ghost", "x").is_err());

        // 落盘读回:改名持久化。
        drop(u);
        let pf2 = write_passfile("u2");
        let u2 = Unlocked::unlock(&p, Some(&pf2)).unwrap();
        let tags2 = store::list_tags(u2.db.conn()).unwrap();
        assert!(tags2.iter().any(|t| t.name == "vip"));
        assert!(!tags2.iter().any(|t| t.name == "work2"));
        cleanup(&p);
    }

    #[test]
    fn run_edit_sets_category() {
        let p = make_vault("editcat");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();

        // 先建一个分类,再把 id=1 的 item 设到该分类下。
        let cid = run_cat_add(&u, "Work", None).unwrap();
        run_edit(&u, 1, None, None, None, None, Some("Work")).unwrap();

        let got = store::get_item(u.db.conn(), 1).unwrap().unwrap();
        assert_eq!(got.category_id, Some(cid));

        // 未知分类名 → 报错。
        assert!(run_edit(&u, 1, None, None, None, None, Some("Ghost")).is_err());
        cleanup(&p);
    }

    #[test]
    fn run_ls_favorite_only_returns_favorites() {
        let p = make_vault("lsfav");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // make_vault 的两条 item 都不是收藏;add 一条收藏项。
        let data = r#"{"type":"password","username":"bob","password":"pw","url":"","totp_secret":"","notes":""}"#;
        let _fav_id = run_add(&u, "Fav", data, vec![], true, None).unwrap();

        let f = ListFilter::default();
        // favorite=false:返回全部 3 条。
        let sf_all = to_search_filter(&f, None);
        let all = search::search(u.db.conn(), &sf_all).unwrap();
        assert_eq!(all.len(), 3);

        // favorite=true:只返回 1 条(收藏项)。
        assert!(run_ls(&u, &f, true, false).is_ok());
        let mut f2 = f.clone();
        f2.favorite_only = true;
        let sf_fav = to_search_filter(&f2, None);
        let favs = search::search(u.db.conn(), &sf_fav).unwrap();
        assert_eq!(favs.len(), 1);
        assert!(favs.iter().all(|i| i.favorite));
        cleanup(&p);
    }

    // --- 附件管理(attach add/ls/get/rm) ---

    /// 构造一个临时附件文件,内容 = `bytes`,**文件名保持 `name`**(含扩展名),
    /// 放在临时目录下。文件名决定了 filename/mime 推断,故不能用带计数器的 tmp_path。
    fn write_att_file(name: &str, bytes: &[u8]) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("zkv_att_{}_{}", std::process::id(), name));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    /// 直接查 attachments 表行数(不含 blob 列),用于断言。
    fn count_attachments(conn: &rusqlite::Connection, item_id: i64) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM attachments WHERE item_id = ?1",
            rusqlite::params![item_id],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
    }

    #[test]
    fn guess_mime_known_and_unknown() {
        // 已知扩展名。
        assert_eq!(
            guess_mime(Path::new("a.pdf")).as_deref(),
            Some("application/pdf")
        );
        assert_eq!(
            guess_mime(Path::new("b.PNG")).as_deref(),
            Some("image/png")
        );
        assert_eq!(
            guess_mime(Path::new("c.jpeg")).as_deref(),
            Some("image/jpeg")
        );
        assert_eq!(
            guess_mime(Path::new("d.json")).as_deref(),
            Some("application/json")
        );
        assert_eq!(
            guess_mime(Path::new("e.docx")).as_deref(),
            Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        );
        // 未知扩展 / 无扩展 → None。
        assert_eq!(guess_mime(Path::new("f.xyz")), None);
        assert_eq!(guess_mime(Path::new("noext")), None);
    }

    #[test]
    fn attachment_belongs_to_logic() {
        let p = make_vault("att_belongs");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        let conn = u.db.conn();
        // 插一个附件到 item 1。
        let mut att = Attachment {
            id: None,
            item_id: 1,
            filename: "x.bin".into(),
            mime_type: None,
            size: 0,
            blob: vec![1, 2, 3],
        };
        let aid = store::insert_attachment(conn, &mut att).unwrap();
        // 归属正确 / 不归属其它 item / 不存在。
        assert!(attachment_belongs_to(conn, aid, 1).unwrap());
        assert!(!attachment_belongs_to(conn, aid, 2).unwrap());
        assert!(!attachment_belongs_to(conn, 99999, 1).unwrap());
        cleanup(&p);
    }

    #[test]
    fn run_attach_add_ls_get_rm_roundtrip() {
        let p = make_vault("att_flow");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();

        // 1. add:把一个临时文件挂到 item 1。
        let blob = b"\x00hello-attachment\xff".to_vec();
        let att_file = write_att_file("src.txt", &blob);
        let aid = run_attach_add(&u, 1, &att_file, Some("text/plain")).unwrap();
        assert!(aid > 0);
        assert_eq!(count_attachments(u.db.conn(), 1), 1);

        // 验证落库的元数据(filename 保留 basename、size/mime/blob)。
        let got = store::get_attachment(u.db.conn(), aid).unwrap().unwrap();
        let basename = att_file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        assert_eq!(got.filename, basename);
        assert_eq!(got.size, blob.len() as i64);
        assert_eq!(got.mime_type.as_deref(), Some("text/plain"));
        assert_eq!(got.blob, blob);
        cleanup(&att_file);

        // 2. ls:不报错,且 item 1 有 1 条;item 2 为空。
        assert!(run_attach_ls(&u, 1).is_ok());
        assert_eq!(count_attachments(u.db.conn(), 1), 1);
        assert_eq!(count_attachments(u.db.conn(), 2), 0);

        // 3. get -o <out>:读回对比 blob 一致。
        let out = tmp_path("att_out");
        run_attach_get(&u, 1, aid, Some(&out)).unwrap();
        let read_back = std::fs::read(&out).unwrap();
        assert_eq!(read_back, blob);
        cleanup(&out);

        // get 归属错误(item 不匹配)→ 报错。
        assert!(matches!(
            run_attach_get(&u, 2, aid, None),
            Err(Error::Other(_))
        ));
        // get 不存在的附件 → 报错。
        assert!(matches!(
            run_attach_get(&u, 1, 99999, None),
            Err(Error::Other(_))
        ));

        // 4. rm:删除后再 ls 为空。
        run_attach_rm(&u, 1, aid).unwrap();
        assert_eq!(count_attachments(u.db.conn(), 1), 0);
        assert!(matches!(
            run_attach_rm(&u, 1, aid),
            Err(Error::Other(_))
        ));

        // 落盘读回:删除持久化。
        drop(u);
        let pf2 = write_passfile("u2");
        let u2 = Unlocked::unlock(&p, Some(&pf2)).unwrap();
        assert_eq!(count_attachments(u2.db.conn(), 1), 0);
        cleanup(&p);
    }

    #[test]
    fn run_attach_add_missing_item_errors() {
        let p = make_vault("att_baditem");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        let f = write_att_file("x", b"data");
        // item 不存在 → Error::Other。
        let err = run_attach_add(&u, 9999, &f, None);
        assert!(matches!(err, Err(Error::Other(_))));
        cleanup(&f);
        cleanup(&p);
    }

    #[test]
    fn run_attach_add_missing_file_errors() {
        let p = make_vault("att_badfile");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // 源文件不存在 → 读文件失败(冒泡为 Err)。
        let f = tmp_path("does_not_exist");
        cleanup(&f);
        assert!(run_attach_add(&u, 1, &f, None).is_err());
        cleanup(&p);
    }

    #[test]
    fn run_attach_ls_empty_prints_no_attachments() {
        let p = make_vault("att_ls_empty");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // item 1 无附件 → Ok(打印 (no attachments))。
        assert!(run_attach_ls(&u, 1).is_ok());
        assert_eq!(count_attachments(u.db.conn(), 1), 0);
        cleanup(&p);
    }

    #[test]
    fn run_attach_add_guesses_mime_from_extension() {
        let p = make_vault("att_mime");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // 不传 --mime,由扩展名推断 .json。
        let f = write_att_file("data.json", b"{}");
        let aid = run_attach_add(&u, 1, &f, None).unwrap();
        let got = store::get_attachment(u.db.conn(), aid).unwrap().unwrap();
        assert_eq!(got.mime_type.as_deref(), Some("application/json"));
        cleanup(&f);
        cleanup(&p);
    }

    // --- 密码生成(generate_password / run_gen / add --gen-password) ---

    /// 字符池基集(字母 + 数字)。
    fn is_alnum(c: char) -> bool {
        c.is_ascii_alphanumeric()
    }
    /// 是否属于符号集。
    fn is_symbol(c: char) -> bool {
        "!@#$%^&*()-_=+[]{};:,.?/".contains(c)
    }
    /// 是否属于易混集。
    fn is_ambiguous(c: char) -> bool {
        "0Oo1lI|5S2ZB8".contains(c)
    }

    #[test]
    fn generate_password_default_length_and_charset() {
        let pw = generate_password(20, true, false).unwrap();
        assert_eq!(pw.len(), 20);
        // 默认含符号 → 池里每个字符应来自 alnum 或符号集。
        assert!(pw.chars().all(|c| is_alnum(c) || is_symbol(c)));
    }

    #[test]
    fn generate_password_no_symbols() {
        let pw = generate_password(40, false, false).unwrap();
        assert_eq!(pw.len(), 40);
        // 不含符号:全字母数字,且不含任何符号集字符。
        assert!(pw.chars().all(is_alnum));
        assert!(!pw.chars().any(is_symbol));
    }

    #[test]
    fn generate_password_no_ambiguous() {
        let pw = generate_password(40, true, true).unwrap();
        assert_eq!(pw.len(), 40);
        // 不含任何易混字符。
        assert!(!pw.chars().any(is_ambiguous));
    }

    #[test]
    fn generate_password_length_respected() {
        for &len in &[4usize, 5, 16, 32, 100] {
            let pw = generate_password(len, true, false).unwrap();
            assert_eq!(pw.len(), len);
        }
    }

    #[test]
    fn generate_password_two_runs_differ() {
        // 概率性:两次独立生成应(几乎必然)不同。
        let a = generate_password(32, true, false).unwrap();
        let b = generate_password(32, true, false).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn generate_password_too_short_errors() {
        assert!(matches!(
            generate_password(3, true, false),
            Err(Error::Other(m)) if m.contains("too short")
        ));
    }

    #[test]
    fn generate_password_too_long_errors() {
        assert!(matches!(
            generate_password(2000, true, false),
            Err(Error::Other(m)) if m.contains("too long")
        ));
    }

    #[test]
    fn run_gen_prints_password() {
        // run_gen 写到 stdout;验证返回 Ok(不在此捕获 stdout,仅断言不报错)。
        assert!(run_gen(16, true, false).is_ok());
        assert!(run_gen(8, false, true).is_ok());
    }

    #[test]
    fn run_add_gen_password_overrides_field() {
        let p = make_vault("addgen");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // --data 里 password 是占位 "old",--gen-password 12 应覆盖。
        let data = r#"{"type":"password","username":"bob","password":"old","url":"https://x","totp_secret":"","notes":""}"#;
        let id = run_add(&u, "Gen", data, vec![], false, Some(12)).unwrap();
        assert!(id > 0);

        let got = store::get_item(u.db.conn(), id).unwrap().unwrap();
        let pw = item_field(&got, "password").unwrap();
        assert_eq!(pw.len(), 12);
        assert_ne!(pw, "old");
        // 默认 generate_password(len, true, true) → 含符号、去易混。
        assert!(pw.chars().all(|c| is_alnum(c) || is_symbol(c)));
        assert!(!pw.chars().any(is_ambiguous));
        cleanup(&p);
    }

    #[test]
    fn run_add_gen_password_non_password_errors() {
        let p = make_vault("addgennp");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        // note 条目 + --gen-password → 报错。
        let data = r#"{"type":"note","format":"text","content":"hi"}"#;
        let err = run_add(&u, "N", data, vec![], false, Some(20));
        assert!(matches!(err, Err(Error::Other(m)) if m.contains("--gen-password")));
        cleanup(&p);
    }
}
