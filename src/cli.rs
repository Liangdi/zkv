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
use crate::model::{Item, ItemData, ItemType};
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
}

/// 把 `ListFilter` + 已解析的 `category_id` 转成 [`search::Filter`]。
fn to_search_filter(list: &ListFilter, category_id: Option<i64>) -> Filter {
    Filter {
        query: list.query.clone(),
        category: category_id,
        tags: list.tags.clone(),
        item_type: list.item_type,
        favorite_only: false,
    }
}

/// 根据分类名解析其 id;找不到返回 `None`(调用方可决定报错或空结果)。
fn category_id_by_name(conn: &rusqlite::Connection, name: &str) -> Result<Option<i64>> {
    let cats = store::list_categories(conn)?;
    Ok(cats.into_iter().find(|c| c.name == name).and_then(|c| c.id))
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
/// 成功后向 stdout 打印 `added item <id>: <title>` 并返回新 id。
pub fn run_add(
    u: &Unlocked,
    title: &str,
    data_json: &str,
    tags: Vec<String>,
    favorite: bool,
) -> Result<i64> {
    let data: ItemData = serde_json::from_str(data_json)?;
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
    Ok(id)
}

/// `edit`:修改已存在条目的若干字段。每个参数为 `None` 表示「不改」。
///
/// 至少要改一处(title/data/tags/favorite 之一);全 `None` 报错。
/// 替换 data 时同步 `item_type`,保持与 data tag 一致。成功打印 `updated item <id>`。
pub fn run_edit(
    u: &Unlocked,
    id: i64,
    title: Option<&str>,
    data_json: Option<&str>,
    tags: Option<Vec<String>>,
    favorite: Option<bool>,
) -> Result<()> {
    let mut item = store::get_item(u.db.conn(), id)?
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
    if !changed {
        return Err(Error::Other("edit: nothing to change".into()));
    }

    store::update_item(u.db.conn(), &item)?;
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
// 只读命令
// ---------------------------------------------------------------------------

/// `ls`:按过滤条件列出条目。
pub fn run_ls(u: &Unlocked, f: &ListFilter, json: bool) -> Result<()> {
    let conn = u.db.conn();
    let category_id = match &f.category {
        Some(name) => Some(
            category_id_by_name(conn, name)?
                .ok_or_else(|| Error::Other(format!("category '{name}' not found")))?,
        ),
        None => None,
    };
    let sf = to_search_filter(f, category_id);
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
        };
        let sf = to_search_filter(&lf, Some(7));
        assert_eq!(sf.item_type, Some(ItemType::Password));
        assert_eq!(sf.tags, vec!["a".to_string()]);
        assert_eq!(sf.category, Some(7));
        assert_eq!(sf.query.as_deref(), Some("q"));
        assert!(!sf.favorite_only);
    }

    // --- 端到端(只读命令返回 Ok/Err 路径) ---

    #[test]
    fn run_ls_returns_ok() {
        let p = make_vault("ls");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        let f = ListFilter::default();
        assert!(run_ls(&u, &f, false).is_ok());
        assert!(run_ls(&u, &f, true).is_ok());
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
        let err = run_ls(&u, &f, false);
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
        let id = run_add(&u, "Server", data, vec!["ops".into()], true).unwrap();
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
        assert!(run_add(&u, "X", "{ not json", vec![], false).is_err());
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
        run_edit(&u, 1, Some("JustTitle"), None, None, None).unwrap();
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
        let err = run_edit(&u, 1, None, None, None, None);
        assert!(matches!(err, Err(Error::Other(_))));
    }

    #[test]
    fn run_edit_missing_item_errors() {
        let p = make_vault("editmissing");
        let pf = write_passfile("u");
        let u = Unlocked::unlock(&p, Some(&pf)).unwrap();
        let err = run_edit(&u, 9999, Some("x"), None, None, None);
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
}
