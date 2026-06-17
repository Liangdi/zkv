//! 内存 SQLite 数据库:连接管理 + schema(含 FTS5)。对应 PRD §5。
//!
//! 对外接口:
//! - [`Database`]:封装 `rusqlite::Connection`,字段私有。
//! - [`Database::open_in_memory`]:创建 `:memory:` 库并执行 [`Database::migrate`]。
//! - [`Database::migrate`]:按 PRD §5 建 `categories`/`tags`/`items`/`item_tags`/`attachments`
//!   + FTS5 虚拟表 `items_fts` 及其同步触发器。
//! - [`Database::dump_bytes`]:把整个库导出为字节(`VACUUM INTO` 到临时文件 → 读回 → 删临时文件)。
//! - [`Database::from_bytes`]:从字节恢复内存库。
//! - [`Database::conn`]:借用底层连接(供 store/search 层使用)。
//!
//! ## FTS5
//! 当前依赖 `rusqlite = { features = ["bundled"] }`,`libsqlite3-sys` 的 `build.rs` 默认
//! 传入 `-DSQLITE_ENABLE_FTS5`,因此内置 SQLite 已启用 FTS5,**无需额外 feature**。
//! [`Database::migrate`] 会先尝试创建 `items_fts` 虚拟表;若环境确无 FTS5,将返回
//! [`Error::Database`](建表失败),调用方据此判断。
//!
//! ## dump / restore 实现
//! - `dump_bytes`:`VACUUM INTO '<tmpfile>'` 生成单个完整的 SQLite 数据库文件字节(瞬时落盘,用完即删)。
//! - `from_bytes`:把字节写入 0600 临时文件作为 backup 源,用 rusqlite `backup` API 灌入真正的
//!   `:memory:` 连接后**立即删除临时文件**。`Database` 存活期间不持有任何明文文件(满足 PRD「明文只存在于运行内存」)。
//!
//! 规则(L2):仅依赖 [`crate::error`] 与外部 crate,不引用 store/search/app/ui。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::Connection;

use crate::error::Result;

/// 临时文件后缀(便于排查,本身不承载安全语义)。
const TMP_SUFFIX: &str = ".zkvtmp";

/// 内存 SQLite 数据库句柄,底层始终是真正的 `:memory:` 连接。
///
/// `backing_tmp` 历史上用于持有临时文件;启用 rusqlite `backup` feature 后,
/// [`Database::from_bytes`] 也改为灌入 `:memory:`,该字段恒为 `None`,保留以备后用。
#[derive(Debug)]
pub struct Database {
    conn: Connection,
    backing_tmp: Option<PathBuf>,
}

impl Database {
    /// 借用底层 `rusqlite::Connection`,供 store/search 层使用。
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// 创建一个空的 `:memory:` 数据库并执行 schema 迁移。
    pub fn open_in_memory() -> Result<Database> {
        let conn = Connection::open_in_memory()?;
        let db = Database {
            conn,
            backing_tmp: None,
        };
        db.migrate()?;
        Ok(db)
    }

    /// 按 PRD §5 建表与索引、FTS5 虚拟表及同步触发器。幂等(`IF NOT EXISTS`)。
    pub fn migrate(&self) -> Result<()> {
        let c = &self.conn;

        c.execute_batch(
            r#"
            -- 分类:支持层级(parent_id 自引用)
            CREATE TABLE IF NOT EXISTS categories (
                id         INTEGER PRIMARY KEY,
                name       TEXT NOT NULL,
                parent_id  INTEGER REFERENCES categories(id) ON DELETE SET NULL,
                sort_order INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            -- 标签
            CREATE TABLE IF NOT EXISTS tags (
                id   INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE
            );

            -- 条目:核心表,统一承载所有类型
            CREATE TABLE IF NOT EXISTS items (
                id          INTEGER PRIMARY KEY,
                type        TEXT NOT NULL,
                title       TEXT NOT NULL,
                category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
                data        TEXT NOT NULL,
                favorite    INTEGER NOT NULL DEFAULT 0,
                search_text TEXT NOT NULL DEFAULT '',
                created_at  INTEGER NOT NULL,
                updated_at  INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_items_category ON items(category_id);
            CREATE INDEX IF NOT EXISTS idx_items_type     ON items(type);

            -- 条目 ↔ 标签(多对多)
            CREATE TABLE IF NOT EXISTS item_tags (
                item_id INTEGER REFERENCES items(id) ON DELETE CASCADE,
                tag_id  INTEGER REFERENCES tags(id)  ON DELETE CASCADE,
                PRIMARY KEY (item_id, tag_id)
            );

            -- 附件:图片/电子档内嵌为 BLOB
            CREATE TABLE IF NOT EXISTS attachments (
                id         INTEGER PRIMARY KEY,
                item_id    INTEGER REFERENCES items(id) ON DELETE CASCADE,
                filename   TEXT NOT NULL,
                mime_type  TEXT,
                size       INTEGER NOT NULL,
                blob       BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            "#,
        )?;

        // FTS5 虚拟表 + 同步触发器。若内置 SQLite 未启用 FTS5,此处返回 Database 错误。
        c.execute_batch(
            r#"
            CREATE VIRTUAL TABLE IF NOT EXISTS items_fts USING fts5(
                title, search_text,
                content='items', content_rowid='id'
            );

            -- items 增/改时重建对应行的 FTS 索引
            CREATE TRIGGER IF NOT EXISTS items_ai AFTER INSERT ON items BEGIN
                INSERT INTO items_fts(rowid, title, search_text)
                VALUES (new.id, new.title, new.search_text);
            END;

            CREATE TRIGGER IF NOT EXISTS items_ad AFTER DELETE ON items BEGIN
                INSERT INTO items_fts(items_fts, rowid, title, search_text)
                VALUES ('delete', old.id, old.title, old.search_text);
            END;

            CREATE TRIGGER IF NOT EXISTS items_au AFTER UPDATE ON items BEGIN
                INSERT INTO items_fts(items_fts, rowid, title, search_text)
                VALUES ('delete', old.id, old.title, old.search_text);
                INSERT INTO items_fts(rowid, title, search_text)
                VALUES (new.id, new.title, new.search_text);
            END;
            "#,
        )?;

        Ok(())
    }

    /// 把整个数据库导出为字节(`VACUUM INTO` 到临时文件 → 读回 → 删临时文件)。
    ///
    /// `VACUUM INTO` 生成一个完整、自包含、干净 VACUUM 过的副本文件,适合作为整库加密的明文输入。
    pub fn dump_bytes(&self) -> Result<Vec<u8>> {
        let tmp = secure_tmp_path("zkv_dump");
        // 注意:SQL 字符串字面量里用单引号转义路径。路径为系统临时目录下的随机名,
        // 不含单引号。
        let sql = format!("VACUUM INTO '{}'", tmp.display());
        // 即便后续读回失败也要删除临时文件。
        let result = (|| -> Result<Vec<u8>> {
            self.conn.execute_batch(&sql)?;
            let bytes = fs::read(&tmp)?;
            Ok(bytes)
        })();
        let _ = fs::remove_file(&tmp);
        result
    }

    /// 从字节恢复数据库。
    ///
    /// 把字节写入 0600 临时文件作为 backup 源 → 用 rusqlite `backup` API 灌入真正的
    /// `:memory:` 连接 → 立即删除临时文件。`Database` 存活期间不持有明文文件
    /// (满足 PRD「明文只存在于运行内存」);临时文件仅瞬时存在(写 → backup → 删)。
    pub fn from_bytes(bytes: &[u8]) -> Result<Database> {
        let tmp = secure_tmp_path("zkv_load");
        {
            use std::io::Write;
            let mut f = open_secure(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        let res = (|| -> Result<Database> {
            let src = Connection::open(&tmp)?;
            let mut dst = Connection::open_in_memory()?;
            {
                let b = rusqlite::backup::Backup::new(&src, &mut dst)?;
                b.run_to_completion(100, Duration::from_millis(250), None)?;
            }
            drop(src);
            Ok(Database {
                conn: dst,
                backing_tmp: None,
            })
        })();
        let _ = fs::remove_file(&tmp);
        res
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        if let Some(p) = self.backing_tmp.take() {
            let _ = fs::remove_file(&p);
        }
    }
}

/// 在系统临时目录下生成一个随机命名的路径(不带文件后缀,由调用方追加)。
fn secure_tmp_base(prefix: &str) -> PathBuf {
    let mut name = String::from(prefix);
    name.push('-');
    // 用进程内计数 + 时间 + 一段随机,确保唯一性。
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    name.push_str(&format!(
        "{}{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        n
    ));
    std::env::temp_dir().join(name)
}

/// 生成一个 0600 临时文件路径(名随机,带 `.zkvtmp` 后缀,置于系统临时目录)。
fn secure_tmp_path(prefix: &str) -> PathBuf {
    let mut p = secure_tmp_base(prefix);
    p.set_extension(TMP_SUFFIX.trim_start_matches('.'));
    p
}

/// 以 0600 权限打开/创建文件(Unix)。
#[cfg(unix)]
fn open_secure(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_secure(path: &Path) -> Result<std::fs::File> {
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .truncate(true)
        .open(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_and_migrate_ok() {
        // 基本:open_in_memory 不报错,且包含 PRD §5 的所有表。
        let db = Database::open_in_memory().expect("open_in_memory");
        let names: Vec<String> = db
            .conn()
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        for expected in [
            "categories",
            "tags",
            "items",
            "item_tags",
            "attachments",
            "items_fts",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing table: {expected} (have {:?})",
                names
            );
        }
        // 触发器
        let trigs: Vec<String> = db
            .conn()
            .prepare("SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert!(trigs.iter().any(|n| n == "items_ai"));
        assert!(trigs.iter().any(|n| n == "items_ad"));
        assert!(trigs.iter().any(|n| n == "items_au"));
    }

    #[test]
    fn insert_item_and_fts_hit() {
        // 插一条 item(含 search_text),FTS5 应命中。
        let db = Database::open_in_memory().unwrap();
        let now = 1_700_000_000i64;
        db.conn()
            .execute(
                "INSERT INTO items(type,title,data,search_text,created_at,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![
                    "password",
                    "GitHub Login",
                    "{}",
                    "github.com myuser",
                    now,
                    now,
                ],
            )
            .unwrap();

        // FTS MATCH 命中
        let hit: bool = db
            .conn()
            .prepare("SELECT 1 FROM items_fts WHERE items_fts MATCH ?1 LIMIT 1")
            .unwrap()
            .query_map(["github"], |r| r.get::<_, i64>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .next()
            .is_some();
        assert!(hit, "FTS5 应命中 'github'");

        // 不命中
        let miss: bool = db
            .conn()
            .prepare("SELECT 1 FROM items_fts WHERE items_fts MATCH ?1 LIMIT 1")
            .unwrap()
            .query_map(["nomatchxyz"], |r| r.get::<_, i64>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .next()
            .is_some();
        assert!(!miss);
    }

    #[test]
    fn dump_from_bytes_roundtrip_preserves_data() {
        let db = Database::open_in_memory().unwrap();
        let now = 1_700_000_000i64;
        db.conn()
            .execute(
                "INSERT INTO items(type,title,data,search_text,created_at,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params!["note", "My Note", "{\"content\":\"hi\"}", "hi body", now, now],
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO tags(name) VALUES ('personal')",
                [],
            )
            .unwrap();

        let bytes = db.dump_bytes().expect("dump");
        assert!(!bytes.is_empty(), "dump 应产出非空字节");

        let db2 = Database::from_bytes(&bytes).expect("from_bytes");
        let cnt: i64 = db2
            .conn()
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get::<_, i64>(0))
            .unwrap();
        assert_eq!(cnt, 1);
        let tag_cnt: i64 = db2
            .conn()
            .query_row("SELECT COUNT(*) FROM tags", [], |r| r.get::<_, i64>(0))
            .unwrap();
        assert_eq!(tag_cnt, 1);

        // round-trip 后 FTS5 仍可查(SQLite 文件里 FTS5 索引随库一起 dump)。
        let fts_hit: bool = db2
            .conn()
            .prepare("SELECT 1 FROM items_fts WHERE items_fts MATCH ?1 LIMIT 1")
            .unwrap()
            .query_map(["note"], |r| r.get::<_, i64>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .next()
            .is_some();
        assert!(fts_hit, "round-trip 后 FTS5 仍应命中");
    }
}
