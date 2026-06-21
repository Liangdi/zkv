//! 内存 SQLite 数据库:连接管理 + schema(含 FTS5)。对应 PRD §5。
//!
//! 对外接口:
//! - [`Database`]:封装 `rusqlite::Connection`,字段私有。
//! - [`Database::open_in_memory`]:创建 `:memory:` 库并执行 [`Database::migrate`]。
//! - [`Database::migrate`]:按 PRD §5 建 `categories`/`tags`/`items`/`item_tags`/`attachments`
//!   + FTS5 虚拟表 `items_fts` 及其同步触发器。
//! - [`Database::dump_bytes`]:把整个库导出为字节(`VACUUM INTO` 到临时文件 → 读回 → 删临时文件)。
//! - [`Database::from_bytes`][]:从字节恢复内存库。
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
    ///
    /// 随后执行 [`Database::migrate_data`]:空库瞬时完成(`user_version` 0 → 1),
    /// 保证打开后即为新形状(老库经 [`Database::from_bytes`] 接入迁移)。
    pub fn open_in_memory() -> Result<Database> {
        let conn = Connection::open_in_memory()?;
        let db = Database {
            conn,
            backing_tmp: None,
        };
        db.migrate()?;
        db.migrate_data()?;
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

            -- 字段模板(A1):承载内置/自定义模板。fields 为 FieldSpec 数组的 JSON。
            CREATE TABLE IF NOT EXISTS templates (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                fields     TEXT NOT NULL,
                built_in  INTEGER NOT NULL DEFAULT 0,
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

    /// 把历史形状(`items.data` 为 `ItemData` tagged JSON)迁移为新形状
    /// (`items.data` 为 `Vec<Field>` JSON 数组),并重算 `search_text`。
    ///
    /// 已接入 live 打开路径:[`open_in_memory`](Self::open_in_memory) 在 `migrate` 后调用
    /// (空库瞬时,`user_version` 0→1);[`from_bytes`](Self::from_bytes) 在 backup 灌入后调用
    /// (老库就地迁移)。这样老库打开自动转新形状,新库直接落新形状。
    ///
    /// 幂等性:用 `PRAGMA user_version` 作迁移水位。`>= 1` 视为已迁移,立即返回。
    ///
    /// 实现要点:
    /// - `Database.conn` 是 `Connection`(非 `&mut`),无法直接调用 `conn.transaction()`
    ///   (需 `&mut`)。因此用 `BEGIN IMMEDIATE; ... UPDATE ...; COMMIT;` 的 `execute_batch`
    ///   语义在同一连接上模拟事务:逐条 `execute` 在 `BEGIN`/`COMMIT` 之间执行,任一语句出错
    ///   时整体回滚(错误向上传播,不执行 `COMMIT`/不升 user_version)。
    /// - `PRAGMA user_version = 1` 必须在事务 `COMMIT` **之后**执行:pragma 不随事务回滚,
    ///   若中途出错则版本不升,可重试。
    /// - 对每行 `data`:先试新形状(`Vec<Field>`),再试 legacy(`LegacyItemData`),
    ///   两者都失败的「损坏」行跳过更新(不中断整体迁移)。
    pub fn migrate_data(&self) -> Result<()> {
        let c = &self.conn;

        let v: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if v >= 1 {
            return Ok(());
        }

        // 收集所有 items 的 (id, type, data)——在开启事务前读取,避免长事务持有读锁。
        let mut stmt = c.prepare("SELECT id, type, data FROM items")?;
        let rows: Vec<(i64, String, String)> = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);

        // 开启事务。BEGIN IMMEDIATE 立即获取保留锁,语义同 transaction()。
        c.execute_batch("BEGIN IMMEDIATE")?;

        // 任一 UPDATE 出错时:回滚并把错误向上传播,不执行 COMMIT、不升 user_version。
        let tx_result: Result<()> = (|| {
            for (id, ty, data) in &rows {
                // 先试新形状。
                if let Ok(fields) = serde_json::from_str::<Vec<crate::model::Field>>(data) {
                    let new_json = serde_json::to_string(&fields)?;
                    let st = crate::model::fields_search_text(&fields);
                    c.execute(
                        "UPDATE items SET type=?1, data=?2, search_text=?3 WHERE id=?4",
                        rusqlite::params![ty, new_json, st, id],
                    )?;
                    continue;
                }
                // 再试 legacy。
                if let Ok(legacy) = serde_json::from_str::<crate::model::LegacyItemData>(data) {
                    let (tpl, fields) = crate::model::legacy_to_fields(legacy);
                    let new_json = serde_json::to_string(&fields)?;
                    let st = crate::model::fields_search_text(&fields);
                    c.execute(
                        "UPDATE items SET type=?1, data=?2, search_text=?3 WHERE id=?4",
                        rusqlite::params![tpl, new_json, st, id],
                    )?;
                    continue;
                }
                // 损坏:跳过(不更新该行,不中断)。
            }
            Ok(())
        })();

        match tx_result {
            Ok(()) => {
                c.execute_batch("COMMIT")?;
                // 升水位:必须在 COMMIT 之后(pragma 不随事务回滚)。
                c.execute_batch("PRAGMA user_version = 1")?;
                Ok(())
            }
            Err(e) => {
                // 尽力回滚;回滚失败不掩盖原错误。
                let _ = c.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// 把整个数据库导出为字节(`VACUUM INTO` 到临时文件 → 读回 → 删临时文件)。
    ///
    /// `VACUUM INTO` 生成一个完整、自包含、干净 VACUUM 过的副本文件,适合作为整库加密的明文输入。
    pub fn dump_bytes(&self) -> Result<Vec<u8>> {
        let tmp = secure_tmp_path("zkv_dump")?;
        // 注意:SQL 字符串字面量里用单引号转义路径。路径为安全基目录下的随机名,
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
        let tmp = secure_tmp_path("zkv_load")?;
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
            let db = Database {
                conn: dst,
                backing_tmp: None,
            };
            // 老库就地在内存副本上迁移:补 schema(幂等,如 templates 表)+
            // 数据形状(legacy → Vec<Field>),search_text 重算。user_version 门控,可重入。
            db.migrate()?;
            db.migrate_data()?;
            Ok(db)
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

/// 返回明文临时文件应落入的**安全基目录**。
///
/// - Unix:系统临时目录(临时文件本身由 [`open_secure`] 设 `0600`)。
/// - Windows:一个 **owner-only 私有子目录**([`win_security::secure_tmp_dir`]),
///   使即便由 SQLite `VACUUM INTO` 自建的临时文件也受目录 ACL 兜底(继承 owner-only ACE)。
fn secure_tmp_dir() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        Ok(std::env::temp_dir())
    }
    #[cfg(windows)]
    {
        win_security::secure_tmp_dir()
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(std::env::temp_dir())
    }
}

/// 在安全基目录下生成一个不可预测命名的路径(不带文件后缀,由调用方追加)。
///
/// 文件名取自 CSPRNG(`getrandom`),避免可预测的时间戳/计数器(防御纵深):
/// 这些临时文件瞬时持有**明文 SQLite**,名不可预测减少攻击面。唯一性由
/// [`open_secure`] 的 `create_new`/`CREATE_NEW` 原子创建保证。
fn secure_tmp_base(prefix: &str) -> Result<PathBuf> {
    let mut buf = [0u8; 16];
    // CSPRNG;系统熵故障无合理恢复路径,直接 expect(与 crypto.rs 一致)。
    getrandom::fill(&mut buf).expect("getrandom::fill failed for temp name");
    let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
    let mut name = String::from(prefix);
    name.push('-');
    name.push_str(&hex);
    Ok(secure_tmp_dir()?.join(name))
}

/// 生成一个安全临时文件路径(名随机,带 `.zkvtmp` 后缀)。
fn secure_tmp_path(prefix: &str) -> Result<PathBuf> {
    let mut p = secure_tmp_base(prefix)?;
    p.set_extension(TMP_SUFFIX.trim_start_matches('.'));
    Ok(p)
}

/// 以 owner-only 权限打开/创建文件(已存在则报错,对齐 `create_new`)。
///
/// - Unix:`0600`。
/// - Windows:`CreateFileW` + owner-only DACL(见 [`win_security::open_secure_file`])。
/// - 其他平台:无文件权限语义,fallback 到默认打开。
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

#[cfg(windows)]
fn open_secure(path: &Path) -> Result<std::fs::File> {
    win_security::open_secure_file(path)
}

#[cfg(not(any(unix, windows)))]
fn open_secure(path: &Path) -> Result<std::fs::File> {
    Ok(std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .truncate(true)
        .open(path)?)
}

/// Windows owner-only ACL:为明文临时文件/目录构造仅当前用户可访问的安全描述符。
///
/// 背景:`std::fs` 在 Windows 上无法设文件 ACL,默认继承的 DACL 可能让同机其他用户读到
/// 明文临时文件。此处用 `windows-sys` 构造 owner-only DACL:文件用 [`open_secure_file`]
/// 创建即带权限(无 TOCTOU);目录用 [`create_dir_owner_only`] 且带继承 ACE,使 SQLite
/// `VACUUM INTO` 自建的文件也继承 owner-only —— 单文件 ACL 管不到 SQLite 自建文件,目录 ACL 兜底。
#[cfg(windows)]
pub(crate) mod win_security {
    use std::ffi::c_void;
    use std::path::{Path, PathBuf};
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_ALL, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
        TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        CONTAINER_INHERIT_ACE, GetTokenInformation, InitializeSecurityDescriptor, NO_INHERITANCE,
        OBJECT_INHERIT_ACE, SetSecurityDescriptorDacl, ACL, SECURITY_ATTRIBUTES,
        SECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, CREATE_NEW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use crate::error::{Error, Result};

    /// per-process 缓存的安全临时目录(线程安全单例)。
    static SECURE_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

    /// 返回 owner-only 私有临时目录(惰性创建、同进程复用)。
    ///
    /// 目录名随机(`%TEMP%\zkv-<hex>`),置于世界可列的系统临时目录下而不暴露固定名;
    /// 带继承 ACE,目录内任何文件(含 SQLite `VACUUM INTO` 自建的)均继承 owner-only。
    pub(super) fn secure_tmp_dir() -> Result<PathBuf> {
        if let Some(d) = SECURE_DIR.get() {
            return Ok(d.clone());
        }
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).expect("getrandom::fill failed for tmp dir name");
        let hex: String = buf.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("zkv-{hex}"));
        create_dir_owner_only(&dir)?;
        // 并发:两线程各自建随机名目录(名字不同,无冲突);败者丢弃自己的,统一用胜者的。
        let _ = SECURE_DIR.set(dir);
        Ok(SECURE_DIR.get().expect("secure tmp dir set").clone())
    }

    /// owner-only ACL 的 RAII 持有者:`acl` 由 `SetEntriesInAclW` 经 `LocalAlloc` 分配,Drop 时 `LocalFree`。
    ///
    /// 仅持有 `acl`。`SetEntriesInAclW` 会把 trustee SID **复制**进新 ACL,故 token 与 token buffer
    /// 在 [`build`](OwnerOnlyAcl::build) 内用完即释放。安全描述符(SD)/`SECURITY_ATTRIBUTES` 不在此
    /// 持有 —— 它们由调用方作为局部变量构造并指向 `acl`(见 [`build_sa`]),避免返回后 SD 被 move
    /// 导致 `SA.lpSecurityDescriptor` 悬垂(dangling pointer)。
    struct OwnerOnlyAcl {
        acl: *mut ACL,
    }

    impl OwnerOnlyAcl {
        /// 构造 owner-only ACL。`inherit=true` 时 ACE 带 `CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`
        /// (供目录,让子文件继承 owner-only);`false` 时用 `NO_INHERITANCE`(单文件)。
        fn build(inherit: bool) -> Result<Self> {
            unsafe {
                // 1. 当前进程 token
                let mut token: HANDLE = ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return Err(io_err("OpenProcessToken"));
                }

                // 2. 探测 TokenUser 所需大小,再取(失败即关闭句柄)
                let mut len: u32 = 0;
                GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len);
                let mut token_buf = vec![0u8; len as usize];
                let token_ok = GetTokenInformation(
                    token,
                    TokenUser,
                    token_buf.as_mut_ptr() as *mut c_void,
                    len,
                    &mut len,
                ) != 0;
                if !token_ok {
                    CloseHandle(token);
                    return Err(io_err("GetTokenInformation"));
                }
                let user_sid = (*(token_buf.as_ptr() as *const TOKEN_USER)).User.Sid;

                // 3. EXPLICIT_ACCESS_W:grant 当前用户 GENERIC_ALL(以 SID 形式,免名字解析)。
                //    SetEntriesInAclW 会**复制** SID 进新 ACL,故 token_buf 此后可释放。
                let mut trustee: TRUSTEE_W = std::mem::zeroed();
                trustee.TrusteeForm = TRUSTEE_IS_SID;
                trustee.TrusteeType = TRUSTEE_IS_USER;
                trustee.ptstrName = user_sid as *mut u16;

                let mut ea: EXPLICIT_ACCESS_W = std::mem::zeroed();
                ea.grfAccessPermissions = GENERIC_ALL;
                ea.grfAccessMode = GRANT_ACCESS;
                ea.grfInheritance = if inherit {
                    CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
                } else {
                    NO_INHERITANCE
                };
                ea.Trustee = trustee;

                let mut acl: *mut ACL = ptr::null_mut();
                let acl_ok = SetEntriesInAclW(1, &ea, ptr::null(), &mut acl) == 0;
                CloseHandle(token); // token 用毕释放(SID 已复制进 acl)
                if !acl_ok || acl.is_null() {
                    if !acl.is_null() {
                        LocalFree(acl as *mut c_void);
                    }
                    return Err(io_err("SetEntriesInAclW"));
                }
                Ok(OwnerOnlyAcl { acl })
            }
        }
    }

    impl Drop for OwnerOnlyAcl {
        fn drop(&mut self) {
            unsafe {
                if !self.acl.is_null() {
                    LocalFree(self.acl as *mut c_void);
                }
            }
        }
    }

    /// 以 owner-only DACL 创建文件(已存在报错,对齐 unix `create_new`)。
    pub(crate) fn open_secure_file(path: &Path) -> Result<std::fs::File> {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;

        let owner = OwnerOnlyAcl::build(false)?;
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0); // CreateFileW 要求 NUL 终止
        // SD 与 SA 均为本函数局部变量:SA.lpSecurityDescriptor 指向局部 SD,SD.DACL 指向 owner.acl
        // (堆,存活到函数末 owner drop)。三者生命周期覆盖下面的 CreateFileW 调用,无悬垂指针。
        let mut sd: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let psec = core::ptr::addr_of_mut!(sd) as *mut c_void;
        let sa = build_sa(psec, &owner)?;

        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE | DELETE,
                FILE_SHARE_READ,
                &sa,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io_err("CreateFileW"));
        }
        Ok(unsafe { std::fs::File::from_raw_handle(h as _) })
    }

    /// 以 owner-only DACL(带继承 ACE)创建目录。
    fn create_dir_owner_only(path: &Path) -> Result<()> {
        use std::os::windows::ffi::OsStrExt;

        let owner = OwnerOnlyAcl::build(true)?;
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        let mut sd: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let psec = core::ptr::addr_of_mut!(sd) as *mut c_void;
        let sa = build_sa(psec, &owner)?;
        if unsafe { CreateDirectoryW(wide.as_ptr(), &sa) } == 0 {
            return Err(io_err("CreateDirectoryW"));
        }
        Ok(())
    }

    /// 在调用方提供的 SD 缓冲(`psec`)上初始化 owner-only DACL,返回指向它的 `SECURITY_ATTRIBUTES`。
    ///
    /// `psec` 必须指向调用方存活的 `SECURITY_DESCRIPTOR`(由调用方持有,保证 SA 有效);
    /// SA 的 move 仅拷贝指针值,仍指向调用方局部 SD,故无悬垂。
    fn build_sa(psec: *mut c_void, owner: &OwnerOnlyAcl) -> Result<SECURITY_ATTRIBUTES> {
        unsafe {
            if InitializeSecurityDescriptor(psec, 1 /* SECURITY_DESCRIPTOR_REVISION */) == 0
                || SetSecurityDescriptorDacl(psec, 1, owner.acl, 0) == 0
            {
                return Err(io_err("security descriptor"));
            }
            Ok(SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psec,
                bInheritHandle: 0,
            })
        }
    }

    /// 把上次 OS 错误包成 `Error::Io`(附带调用点便于排查)。
    fn io_err(ctx: &str) -> Error {
        let e = std::io::Error::last_os_error();
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("zkv win_security {ctx} failed: {e}"),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn secure_tmp_dir_exists() {
            // owner-only 私有目录应被成功创建(惰性、同进程复用)。
            let dir = secure_tmp_dir().expect("secure_tmp_dir");
            assert!(dir.is_dir(), "owner-only secure tmp dir should exist");
        }

        #[test]
        fn open_secure_file_existing_errors() {
            // CREATE_NEW 语义:已存在文件应报错(对齐 unix create_new 的 EEXIST)。
            let mut p = secure_tmp_dir().unwrap();
            p.push("zkv_test_exists_err");
            let _ = std::fs::remove_file(&p);
            {
                let _f = open_secure_file(&p).expect("first create should succeed");
            } // 释放句柄后再试
            let second = open_secure_file(&p);
            assert!(second.is_err(), "second create must fail (file exists)");
            let _ = std::fs::remove_file(&p);
        }
    }
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
        // open_in_memory 已升 user_version=1;重置回 0 模拟真实老库,from_bytes 才会就地迁移。
        db.conn().execute_batch("PRAGMA user_version = 0").unwrap();
        let now = 1_700_000_000i64;
        // 直接插一条 legacy note 形状(from_bytes 会就地迁移为新 Vec<Field>)。
        db.conn()
            .execute(
                "INSERT INTO items(type,title,data,search_text,created_at,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![
                    "note",
                    "My Note",
                    "{\"type\":\"note\",\"format\":\"text\",\"content\":\"hi\"}",
                    "hi body",
                    now,
                    now
                ],
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

        // 迁移后 data 应为 Vec<Field> JSON,内容字段值 "hi" 保留。
        let data: String = db2
            .conn()
            .query_row(
                "SELECT data FROM items WHERE title='My Note'",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap();
        assert!(data.contains("\"name\":\"content\""));
        assert!(data.contains("\"value\":\"hi\""));

        // round-trip 后 FTS5 仍可查(标题 "My Note" 由 FTS 索引;迁移重算 search_text 含 "hi")。
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

    // -----------------------------------------------------------------------
    // 字段模板迁移(A1)
    // -----------------------------------------------------------------------

    /// 辅助:读某行的 (type, data, search_text)。
    fn read_item_row(conn: &Connection, id: i64) -> (String, String, String) {
        conn.query_row(
            "SELECT type, data, search_text FROM items WHERE id = ?1",
            rusqlite::params![id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .unwrap()
    }

    fn user_version(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap()
    }

    #[test]
    fn migrate_data_converts_three_variants_and_corrupt() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        // open_in_memory 已把 user_version 升到 1;重置回 0 以模拟老库,插入 legacy 行后再迁移。
        conn.execute_batch("PRAGMA user_version = 0").unwrap();
        assert_eq!(user_version(conn), 0);

        // 直接 SQL 插入旧形状行(绕过 store,模拟历史数据)。
        conn.execute(
            "INSERT INTO items(type,title,data,search_text,created_at,updated_at)
             VALUES ('password','t','{\"type\":\"password\",\"username\":\"u\",\"password\":\"s3cret\",\"url\":\"x\",\"totp_secret\":\"T\",\"notes\":\"n\"}','old',1,1)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO items(type,title,data,search_text,created_at,updated_at)
             VALUES ('note','n','{\"type\":\"note\",\"format\":\"text\",\"content\":\"body\"}','old',1,1)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO items(type,title,data,search_text,created_at,updated_at)
             VALUES ('card','c','{\"type\":\"card\",\"holder\":\"h\",\"number\":\"4111\",\"expiry\":\"01/30\",\"cvv\":\"9\",\"bank\":\"b\",\"notes\":\"cn\"}','old',1,1)",
            [],
        ).unwrap();
        // 损坏行
        conn.execute(
            "INSERT INTO items(type,title,data,search_text,created_at,updated_at)
             VALUES ('password','broken','not json','old',1,1)",
            [],
        ).unwrap();

        // 迁移
        db.migrate_data().unwrap();

        // 水位升至 1
        assert_eq!(user_version(conn), 1);

        let pw_id: i64 = conn
            .query_row("SELECT id FROM items WHERE title='t'", [], |r| r.get(0))
            .unwrap();
        let (ty, data, st) = read_item_row(conn, pw_id);
        assert_eq!(ty, "password");
        // data 现在是 Vec<Field> JSON 数组
        let fields: Vec<crate::model::Field> = serde_json::from_str(&data).unwrap();
        assert_eq!(fields.len(), 5);
        // search_text 含 username/url/notes,不含 password(Secret)/totp(Totp)
        assert!(st.contains("u"));
        assert!(st.contains("x"));
        assert!(st.contains("n"));
        assert!(!st.contains("s3cret"), "Secret 不应进入 search_text");

        let note_id: i64 = conn
            .query_row("SELECT id FROM items WHERE title='n'", [], |r| r.get(0))
            .unwrap();
        let (_, nd, nst) = read_item_row(conn, note_id);
        let nf: Vec<crate::model::Field> = serde_json::from_str(&nd).unwrap();
        assert_eq!(nf.len(), 2);
        assert!(nst.contains("body"));

        let card_id: i64 = conn
            .query_row("SELECT id FROM items WHERE title='c'", [], |r| r.get(0))
            .unwrap();
        let (_, cd, cst) = read_item_row(conn, card_id);
        let cf: Vec<crate::model::Field> = serde_json::from_str(&cd).unwrap();
        assert_eq!(cf.len(), 6);
        // number 是 Secret,不入 search_text
        assert!(cst.contains("h"));
        assert!(!cst.contains("4111"));

        // 损坏行:迁移完成(version 1),其 data 未被改写(仍为 'not json')。
        let broken_id: i64 = conn
            .query_row("SELECT id FROM items WHERE title='broken'", [], |r| r.get(0))
            .unwrap();
        let (bt, bd, bst) = read_item_row(conn, broken_id);
        assert_eq!(bt, "password");
        assert_eq!(bd, "not json", "损坏行 data 应保持不变");
        assert_eq!(bst, "old", "损坏行 search_text 应保持不变");
    }

    #[test]
    fn migrate_data_is_idempotent() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        conn.execute_batch("PRAGMA user_version = 0").unwrap();
        conn.execute(
            "INSERT INTO items(type,title,data,search_text,created_at,updated_at)
             VALUES ('password','t','{\"type\":\"password\",\"username\":\"u\",\"password\":\"s\",\"url\":\"\",\"totp_secret\":\"\",\"notes\":\"n\"}','old',1,1)",
            [],
        ).unwrap();

        db.migrate_data().unwrap();
        assert_eq!(user_version(conn), 1);

        // 捕获迁移后状态
        let pw_id: i64 = conn
            .query_row("SELECT id FROM items WHERE title='t'", [], |r| r.get(0))
            .unwrap();
        let (_, data_before, st_before) = read_item_row(conn, pw_id);

        // 再次调用:user_version >= 1 → 立即返回 Ok,数据不变。
        db.migrate_data().unwrap();
        assert_eq!(user_version(conn), 1);
        let (_, data_after, st_after) = read_item_row(conn, pw_id);
        assert_eq!(data_before, data_after);
        assert_eq!(st_before, st_after);
    }

    #[test]
    fn migrate_data_handles_mixed_new_and_legacy_shapes() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        conn.execute_batch("PRAGMA user_version = 0").unwrap();

        // 已是新形状(Vec<Field>)的行:migrate_data 应识别并保留(可重新规范化 search_text)。
        let new_shape = serde_json::to_string(&vec![
            crate::model::Field {
                name: "ssid".into(),
                value: "HomeNet".into(),
                kind: crate::model::FieldKind::Text,
                protected: false,
            },
            crate::model::Field {
                name: "password".into(),
                value: "wifipass".into(),
                kind: crate::model::FieldKind::Secret,
                protected: true,
            },
        ])
        .unwrap();
        conn.execute(
            "INSERT INTO items(type,title,data,search_text,created_at,updated_at)
             VALUES ('wifi','w',?1,'old',1,1)",
            rusqlite::params![new_shape],
        )
        .unwrap();

        db.migrate_data().unwrap();
        assert_eq!(user_version(conn), 1);

        let w_id: i64 = conn
            .query_row("SELECT id FROM items WHERE title='w'", [], |r| r.get(0))
            .unwrap();
        let (ty, data, st) = read_item_row(conn, w_id);
        assert_eq!(ty, "wifi");
        let fields: Vec<crate::model::Field> = serde_json::from_str(&data).unwrap();
        assert_eq!(fields.len(), 2);
        // search_text 含 ssid(Text),不含 Secret
        assert!(st.contains("HomeNet"));
        assert!(!st.contains("wifipass"));
    }

    #[test]
    fn migrate_data_noop_on_fresh_empty_db() {
        let db = Database::open_in_memory().unwrap();
        // 空库也能迁移:user_version 0 → 1,无 items 不报错。
        db.migrate_data().unwrap();
        assert_eq!(user_version(db.conn()), 1);
    }

    #[test]
    fn templates_table_exists_after_migrate() {
        let db = Database::open_in_memory().unwrap();
        let names: Vec<String> = db
            .conn()
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='templates'")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert_eq!(names, vec!["templates".to_string()]);
    }
}
