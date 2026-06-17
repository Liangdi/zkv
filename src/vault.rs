//! `.zkv` 加密容器:文件头、解锁/保存/锁定。对应 PRD §3、§4。
//!
//! 文件格式(小端,见 PRD §4,头长 58 字节):
//! ```text
//! [4 Magic "ZKV1"][1 ver][1 flags][4 m_kib][4 t_cost][4 p_cost][16 salt][24 nonce][N ciphertext]
//! ```
//!
//! 对外接口:
//! - [`VaultHeader`] / [`HEADER_LEN`] / [`MAGIC`]
//! - [`create`] / [`unlock`] / [`save`]:使用默认 KDF 参数(64MiB/3/4)的生产入口。
//! - [`create_with_params`] / [`unlock_with_params`] / [`save_with_params`]:可注入 KDF 参数,
//!   **测试**用 `KdfParams{4096,1,1}` 加速(见模块测试)。
//!
//! ## 测试 KDF 加速策略
//! 默认 `KdfParams::default()`(64MiB/3/4)每次派生约几百 ms,多个集成测试会很慢。
//! 因此 `create`/`unlock`/`save` 均拆出 `_with_params` 版本,核心逻辑只实现一次;
//! 测试统一用小参数 `KdfParams{4096,1,1}` 派生(与 crypto.rs 单测一致)。
//! `VaultHeader` 里已保存 params,故 `unlock` 只需调用方传一次小 params 即可正确派生。
//!
//! 原子写:写 `<path>.tmp`(0600)→ `fs::rename` → 目标 0600。
//!
//! 规则(L2):仅依赖 [`crate::error`]/[`crate::crypto`]/[`crate::db`],不引用 store/search/app/ui。

use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::{self, Encrypted, KdfParams, MasterKey};
use crate::db::Database;
use crate::error::{Error, Result};

/// 文件魔数 `ZKV1`。
pub const MAGIC: [u8; 4] = *b"ZKV1";
/// 固定头长度:4+1+1+4+4+4+16+24 = 58 字节。
pub const HEADER_LEN: usize = 58;
/// 当前容器版本。
pub const VERSION: u8 = 1;

/// `.zkv` 文件头。小端序,布局见 PRD §4。
#[derive(Debug, Clone)]
pub struct VaultHeader {
    /// 版本(当前固定 1)。
    pub version: u8,
    /// 保留标志位(当前置 0)。
    pub flags: u8,
    /// Argon2id 参数。
    pub kdf: KdfParams,
    /// 16 字节 salt。
    pub salt: [u8; 16],
    /// 本次加密的 24 字节 XChaCha20 nonce。
    pub nonce: [u8; 24],
}

impl VaultHeader {
    /// 序列化为 58 字节(小端)。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN);
        out.extend_from_slice(&MAGIC);
        out.push(self.version);
        out.push(self.flags);
        out.extend_from_slice(&self.kdf.m_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf.t_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf.p_cost.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        debug_assert_eq!(out.len(), HEADER_LEN);
        out
    }

    /// 从字节解析头(至少 58 字节)。校验 Magic/Version,不符返回 [`Error::CorruptFile`]。
    pub fn parse(bytes: &[u8]) -> Result<VaultHeader> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::CorruptFile(format!(
                "header too short: {} < {HEADER_LEN}",
                bytes.len()
            )));
        }
        if &bytes[0..4] != MAGIC {
            return Err(Error::CorruptFile("bad magic".to_string()));
        }
        let version = bytes[4];
        if version != VERSION {
            return Err(Error::CorruptFile(format!(
                "unsupported version: {version}"
            )));
        }
        let flags = bytes[5];
        let m_kib = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let t_cost = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]);
        let p_cost = u32::from_le_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[18..34]);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&bytes[34..58]);

        Ok(VaultHeader {
            version,
            flags,
            kdf: KdfParams {
                m_kib,
                t_cost,
                p_cost,
            },
            salt,
            nonce,
        })
    }
}

/// 创建一个新的空 `.zkv` 库(默认 KDF 参数)。
pub fn create(path: &Path, passphrase: &str) -> Result<()> {
    create_with_params(path, passphrase, &KdfParams::default())
}

/// 创建一个新的空 `.zkv` 库,使用指定 KDF 参数(测试用小参数加速)。
pub fn create_with_params(path: &Path, passphrase: &str, kdf: &KdfParams) -> Result<()> {
    let db = Database::open_in_memory()?;
    let plaintext = db.dump_bytes()?;
    encrypt_and_write(path, passphrase, kdf, crypto::gen_salt(), plaintext)
}

/// 解锁现有 `.zkv` 库(默认 KDF 参数)。
pub fn unlock(path: &Path, passphrase: &str) -> Result<Database> {
    let file = fs::read(path)?;
    let header = VaultHeader::parse(&file)?;
    let key = crypto::derive_key(passphrase.as_bytes(), &header.salt, &header.kdf)?;
    let enc = Encrypted {
        nonce: header.nonce,
        ciphertext: file[HEADER_LEN..].to_vec(),
    };
    let plaintext = crypto::decrypt(&key, &enc)?;
    Database::from_bytes(&plaintext)
}

/// 解锁现有 `.zkv` 库,使用指定 KDF 参数。
///
/// 实际上 `unlock` 总是读取文件头中的 KDF 参数来派生,故此入口仅用于显式语义/测试对照,
/// 其实现等价于 [`unlock`](同名函数)(params 来自文件头)。
pub fn unlock_with_params(path: &Path, passphrase: &str, _kdf: &KdfParams) -> Result<Database> {
    // 文件头自带 kdf,忽略传入参数,保持与 unlock 一致。
    unlock(path, passphrase)
}

/// 保存(覆盖)`.zkv` 库(默认 KDF 参数)。
pub fn save(path: &Path, passphrase: &str, db: &Database) -> Result<()> {
    save_with_params(path, passphrase, db, &KdfParams::default())
}

/// 保存(覆盖)`.zkv` 库,使用指定 KDF 参数。
///
/// **salt 复用现有文件头中的 salt**(保持同一派生密钥);每次保存生成**新 nonce**。
/// 若文件不存在则等价于新建(用传入 kdf + 新随机 salt)。
pub fn save_with_params(
    path: &Path,
    passphrase: &str,
    db: &Database,
    kdf: &KdfParams,
) -> Result<()> {
    let plaintext = db.dump_bytes()?;

    // 复用现有文件的 salt(若有),保持同一派生密钥。
    let salt = match fs::read(path) {
        Ok(file) => match VaultHeader::parse(&file) {
            Ok(h) => h.salt,
            Err(_) => crypto::gen_salt(),
        },
        Err(_) => crypto::gen_salt(),
    };

    encrypt_and_write(path, passphrase, kdf, salt, plaintext)
}

/// 内部:派生密钥 → 加密(新 nonce 由 encrypt 生成,但我们需要它进文件头,故手写一遍)→ 原子写。
fn encrypt_and_write(
    path: &Path,
    passphrase: &str,
    kdf: &KdfParams,
    salt: [u8; 16],
    plaintext: Vec<u8>,
) -> Result<()> {
    let key: MasterKey = crypto::derive_key(passphrase.as_bytes(), &salt, kdf)?;
    let enc = crypto::encrypt(&key, &plaintext)?;
    let header = VaultHeader {
        version: VERSION,
        flags: 0,
        kdf: *kdf,
        salt,
        nonce: enc.nonce,
    };
    let mut out = header.to_bytes();
    out.extend_from_slice(&enc.ciphertext);
    atomic_write(path, &out)
}

/// 原子写:写到 `<path>.tmp`(0600)→ `fs::rename` → 目标 0600。失败删除临时文件。
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    // 写临时文件
    {
        let res = (|| -> Result<()> {
            let mut f = open_secure(&tmp)?;
            use std::io::Write;
            f.write_all(data)?;
            f.sync_all()?;
            Ok(())
        })();
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
            return res;
        }
    }
    set_mode_0600(&tmp);

    // rename
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(Error::Io(e));
    }
    // 确保最终文件也是 0600(rename 保留临时文件权限,已设;再兜底)。
    set_mode_0600(path);
    Ok(())
}

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

#[cfg(unix)]
fn set_mode_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_mode_0600(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    /// 测试用小 KDF 参数(与 crypto.rs 单测一致),加速派生。
    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_kib: 4_096,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// 唯一临时文件路径(每个测试独立)。
    fn tmp_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("zkv_test_{tag}_{}_{}", std::process::id(), n));
        p
    }

    fn cleanup(p: &std::path::Path) {
        let _ = std::fs::remove_file(p);
        let mut t = p.as_os_str().to_owned();
        t.push(".tmp");
        let _ = std::fs::remove_file(std::path::PathBuf::from(t));
    }

    #[test]
    fn header_roundtrip_and_constants() {
        let kdf = fast_kdf();
        let h = VaultHeader {
            version: VERSION,
            flags: 0,
            kdf,
            salt: [0xA0u8; 16],
            nonce: [0xB1u8; 24],
        };
        let b = h.to_bytes();
        assert_eq!(b.len(), HEADER_LEN);
        assert_eq!(&b[0..4], &MAGIC);
        let h2 = VaultHeader::parse(&b).unwrap();
        assert_eq!(h2.version, VERSION);
        assert_eq!(h2.flags, 0);
        assert_eq!(h2.kdf, kdf);
        assert_eq!(h2.salt, [0xA0u8; 16]);
        assert_eq!(h2.nonce, [0xB1u8; 24]);
    }

    #[test]
    fn header_parse_rejects_bad_magic_and_short() {
        // 短
        assert!(matches!(
            VaultHeader::parse(&[0u8; 10]),
            Err(Error::CorruptFile(_))
        ));
        // 坏魔数
        let mut bad = vec![0u8; HEADER_LEN];
        bad[0..4].copy_from_slice(b"XXXX");
        assert!(matches!(
            VaultHeader::parse(&bad),
            Err(Error::CorruptFile(_))
        ));
    }

    #[test]
    fn create_unlock_roundtrip() {
        let p = tmp_path("cu");
        cleanup(&p);
        let kdf = fast_kdf();
        create_with_params(&p, "hunter2", &kdf).expect("create");
        let db = unlock(&p, "hunter2").expect("unlock");
        // 默认库应能查询 items 表(空)
        let cnt: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get::<_, i64>(0))
            .unwrap();
        assert_eq!(cnt, 0);
        cleanup(&p);
    }

    #[test]
    fn save_then_unlock_preserves_changes() {
        let p = tmp_path("save");
        cleanup(&p);
        let kdf = fast_kdf();
        create_with_params(&p, "pw", &kdf).unwrap();

        // 解锁 → 改 → 保存 → 再解锁
        {
            let db = unlock(&p, "pw").unwrap();
            db.conn()
                .execute(
                    "INSERT INTO items(type,title,data,search_text,created_at,updated_at)
                     VALUES ('note','T','{}','s',1,1)",
                    [],
                )
                .unwrap();
            save_with_params(&p, "pw", &db, &kdf).unwrap();
        }
        let db2 = unlock(&p, "pw").unwrap();
        let cnt: i64 = db2
            .conn()
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get::<_, i64>(0))
            .unwrap();
        assert_eq!(cnt, 1);
        cleanup(&p);
    }

    #[test]
    fn wrong_passphrase_yields_bad_passphrase() {
        let p = tmp_path("wrong");
        cleanup(&p);
        let kdf = fast_kdf();
        create_with_params(&p, "correct", &kdf).unwrap();
        let res = unlock(&p, "incorrect");
        assert!(
            matches!(res, Err(Error::BadPassphrase)),
            "expected BadPassphrase, got {:?}",
            res
        );
        cleanup(&p);
    }

    #[test]
    fn corrupted_magic_yields_corrupt_file() {
        let p = tmp_path("corrupt");
        cleanup(&p);
        let kdf = fast_kdf();
        create_with_params(&p, "pw", &kdf).unwrap();

        // 篡改魔数
        let mut data = std::fs::read(&p).unwrap();
        data[0] = 0x00;
        std::fs::write(&p, &data).unwrap();

        let res = unlock(&p, "pw");
        assert!(matches!(res, Err(Error::CorruptFile(_))));
        cleanup(&p);
    }

    #[test]
    fn save_each_time_new_nonce() {
        // 两次保存产生不同的 nonce(头中的 nonce 字段应不同)。
        let p = tmp_path("nonce");
        cleanup(&p);
        let kdf = fast_kdf();
        create_with_params(&p, "pw", &kdf).unwrap();
        let f1 = std::fs::read(&p).unwrap();
        let h1 = VaultHeader::parse(&f1).unwrap();

        {
            let db = unlock(&p, "pw").unwrap();
            save_with_params(&p, "pw", &db, &kdf).unwrap();
        }
        let f2 = std::fs::read(&p).unwrap();
        let h2 = VaultHeader::parse(&f2).unwrap();

        assert_ne!(h1.nonce, h2.nonce, "每次保存应生成新 nonce");
        // salt 保持不变
        assert_eq!(h1.salt, h2.salt);
        cleanup(&p);
    }
}
