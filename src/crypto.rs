//! 加密原语:Argon2id 派生 + XChaCha20-Poly1305(L1)。
//!
//! 对外接口:
//! - [`KdfParams`]:Argon2id 参数(m/t/p),默认值遵循 PRD §3.1。
//! - [`MasterKey`]:32B 主密钥,以 `secrecy::Secret` 包裹,drop 时 zeroize。
//! - [`derive_key`]:从口令 + salt 派生主密钥(Argon2id, 32B 输出)。
//! - [`Encrypted`]:加密产物(nonce + ciphertext,ciphertext 末尾含 16B Poly1305 tag)。
//! - [`encrypt`] / [`decrypt`]:每次加密生成新随机 nonce;AEAD 校验失败 ⇒ [`Error::BadPassphrase`]。
//! - [`gen_salt`] / [`gen_nonce`]:系统 CSPRNG(`getrandom` 0.4)生成随机盐/nonce。
//!
//! 规则:L1 模块仅依赖 [`crate::error`] 与外部 crate,不引用 `db`/`vault` 等上层。

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit},
};
// 注:secrecy 0.10 把旧的 `Secret<T>` 重命名为 `SecretBox<T>`(此处实际安装 0.10.3)。
// 为遵循契约意图(以 secrecy 包裹 + drop 时 zeroize),此处使用 `SecretBox<[u8;32]>`。
use secrecy::{ExposeSecret, SecretBox};
use zeroize::ZeroizeOnDrop;

use crate::error::{Error, Result};

/// Argon2id 参数。默认值遵循 PRD §3.1:m = 64 MiB(65536 KiB),t = 3,p = 4。
///
/// derive `Serialize`/`Deserialize`:供 agent 守护进程经本地 socket 传输已派生密钥时,
/// 把 KDF 参数一并发给客户端(写入回盘的文件头需要它)。不涉及口令/密钥序列化。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// 内存成本,单位 KiB(PRD §3.1 默认 65536 = 64 MiB)。
    pub m_kib: u32,
    /// 时间成本(迭代次数,PRD §3.1 默认 3)。
    pub t_cost: u32,
    /// 并行度(PRD §3.1 默认 4)。
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_kib: 65_536, // 64 MiB
            t_cost: 3,
            p_cost: 4,
        }
    }
}

/// 主密钥:32 字节,以 `secrecy::SecretBox` 包裹。
///
/// derive `ZeroizeOnDrop`:当 `MasterKey` 被丢弃时,内部的 `[u8;32]` 会被 zeroize 清零,
/// 防止密钥残留在内存中(配合 `SecretBox` 自身的零化策略)。
#[derive(ZeroizeOnDrop)]
pub struct MasterKey(pub(crate) SecretBox<[u8; 32]>);

impl MasterKey {
    /// 以 32 字节数组引用形式暴露密钥(供 AEAD 初始化)。
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    /// 从 32 字节数组重建主密钥(同 crate 内使用)。
    ///
    /// 供 agent 客户端:从本地 socket 收到密钥字节后构造 [`MasterKey`],
    /// 跳过 Argon2id 派生直接解库。调用方应保证传入字节的来源可信(同 uid 本地 socket)。
    ///
    /// 注:仅 `agent`(Unix)调用;非 Unix agent 为 no-op,故该函数在非 Unix 上是 dead code。
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(crate) fn from_bytes(arr: [u8; 32]) -> Self {
        MasterKey(SecretBox::new(Box::new(arr)))
    }
}

/// 加密产物。
///
/// `ciphertext` 末尾包含 16 字节 Poly1305 认证 tag(XChaCha20-Poly1305 AEAD 标准布局)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encrypted {
    /// XChaCha20 随机 nonce,24 字节。
    pub nonce: [u8; 24],
    /// 密文(末尾含 16B Poly1305 tag)。
    pub ciphertext: Vec<u8>,
}

/// 用 Argon2id 从口令 + 16 字节 salt 派生 32 字节主密钥。
///
/// 参数遵循 PRD §3.1。失败归为 [`Error::Crypto`]。
pub fn derive_key(passphrase: &[u8], salt: &[u8; 16], params: &KdfParams) -> Result<MasterKey> {
    let argon_params = Params::new(params.m_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| Error::Crypto(format!("invalid argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| Error::Crypto(format!("argon2 derivation failed: {e}")))?;

    Ok(MasterKey(SecretBox::new(Box::new(out))))
}

/// 用主密钥加密明文。每次调用生成**新的随机 24 字节 nonce**。
///
/// 返回的 [`Encrypted`] 中 `ciphertext` 末尾含 16B Poly1305 tag。
pub fn encrypt(key: &MasterKey, plaintext: &[u8]) -> Result<Encrypted> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = gen_nonce();
    let nonce_obj = chacha20poly1305::XNonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_obj, plaintext)
        .map_err(|e| Error::Crypto(format!("encryption failed: {e}")))?;
    Ok(Encrypted { nonce, ciphertext })
}

/// 用主密钥解密 [`Encrypted`]。
///
/// AEAD(Poly1305)校验失败 ⇒ [`Error::BadPassphrase`](口令错误 / 数据被篡改)。
pub fn decrypt(key: &MasterKey, enc: &Encrypted) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce_obj = chacha20poly1305::XNonce::from_slice(&enc.nonce);
    cipher
        .decrypt(nonce_obj, enc.ciphertext.as_ref())
        .map_err(|_| Error::BadPassphrase)
}

/// 生成 16 字节随机 salt(系统 CSPRNG)。
pub fn gen_salt() -> [u8; 16] {
    let mut buf = [0u8; 16];
    // getrandom 0.4 API:`fill(&mut buf) -> Result<(), Error>`。
    // 此处仅在系统熵源故障时失败,归为 Crypto 错误;由于无合理恢复路径,直接 expect。
    getrandom::fill(&mut buf).expect("getrandom::fill failed for salt generation");
    buf
}

/// 生成 24 字节随机 nonce(系统 CSPRNG),供 XChaCha20-Poly1305 使用。
pub fn gen_nonce() -> [u8; 24] {
    let mut buf = [0u8; 24];
    getrandom::fill(&mut buf).expect("getrandom::fill failed for nonce generation");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_params_default_matches_prd() {
        let p = KdfParams::default();
        assert_eq!(p.m_kib, 65_536); // 64 MiB
        assert_eq!(p.t_cost, 3);
        assert_eq!(p.p_cost, 4);
    }

    #[test]
    fn derive_key_is_deterministic_for_same_inputs() {
        let params = KdfParams {
            m_kib: 4_096, // 测试用小参数加速
            t_cost: 1,
            p_cost: 1,
        };
        let salt = gen_salt();
        let k1 = derive_key(b"correct horse battery staple", &salt, &params).unwrap();
        let k2 = derive_key(b"correct horse battery staple", &salt, &params).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());

        // 不同口令应产生不同密钥
        let k3 = derive_key(b"different passphrase", &salt, &params).unwrap();
        assert_ne!(k1.as_bytes(), k3.as_bytes());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let params = KdfParams {
            m_kib: 4_096,
            t_cost: 1,
            p_cost: 1,
        };
        let salt = gen_salt();
        let key = derive_key(b"round-trip-passphrase", &salt, &params).unwrap();

        let plaintext = b"hello zkv \x00 binary \xff data";
        let enc = encrypt(&key, plaintext).unwrap();
        let dec = decrypt(&key, &enc).unwrap();
        assert_eq!(dec, plaintext);

        // 密文长度 = 明文 + 16B tag
        assert_eq!(enc.ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let params = KdfParams {
            m_kib: 4_096,
            t_cost: 1,
            p_cost: 1,
        };
        let salt = gen_salt();
        let good = derive_key(b"the right passphrase", &salt, &params).unwrap();
        let bad = derive_key(b"the wrong passphrase", &salt, &params).unwrap();

        let enc = encrypt(&good, b"secret payload").unwrap();
        let res = decrypt(&bad, &enc);
        assert!(matches!(res, Err(Error::BadPassphrase)));
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let params = KdfParams {
            m_kib: 4_096,
            t_cost: 1,
            p_cost: 1,
        };
        let salt = gen_salt();
        let key = derive_key(b"tamper-test-passphrase", &salt, &params).unwrap();

        let mut enc = encrypt(&key, b"tamper me").unwrap();
        // 翻转一个密文字节(破坏 Poly1305 tag 或密文)
        enc.ciphertext[0] ^= 0xff;
        let res = decrypt(&key, &enc);
        assert!(matches!(res, Err(Error::BadPassphrase)));
    }

    #[test]
    fn decrypt_tampered_nonce_fails() {
        let params = KdfParams {
            m_kib: 4_096,
            t_cost: 1,
            p_cost: 1,
        };
        let salt = gen_salt();
        let key = derive_key(b"nonce-tamper", &salt, &params).unwrap();

        let mut enc = encrypt(&key, b"payload").unwrap();
        enc.nonce[0] ^= 0x01;
        let res = decrypt(&key, &enc);
        assert!(matches!(res, Err(Error::BadPassphrase)));
    }

    #[test]
    fn gen_salt_and_nonce_are_random() {
        let s1 = gen_salt();
        let s2 = gen_salt();
        assert_ne!(s1, s2);

        let n1 = gen_nonce();
        let n2 = gen_nonce();
        assert_ne!(n1, n2);
    }
}
