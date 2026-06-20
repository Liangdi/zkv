//! TOTP 验证码生成(RFC 6238)。对应 PRD §安全特性 —— 为 password 条目的 `totp_secret`
//! 实时生成 6 位验证码,供 CLI `otp` 命令与 `cp -f otp` 复用。
//!
//! 算法:HMAC-SHA1,30 秒步长,6 位数字,dynamic truncation(与 Google Authenticator 兼容)。
//!
//! 对外接口:
//! - [`totp_at`]:给定 base32 secret + unix 秒,返回 6 位数字串。
//! - [`current_totp`]:用当前系统时间调 [`totp_at`]。
//!
//! ## base32 secret 处理
//! 用户从二维码复制的 secret 通常是 base32(大写、可能含空格/小写)。统一规范化:
//! 去空白 → 转大写 → 按 RFC 4648 base32 解码。非法字符/长度 → [`Error::Other`]。
//!
//! 分层(L1):仅依赖 `crate::error` 与外部 crate,不引用 db/vault/app/ui/cli。

use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::{Error, Result};

/// HMAC-SHA1 别名。
type HmacSha1 = Hmac<Sha1>;

/// 6 位数字长度(RFC 6238 默认,与主流 authenticator 一致)。
const DIGITS: usize = 6;
/// 时间步长(秒)。
const STEP: u64 = 30;

/// 给定 base32 secret 与 unix 秒,返回 6 位 TOTP 验证码字符串。
///
/// 内部:规范化 → base32 解码 → [`totp_raw`]。
pub fn totp_at(secret_b32: &str, unix_secs: u64) -> Result<String> {
    let key = decode_base32(secret_b32)?;
    Ok(totp_raw(&key, unix_secs))
}

/// 用当前系统时间生成 TOTP 验证码。
pub fn current_totp(secret_b32: &str) -> Result<String> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Error::Other(format!("system clock before epoch: {e}")))?
        .as_secs();
    totp_at(secret_b32, secs)
}

/// TOTP 计算内核:接收**原始密钥字节**与 unix 秒,返回 6 位数字串。
///
/// 把 base32/时间细节剥离出去,便于用 RFC 6238 附录 B 的官方测试向量
/// (密钥为 ASCII 字节,直接喂本函数)精确验证 HMAC-SHA1 + 截断实现。
///
/// 步骤:counter = secs / 30 → HOTP(HMAC-SHA1, counter) → 6 位。
fn totp_raw(key: &[u8], unix_secs: u64) -> String {
    let counter = unix_secs / STEP;
    format_digits(hotp(key, counter), DIGITS)
}

/// HOTP(RFC 4226):HMAC-SHA1(key, counter 的 8 字节大端) → dynamic truncation → 31 位整数。
fn hotp(key: &[u8], counter: u64) -> u32 {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    // Dynamic truncation:取最后一个字节的低 4 位作为偏移,取偏移处的 4 字节(大端),
    // 屏蔽最高位(与 0x7fffffff),得到 31 位正整数。
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bytes = &digest[offset..offset + 4];
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & 0x7fff_ffff
}

/// 把整数格式化为 `n` 位十进制串(前导补零)。
fn format_digits(value: u32, n: usize) -> String {
    let modulus = 10u32.pow(n as u32);
    format!("{:0>width$}", value % modulus, width = n)
}

/// 规范化并解码 base32 secret。
///
/// 处理:去所有空白 → 转大写 → 解码。空串/非法字符/非法长度 → [`Error::Other`]。
///
/// `data_encoding::BASE32`(RFC 4648)要求长度为 8 的倍数且无填充缺失;
/// 这里手动补 `=` 到 8 的倍数后解码,允许用户省略填充。
fn decode_base32(secret: &str) -> Result<Vec<u8>> {
    let cleaned: String = secret.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return Err(Error::Other("no totp secret".into()));
    }
    let upper = cleaned.to_uppercase();
    // 补齐到 8 字符倍数的 `=` 填充(base32 分组大小)。
    let pad = (8 - (upper.len() % 8)) % 8;
    let padded = format!("{upper}{:=<pad$}", "");

    BASE32
        .decode(padded.as_bytes())
        .map_err(|e| Error::Other(format!("invalid base32 totp secret: {e}")))
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 附录 B 的 SHA-1 测试向量(密钥为 ASCII 字节 `"12345678901234567890"`),
    /// 8 位模式下的期望值。验证 HMAC-SHA1 + dynamic truncation 实现正确。
    ///
    /// 用一个直接暴露截断位数的内部辅助复用 [`hotp`] 内核:对相同 counter,
    /// 6 位与 8 位仅是 `% 10^digits` 的模数不同。
    fn hotp_digits(key: &[u8], counter: u64, digits: usize) -> String {
        format_digits(hotp(key, counter), digits)
    }

    #[test]
    fn rfc6238_vectors_8_digit() {
        // 注意:RFC 给的 "Time(s)" 是真实 unix 时间,counter = secs / 30。
        // 这里直接用 counter 与时间无关的 hotp 验证纯算法。
        // 但 RFC 附录 B 表是按 T(time) 算的,所以我们用 totp_raw 走完整路径。
        let key = b"12345678901234567890";
        // (unix_secs, expected 8-digit)
        let cases: &[(u64, &str)] = &[
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
        ];
        for &(secs, expected) in cases {
            // totp_raw 固定 6 位;改用参数化内核取 8 位与 RFC 对齐。
            let got = hotp_digits(key, secs / STEP, 8);
            assert_eq!(
                got, expected,
                "RFC 6238 vector mismatch at secs={secs}: got {got}, want {expected}"
            );
        }
    }

    #[test]
    fn rfc6238_via_totp_raw_matches_hotp() {
        // totp_raw 内部 counter = secs/30,与手算一致。
        let key = b"12345678901234567890";
        let secs = 59u64;
        let raw = totp_raw(key, secs);
        // 6 位 = hotp 模 10^6。
        let direct = hotp_digits(key, secs / STEP, 6);
        assert_eq!(raw, direct);
        assert_eq!(raw.len(), 6);
    }

    #[test]
    fn current_and_at_are_consistent() {
        // 固定时间下 totp_at 返回纯 6 位数字。
        let code = totp_at("JBSWY3DPEHPK3PXP", 1_000_000).unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));

        // current_totp 同样应是 6 位数字(实时,不比对具体值)。
        let now = current_totp("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(now.len(), 6);
        assert!(now.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn totp_changes_with_step() {
        // 跨越一个 30 秒步长边界,counter 变化 → 大概率码不同(理论极小概率相同,可接受)。
        let key = b"12345678901234567890";
        let a = totp_raw(key, 0);
        let b = totp_raw(key, 30);
        // counter 都是 0 vs 1;HMAC 不同输入几乎必不同。
        assert_ne!(a, b);
    }

    #[test]
    fn base32_accepts_lowercase_and_spaces() {
        // 小写 + 内嵌空格应等价于规范化大写。
        let a = totp_at("jbswy 3dpeh pk3pxp", 1_000_000).unwrap();
        let b = totp_at("JBSWY3DPEHPK3PXP", 1_000_000).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn base32_invalid_errors() {
        // 非法字符。
        assert!(totp_at("JBSWY3DPEHPK3P!@", 1_000_000).is_err());
        // 长度非法(base32 解码失败,如奇数非零残段)。
        assert!(totp_at("JBSW3DPEHPK3PXP", 1_000_000).is_err());
    }

    #[test]
    fn base32_empty_errors() {
        assert!(matches!(
            totp_at("", 1_000_000),
            Err(Error::Other(msg)) if msg.contains("no totp secret")
        ));
        // 仅空白也算空。
        assert!(totp_at("   ", 1_000_000).is_err());
    }

    #[test]
    fn format_digits_leading_zeros() {
        assert_eq!(format_digits(7, 6), "000007");
        assert_eq!(format_digits(123456, 6), "123456");
        // 超出位数取模。
        assert_eq!(format_digits(1_234_567, 6), "234567");
    }
}
