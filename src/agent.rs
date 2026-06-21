//! agent 守护进程:无感缓存「已派生主密钥」,跳过每条命令的 Argon2id 派生(Unix-only)。
//!
//! ## 模型
//! 一个常驻后台进程,在内存里按「规范化库路径」缓存 `(MasterKey, KdfParams, salt)`,
//! 经本地 Unix socket 供各 CLI 命令取用。**只缓存派生密钥,绝不缓存 Database**:
//! 每条命令仍现读 `.zkv` 文件解密(微秒级 AEAD),只有昂贵的 Argon2id(百毫秒级)被跳过。
//! 因此 `add`/`edit`/`rm` 后缓存照常有效;只有 `passwd` 换 salt 才失效(见 [`forget`])。
//!
//! ## 无感
//! 首次需要口令时,`put_key` 自动 spawn 一个 `zkv agent serve` 子进程(新进程组,不随调用者退出);
//! 闲置超过 `ZKV_LOCK_SECS`(默认 300s,与 TUI 自动锁同一变量;`0` 禁用)后,
//! 看门狗线程清空缓存(密钥 zeroize)并退出整个进程。用户全程零操作。
//!
//! ## 安全
//! - 派生密钥**仅在 agent 进程 RAM**(`Zeroizing` 包裹,drop 清零),**绝不落盘**;
//!   经本地 0600 Unix socket 传给同 uid 客户端(同 ssh-agent 模型)。
//! - 访问控制 = 0700 私有目录(`XDG_RUNTIME_DIR` 优先,tmpfs 已 0700;否则
//!   `temp_dir/zkv-agent-$uid/` 自建 0700)。只有同 uid 能进入目录触达 socket。
//!   (零依赖方案:不引入 `libc` 做 SO_PEERCRED 二次校验;0700 目录已是主防线。)
//! - **fail-closed**:连不上 / 版本不符 / 解密失败 → 客户端静默回退到正常口令流程,绝不卡死或损坏。
//!
//! 非 Unix 平台:本模块为 no-op([`enabled`] 恒 false),所有命令退回每命令输口令。

/// 协议版本(握手校验);客户端/服务端不一致 ⇒ 客户端回退到正常口令流程。
pub const PROTOCOL_VERSION: u32 = 1;

/// `agent status` 返回的运行时快照。
#[derive(Debug, Clone)]
pub struct StatusInfo {
    /// agent 进程 pid。
    pub pid: u32,
    /// socket 路径。
    pub socket: String,
    /// 已缓存(已解锁)的库规范化路径列表。
    pub vaults: Vec<String>,
    /// 距上次活动已空闲的秒数。
    pub idle_secs: u64,
    /// 闲置 TTL(秒);超过即自退出。
    pub ttl_secs: u64,
}

/// 闲置 TTL(秒),复用 `ZKV_LOCK_SECS`:缺失/非法 → 300;`0` → 禁用。
///
/// 与 `ui` 模块的自动锁阈值语义一致,确保「TUI 闲置自动锁」与「agent 闲置过期」
/// 共享同一心智模型与配置。
pub fn ttl_secs() -> u64 {
    const DEFAULT: u64 = 300;
    match std::env::var_os("ZKV_LOCK_SECS").map(|raw| raw.to_string_lossy().parse::<u64>()) {
        Some(Ok(v)) => v,
        _ => DEFAULT,
    }
}

/// agent 是否启用:`cfg(unix)` + 未设 `ZKV_NO_AGENT=1` + [`ttl_secs`] `> 0`。
///
/// 单一 opt-out 闸门:[`crate::cli::Unlocked::unlock`] 与客户端函数据此短路。
pub fn enabled() -> bool {
    cfg!(unix)
        && ttl_secs() > 0
        && std::env::var_os("ZKV_NO_AGENT").is_none_or(|v| v != "1")
}

// ===== Unix 实现 =====

#[cfg(unix)]
mod imp {
    use super::{StatusInfo, PROTOCOL_VERSION};
    use crate::crypto::{KdfParams, MasterKey};
    use crate::error::Result;
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use std::collections::HashMap;
    use std::fs;
    use std::io::{BufRead, BufReader, BufWriter, Write};
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    // ---------- 协议消息(每条一行 JSON,`\n` 分隔)----------

    #[derive(Serialize, Deserialize, Debug)]
    struct Handshake {
        proto: u32,
    }

    #[derive(Serialize, Deserialize, Debug)]
    enum Request {
        Get { path: String },
        Put {
            path: String,
            key: [u8; 32],
            kdf: KdfParams,
            salt: [u8; 16],
        },
        Forget { path: String },
        Status,
        Stop,
        Lock,
    }

    #[derive(Serialize, Deserialize, Debug)]
    enum Response {
        Got {
            key: [u8; 32],
            kdf: KdfParams,
            salt: [u8; 16],
        },
        Miss,
        Ok,
        StatusResp {
            pid: u32,
            socket: String,
            vaults: Vec<String>,
            idle_secs: u64,
            ttl_secs: u64,
        },
        Error(String),
    }

    // ---------- 服务端状态 ----------

    struct CachedEntry {
        key: Zeroizing<[u8; 32]>,
        kdf: KdfParams,
        salt: [u8; 16],
    }

    struct State {
        by_path: HashMap<String, CachedEntry>,
        last_activity: Instant,
        socket: PathBuf,
        ttl: Duration,
    }

    type Shared = Arc<Mutex<State>>;

    /// 运行 agent 服务端循环(由 `zkv agent serve` 调用)。阻塞,直到 idle-TTL 到期或收到 Stop。
    pub fn serve(socket: &Path, ttl: Duration) -> Result<()> {
        // 私有目录(0700)+ 清理残留 socket + 绑定 + 0600。
        if let Some(dir) = socket.parent() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| {
                    crate::error::Error::Other(format!(
                        "agent: cannot create socket dir {}: {e}",
                        dir.display()
                    ))
                })?;
        }
        let _ = fs::remove_file(socket);
        let listener = UnixListener::bind(socket).map_err(|e| {
            crate::error::Error::Other(format!("agent: bind {}: {e}", socket.display()))
        })?;
        let _ = fs::set_permissions(socket, fs::Permissions::from_mode(0o600));

        let state: Shared = Arc::new(Mutex::new(State {
            by_path: HashMap::new(),
            last_activity: Instant::now(),
            socket: socket.to_path_buf(),
            ttl,
        }));

        // 闲置看门狗:TTL 到点清缓存(密钥 zeroize)+ 删 socket + 退出进程。
        let watch_state = Arc::clone(&state);
        thread::spawn(move || idle_watch(watch_state));

        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let st = Arc::clone(&state);
                    thread::spawn(move || {
                        let _ = handle_conn(s, st);
                    });
                }
                // 单连接 accept 失败不致命,继续。
                Err(_) => continue,
            }
        }
        Ok(())
    }

    fn idle_watch(state: Shared) {
        loop {
            thread::sleep(Duration::from_secs(1));
            let (idle, ttl, sock) = {
                let s = state.lock().unwrap();
                (s.last_activity.elapsed(), s.ttl, s.socket.clone())
            };
            if idle >= ttl {
                // 先清空缓存(Zeroizing drop 清零密钥)再退出,确保密钥不残留。
                state.lock().unwrap().by_path.clear();
                let _ = fs::remove_file(&sock);
                std::process::exit(0);
            }
        }
    }

    fn handle_conn(stream: UnixStream, state: Shared) -> Result<()> {
        // 防止恶意/卡死客户端挂死连接。
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        // std 为 &UnixStream 同时实现 Read/Write,故 reader/writer 可共享同一个引用。
        let mut reader = BufReader::new(&stream);
        let mut writer = BufWriter::new(&stream);

        // 1. 握手。
        let hs: Handshake = read_json(&mut reader)?;
        if hs.proto != PROTOCOL_VERSION {
            write_msg(&mut writer, &Response::Error("protocol mismatch".into()))?;
            return Ok(());
        }

        // 2. 请求。
        let req: Request = read_json(&mut reader)?;

        let resp = {
            let mut s = state.lock().unwrap();
            s.last_activity = Instant::now();
            match req {
                Request::Get { path } => match s.by_path.get(&path) {
                    Some(e) => Response::Got {
                        key: *e.key,
                        kdf: e.kdf,
                        salt: e.salt,
                    },
                    None => Response::Miss,
                },
                Request::Put {
                    path,
                    key,
                    kdf,
                    salt,
                } => {
                    s.by_path.insert(
                        path,
                        CachedEntry {
                            key: Zeroizing::new(key),
                            kdf,
                            salt,
                        },
                    );
                    Response::Ok
                }
                Request::Forget { path } => {
                    s.by_path.remove(&path);
                    Response::Ok
                }
                Request::Status => {
                    let pid = std::process::id();
                    let socket = s.socket.to_string_lossy().into_owned();
                    let vaults = s.by_path.keys().cloned().collect();
                    let idle_secs = s.last_activity.elapsed().as_secs();
                    let ttl_secs = s.ttl.as_secs();
                    Response::StatusResp {
                        pid,
                        socket,
                        vaults,
                        idle_secs,
                        ttl_secs,
                    }
                }
                Request::Lock => {
                    s.by_path.clear();
                    Response::Ok
                }
                Request::Stop => {
                    // 先回 Ok、清缓存、删 socket,再退出整个进程(diverges)。
                    let sock = s.socket.clone();
                    s.by_path.clear();
                    drop(s);
                    let _ = write_msg(&mut writer, &Response::Ok);
                    let _ = writer.flush();
                    let _ = fs::remove_file(&sock);
                    std::process::exit(0);
                }
            }
        };
        write_msg(&mut writer, &resp)?;
        writer.flush()?;
        Ok(())
    }

    // ---------- 客户端 ----------

    /// 尝试从 agent 取该库的缓存密钥。None = 无 agent / Miss / 任何错误(fail-closed)。
    pub fn try_get_key(path: &Path) -> Option<(MasterKey, KdfParams, [u8; 16])> {
        if !super::enabled() {
            return None;
        }
        match request(&Request::Get {
            path: canonical(path),
        })? {
            Response::Got { key, kdf, salt } => Some((MasterKey::from_bytes(key), kdf, salt)),
            _ => None,
        }
    }

    /// 把派生密钥种进 agent(best-effort;失败静默)。autostart 在 connect() 内完成。
    pub fn put_key(path: &Path, key: &MasterKey, kdf: &KdfParams, salt: [u8; 16]) {
        if !super::enabled() {
            return;
        }
        let _ = request(&Request::Put {
            path: canonical(path),
            key: *key.as_bytes(),
            kdf: *kdf,
            salt,
        });
    }

    /// 让 agent 丢弃某库的缓存密钥(`passwd` 后调用,防旧口令缓存被复用)。
    pub fn forget(path: &Path) {
        if !super::enabled() {
            return;
        }
        let _ = request(&Request::Forget {
            path: canonical(path),
        });
    }

    /// 清空 agent 所有缓存密钥(等价于 `zkv lock`)。
    pub fn lock_all() {
        let _ = request(&Request::Lock);
    }

    /// 请求 agent 退出(`zkv agent stop`)。
    pub fn stop() {
        let _ = request(&Request::Stop);
    }

    /// 查询 agent 运行状态。None = 无 agent 在运行。
    pub fn status() -> Option<StatusInfo> {
        match request(&Request::Status)? {
            Response::StatusResp {
                pid,
                socket,
                vaults,
                idle_secs,
                ttl_secs,
            } => Some(StatusInfo {
                pid,
                socket,
                vaults,
                idle_secs,
                ttl_secs,
            }),
            _ => None,
        }
    }

    /// 客户端统一收发:connect(+autostart) → 握手 → 发请求 → 收响应。
    fn request(req: &Request) -> Option<Response> {
        let stream = connect()?;
        {
            let mut w = BufWriter::new(&stream);
            write_msg(&mut w, &Handshake { proto: PROTOCOL_VERSION }).ok()?;
            write_msg(&mut w, req).ok()?;
            w.flush().ok()?;
        }
        let mut r = BufReader::new(&stream);
        read_json::<_, Response>(&mut r).ok()
    }

    fn connect() -> Option<UnixStream> {
        let sock = socket_path()?;
        // 1. 直接连已有 agent。
        if let Ok(s) = UnixStream::connect(&sock) {
            return Some(s);
        }
        // 2. 无 → autostart,再重试 ~2s(40 × 50ms)。
        autostart(&sock);
        for _ in 0..40 {
            if let Ok(s) = UnixStream::connect(&sock) {
                return Some(s);
            }
            thread::sleep(Duration::from_millis(50));
        }
        None
    }

    /// 自我 spawn 一个 detached 的 `zkv agent serve` 子进程。
    ///
    /// 新进程组(`process_group(0)`):不随调用者进程组收到 SIGINT,正常退出后由 init 接管。
    /// 两个命令同时 autostart 都 bind,失败方拿 `AddressInUse` 干净退出(空缓存),无需 lockfile。
    fn autostart(sock: &Path) {
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        let mut cmd = Command::new(exe);
        cmd.arg("agent")
            .arg("serve")
            .arg("--socket")
            .arg(sock)
            .arg("--ttl")
            .arg(super::ttl_secs().to_string());
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let _ = cmd.spawn();
    }

    /// socket 路径:`ZKV_AGENT_SOCKET`(测试覆盖)> `XDG_RUNTIME_DIR/zkv-agent.sock`
    /// > `temp_dir/zkv-agent-$uid/zkv-agent.sock`。
    fn socket_path() -> Option<PathBuf> {
        if let Some(p) = std::env::var_os("ZKV_AGENT_SOCKET") {
            return Some(PathBuf::from(p));
        }
        if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
            return Some(PathBuf::from(dir).join("zkv-agent.sock"));
        }
        Some(
            std::env::temp_dir()
                .join(format!("zkv-agent-{}", uid()))
                .join("zkv-agent.sock"),
        )
    }

    /// 当前 uid(直接 FFI `getuid`,免引 `libc` crate)。
    fn uid() -> u32 {
        unsafe extern "C" {
            fn getuid() -> u32;
        }
        unsafe { getuid() }
    }

    /// 规范化库路径作为缓存 key(解析软链/`./`/`..`,同一库的多种写法命中同一缓存项)。
    /// 解析失败(文件不存在等)则回退到原始字面路径。
    fn canonical(path: &Path) -> String {
        fs::canonicalize(path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned())
    }

    fn write_msg<W: Write>(w: &mut W, msg: &impl Serialize) -> Result<()> {
        serde_json::to_writer(&mut *w, msg)?;
        w.write_all(b"\n")?;
        Ok(())
    }

    fn read_json<R: BufRead, T: DeserializeOwned>(r: &mut R) -> Result<T> {
        let mut line = String::new();
        r.read_line(&mut line)?;
        Ok(serde_json::from_str(line.trim())?)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::{Mutex, OnceLock};

        // env 是进程级共享,串行化所有读写 env 的 agent 测试,避免并行竞争。
        fn env_lock() -> &'static Mutex<()> {
            static M: OnceLock<Mutex<()>> = OnceLock::new();
            M.get_or_init(|| Mutex::new(()))
        }

        fn unique_socket() -> PathBuf {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let id = N.fetch_add(1, Ordering::SeqCst);
            std::env::temp_dir().join(format!(
                "zkv-agent-test-{}-{}.sock",
                std::process::id(),
                id
            ))
        }

        /// 绑定临时 socket + 起一个 accept 循环线程(每连接 handle_conn),返回共享 State。
        /// 不跑 idle_watch / Stop(避免 process::exit 杀掉测试进程),仅服务 Get/Put/Forget/Status/Lock。
        fn start_test_server(sock: &Path) -> Shared {
            let _ = fs::remove_file(sock);
            let listener = UnixListener::bind(sock).unwrap();
            let state: Shared = Arc::new(Mutex::new(State {
                by_path: HashMap::new(),
                last_activity: Instant::now(),
                socket: sock.to_path_buf(),
                ttl: Duration::from_secs(600),
            }));
            let st = Arc::clone(&state);
            thread::spawn(move || {
                for s in listener.incoming() {
                    let Ok(s) = s else { continue };
                    let st2 = Arc::clone(&st);
                    thread::spawn(move || {
                        let _ = handle_conn(s, st2);
                    });
                }
            });
            state
        }

        #[test]
        fn serde_roundtrip_all_variants() {
            // Request 各变体往返。
            let kdf = KdfParams {
                m_kib: 1,
                t_cost: 2,
                p_cost: 3,
            };
            let reqs = vec![
                Request::Get {
                    path: "/x.zkv".into(),
                },
                Request::Put {
                    path: "/x.zkv".into(),
                    key: [4u8; 32],
                    kdf,
                    salt: [9u8; 16],
                },
                Request::Forget {
                    path: "/y".into(),
                },
                Request::Status,
                Request::Stop,
                Request::Lock,
            ];
            for r in reqs {
                let s = serde_json::to_string(&r).unwrap();
                let back: Request = serde_json::from_str(&s).unwrap();
                assert_eq!(s, serde_json::to_string(&back).unwrap(), "Request not stable");
            }
            // Response 各变体往返。
            let resps = vec![
                Response::Got {
                    key: [1u8; 32],
                    kdf,
                    salt: [2u8; 16],
                },
                Response::Miss,
                Response::Ok,
                Response::StatusResp {
                    pid: 42,
                    socket: "/tmp/s.sock".into(),
                    vaults: vec!["/a".into(), "/b".into()],
                    idle_secs: 7,
                    ttl_secs: 300,
                },
                Response::Error("boom".into()),
            ];
            for r in resps {
                let s = serde_json::to_string(&r).unwrap();
                let back: Response = serde_json::from_str(&s).unwrap();
                assert_eq!(s, serde_json::to_string(&back).unwrap(), "Response not stable");
            }
        }

        #[test]
        fn canonical_resolves_existing_file() {
            let tmp = std::env::temp_dir().join(format!("zkv-canon-{}.bin", std::process::id()));
            std::fs::write(&tmp, b"x").unwrap();
            // 同一文件经 ./ 前缀规范化后应与直接路径一致。
            let with_dot = tmp.parent().unwrap().join(".").join(tmp.file_name().unwrap());
            assert_eq!(canonical(&tmp), canonical(&with_dot));
            let _ = std::fs::remove_file(&tmp);
        }

        #[test]
        fn ttl_secs_parsing_mirrors_ui() {
            let _g = env_lock().lock().unwrap();
            unsafe {
                std::env::remove_var("ZKV_LOCK_SECS");
                assert_eq!(super::super::ttl_secs(), 300); // 默认
                std::env::set_var("ZKV_LOCK_SECS", "0");
                assert_eq!(super::super::ttl_secs(), 0); // 禁用
                std::env::set_var("ZKV_LOCK_SECS", "120");
                assert_eq!(super::super::ttl_secs(), 120);
                std::env::set_var("ZKV_LOCK_SECS", "garbage");
                assert_eq!(super::super::ttl_secs(), 300); // 非法 → 默认
                std::env::remove_var("ZKV_LOCK_SECS");
            }
        }

        #[test]
        fn enabled_gate() {
            let _g = env_lock().lock().unwrap();
            unsafe {
                std::env::remove_var("ZKV_NO_AGENT");
                std::env::set_var("ZKV_LOCK_SECS", "300");
                assert!(super::super::enabled());
                std::env::set_var("ZKV_NO_AGENT", "1");
                assert!(!super::super::enabled()); // opt-out
                std::env::remove_var("ZKV_NO_AGENT");
                std::env::set_var("ZKV_LOCK_SECS", "0");
                assert!(!super::super::enabled()); // ttl=0 禁用
                std::env::remove_var("ZKV_NO_AGENT");
                std::env::remove_var("ZKV_LOCK_SECS");
            }
        }

        #[test]
        fn client_server_cache_roundtrip() {
            let _g = env_lock().lock().unwrap();
            let sock = unique_socket();
            let _state = start_test_server(&sock);
            // 隔离到测试专用 socket;确保 agent 开启。
            unsafe {
                std::env::set_var("ZKV_AGENT_SOCKET", &sock);
                std::env::remove_var("ZKV_NO_AGENT");
                std::env::set_var("ZKV_LOCK_SECS", "600");
            }
            // 给连接一点时间起来。
            thread::sleep(Duration::from_millis(50));

            let vp = Path::new("/tmp/zkv-agent-no-such-vault.zkv");
            // 未存 → Miss。
            assert!(try_get_key(vp).is_none());
            // 存入 → 命中,字节/kdf/salt 一致。
            let key = MasterKey::from_bytes([7u8; 32]);
            let kdf = KdfParams::default();
            let salt = [1u8; 16];
            put_key(vp, &key, &kdf, salt);
            let (gk, _gkdf, gsalt) = try_get_key(vp).expect("cached after put");
            assert_eq!(gk.as_bytes(), &[7u8; 32]);
            assert_eq!(gsalt, salt);
            // forget → 再取为 None。
            forget(vp);
            assert!(try_get_key(vp).is_none());

            unsafe {
                std::env::remove_var("ZKV_AGENT_SOCKET");
                std::env::remove_var("ZKV_LOCK_SECS");
            }
            let _ = fs::remove_file(&sock);
        }

        #[test]
        fn version_mismatch_returns_error() {
            let sock = unique_socket();
            let _state = start_test_server(&sock);
            thread::sleep(Duration::from_millis(50));

            let s = UnixStream::connect(&sock).unwrap();
            {
                let mut w = BufWriter::new(&s);
                write_msg(&mut w, &Handshake { proto: 999 }).unwrap();
                write_msg(&mut w, &Request::Get { path: "x".into() }).unwrap();
                w.flush().unwrap();
            }
            let mut r = BufReader::new(&s);
            let resp: Response = read_json(&mut r).unwrap();
            assert!(matches!(resp, Response::Error(_)), "expected Error, got {resp:?}");
            let _ = fs::remove_file(&sock);
        }
    }
}

#[cfg(unix)]
pub use imp::{
    forget, lock_all, put_key, serve, status, stop, try_get_key,
};

// ===== 非 Unix:no-op 桩,保证 cli/main 调用点零 cfg 门控 =====

#[cfg(not(unix))]
mod stub {
    use super::StatusInfo;
    use crate::crypto::{KdfParams, MasterKey};
    use crate::error::{Error, Result};
    use std::path::Path;
    use std::time::Duration;

    pub fn try_get_key(_path: &Path) -> Option<(MasterKey, KdfParams, [u8; 16])> {
        None
    }
    pub fn put_key(_path: &Path, _key: &MasterKey, _kdf: &KdfParams, _salt: [u8; 16]) {}
    pub fn forget(_path: &Path) {}
    pub fn lock_all() {}
    pub fn stop() {}
    pub fn status() -> Option<StatusInfo> {
        None
    }
    pub fn serve(_socket: &Path, _ttl: Duration) -> Result<()> {
        Err(Error::Other(
            "agent is not supported on this platform (Unix only)".into(),
        ))
    }
}

#[cfg(not(unix))]
pub use stub::{forget, lock_all, put_key, serve, status, stop, try_get_key};
