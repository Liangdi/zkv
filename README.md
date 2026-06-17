# zkv · 零知识保险箱

> 🔐 本地优先、端到端加密的个人数据保险箱。口令不出本机,密钥不落盘,`.zkv` 文件离开你的电脑就是一堆无意义的密文。

[English](README_en.md) | 中文

![Rust](https://img.shields.io/badge/Rust-edition%202024-orange)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL-green)
![Tests](https://img.shields.io/badge/tests-59%20passed-success)

一个跑在终端里的密码 / 笔记 / 卡片管理器,采用科幻风 TUI([ratatui-sci-fi](https://crates.io/crates/ratatui-sci-fi) Cyberpunk 主题),所有数据经 **Argon2id + XChaCha20-Poly1305** 整库加密。

---

## ✨ 特性

- 🔒 **零知识加密** — Argon2id 从口令派生密钥,XChaCha20-Poly1305 整库加密;密钥用完即清零,绝不落盘。
- 🗄️ **多库支持** — 每个 `.zkv` 文件独立口令,可同时管理多个保险箱。
- 📇 **多类型条目** — 密码、笔记、卡片三类预设;字段以 JSON 存储,扩展自由。
- 🔎 **全文搜索** — 基于 SQLite FTS5,按标题与内容检索。
- 🏷️ **分类与标签** — 树状分类 + 多对多标签 + 收藏,任意组合过滤。
- 🖼️ **附件内嵌** — 图片 / 电子档直接存入数据库,随库加密。
- 🎨 **科幻风 TUI** — 三栏布局,霓虹配色,键盘驱动。
- ⏱️ **安全细节** — 复制密码后剪贴板 20 秒自动清空;原子写盘防损坏;文件权限 0600。

## 🖥️ 预览

```
┌ Categories / Tags ─┬─ Items ─────────────┬─ Detail ─────────────┐
│ ▸ Work             │ ★ [PW] GitHub Login  │ Title:    GitHub Login│
│   • Servers        │   [PW] GitLab Token  │ Type:     Password    │
│ ▸ Personal         │ ★ [NO] Secret Diary  │ Username: alice       │
│                    │   [CD] Visa ****     │ Password: •••••••••   │
│ Tags               │                      │ URL:      github.com │
│ work  vip  personal│                      │                       │
└────────────────────┴──────────────────────┴───────────────────────┘
[NORMAL]  n:new  e:edit  x:del  /:search  y:copy  l:lock  q:quit
```

## 🚀 快速开始

需要 Rust 1.85+(edition 2024)。

```bash
git clone <repo-url> zkv && cd zkv
cargo run --release -- new  ~/my.zkv     # 创建新库(TUI 内设口令)
cargo run --release -- open ~/my.zkv     # 打开已有库
```

或安装到 `$CARGO_HOME/bin`:

```bash
cargo install --path .
zkv new ~/my.zkv
```

## ⌨️ 操作指南

| 键 | 动作 |
| --- | --- |
| `n` | 新建条目(密码 / 笔记 / 卡片) |
| `e` | 编辑当前条目 |
| `x` | 删除当前条目(需确认) |
| `/` | 搜索 |
| `j` / `k`,`↑` / `↓` | 上下移动 |
| `y` | 复制密码到剪贴板(20s 后自动清空) |
| `l` | 立即锁定(清空内存中的密钥与数据) |
| `c` / `t` | 分类 / 标签管理 |
| `Tab` / `↑` / `↓` | 编辑时切换字段 |
| `Enter` | 保存 / 确认 / 提交口令 |
| `Esc` | 取消 / 返回(锁定态下退出程序) |
| `q` | 退出 |

## 🛡️ 安全设计

**加密方案**

| 用途 | 算法 | 参数 |
| --- | --- | --- |
| 口令派生 (KDF) | Argon2id | m=64MiB, t=3, p=4, salt=16B, 输出 32B |
| 对称加密 | XChaCha20-Poly1305 | key=32B, nonce=24B(每次随机), tag=16B(AEAD) |

**加密粒度**:整个 SQLite 数据库作为一个 blob 加密。解锁时解密载入**内存**(`:memory:`),退出 / 锁定时清零;保存时重新加密(每次生成新 nonce)原子写回。明文从不在磁盘长期存在。

**威胁模型**
- ✅ 防御:`.zkv` 文件被离线窃取后只能暴力破解口令(Argon2id 拉高成本);明文不落盘;元数据(条目数、标签名等)整体加密不可见。
- ⚠️ 不防御:本机已被完全攻陷(键盘记录器、内存 dump、冷启动攻击)。
- ⚠️ **忘记口令 = 数据不可恢复**。零知识的必然代价 —— 请妥善备份口令与 `.zkv` 文件。

## 🧱 技术栈

- **语言**:Rust(edition 2024)
- **TUI**:[ratatui](https://crates.io/crates/ratatui) · [crossterm](https://crates.io/crates/crossterm) · [ratatui-sci-fi](https://crates.io/crates/ratatui-sci-fi)
- **数据库**:[rusqlite](https://crates.io/crates/rusqlite)(bundled SQLite,含 FTS5)
- **加密**:[argon2](https://crates.io/crates/argon2) · [chacha20poly1305](https://crates.io/crates/chacha20poly1305) · [zeroize](https://crates.io/crates/zeroize) · [secrecy](https://crates.io/crates/secrecy)
- **其他**:[clap](https://crates.io/crates/clap)、[serde](https://crates.io/crates/serde)、[thiserror](https://crates.io/crates/thiserror)、[color-eyre](https://crates.io/crates/color-eyre)

## 🏗️ 架构

分层设计,单向依赖(下层不引用上层),遵循 MVC(`App` = Model + Controller,UI = View):

```
error(L0) → crypto/model(L1) → db/vault(L2) → store/search/clipboard(L3) → app(L4) → ui(L5) → main
```

详见 [docs/PROGRESS.md](docs/PROGRESS.md) 与 [docs/prd/zkv.md](docs/prd/zkv.md)。

## 📄 `.zkv` 文件格式

小端序,58 字节定长头 + 密文:

```
[4 "ZKV1"][1 ver][1 flags][4 m_kib][4 t_cost][4 p_cost][16 salt][24 nonce][N ciphertext]
```

KDF 参数随文件存储,便于未来调参而旧文件仍可解析;Poly1305 校验失败即判定口令错误或文件损坏。

## 🛠️ 开发

```bash
cargo test             # 单元 / 集成测试(59 passed)
cargo build --release  # 发布构建
```

## 🗺️ 路线图

- [ ] 分类 / 标签的增删交互(目前仅展示)
- [ ] 自定义字段模板
- [ ] 导入 / 导出(CSV / JSON / KeePass)
- [ ] 大库 per-page 加密优化
- [ ] Windows 剪贴板后端

## 📜 许可证

MIT
