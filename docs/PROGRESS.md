# zkv 开发进度

> 本文件是开发的**单一事实来源**(single source of truth)。
> 产品规格见 [PRD](prd/zkv.md)。

## 当前状态

- **阶段**:✅ **MVP 完成**(SA1–SA6 全部交付,端到端验证通过)+ 无头 CLI / TOTP 扩展
- **最后更新**:2026-06-20
- **验证**:`cargo build` / `cargo test`(**174 passed**, +1 ignored)/ `cargo build --release` / `cargo clippy --all-targets` 全绿、0 warning;PTY e2e 套件(`just e2e`,6 用例)通过;完整无头 CLI(22 子命令)+ TOTP + TUI 管理(分类/标签/附件)经真二进制端到端冒烟验证。

## 使用方法

```bash
zkv new   ~/my.zkv   # 创建新库(进入 TUI 设口令)
zkv open  ~/my.zkv   # 打开已有库(进入 TUI 输口令)
```

**无头 CLI**(可脚本化,无需 TTY;口令取自 `ZKV_PASSPHRASE` / `--passfile` / 交互):

```bash
zkv init   ~/my.zkv                              # 非交互建库(不进 TUI;已存在则报错)
zkv gen    [24] [--no-symbols] [--no-ambiguous]  # 生成强随机密码(无需库)
# 条目 CRUD(<id> 可换成 --find <标题前缀> 定位):
zkv ls     ~/my.zkv [-t password] [--tag T] [--cat C] [-q github] [-F|--favorite] [--json]
zkv get    ~/my.zkv <id> [-f password]           # -f 打印原始字段,便于管道
zkv search ~/my.zkv <query>
zkv otp    ~/my.zkv <id>                         # 打印当前 TOTP 6 位码到 stdout
zkv cp     ~/my.zkv <id> [-f otp] [--clear 20]   # 复制字段(或实时 TOTP 码)到剪贴板
zkv add    ~/my.zkv --title T --data '<ItemData JSON>' [--tag T] [--favorite] [--cat C]
           [--gen-password[=LEN]] [--otpauth 'otpauth://...']
zkv edit   ~/my.zkv <id> [--title T] [--data '<json>'|单字段:--username/--password/--url/--totp/--notes/--content/--holder/--number/--expiry/--cvv/--bank]
           [--tag T | --add-tag T | --rm-tag T] [--cat C] [--favorite|--no-favorite] [--otpauth 'otpauth://...']
zkv rm     ~/my.zkv <id> [-y]                    # 默认交互确认,-y 跳过
# 分类 / 标签 / 附件管理:
zkv cat add ~/my.zkv <name> [--parent P]  ·  zkv cat ls ~/my.zkv  ·  zkv cat rm ~/my.zkv <id|name>
zkv tag ls ~/my.zkv  ·  zkv tag mv ~/my.zkv <old> <new>  ·  zkv tag rm ~/my.zkv <name>
zkv attach add ~/my.zkv <id> <file> [--mime M]  ·  zkv attach ls ~/my.zkv <id>
zkv attach get ~/my.zkv <id> <att> [-o file|>file]  ·  zkv attach rm ~/my.zkv <id> <att>
# 导入 / 导出(明文;JSON 无损,CSV 仅 password):
zkv export ~/my.zkv --format json|csv [-o file]  ·  zkv import ~/my.zkv --format json|csv [-i file]
```

TUI 快捷键:`n` 新建 · `e` 编辑 · `x` 删除 · `/` 搜索 · `y` 复制密码(20s 自动清空) · **`o` 复制 TOTP 验证码** · **`a` 附件管理** · `l` 锁定 · **`c`/`t` 分类/标签管理(增删改)** · `q` 退出。三类条目:密码 / 笔记 / 卡片。

## 关键决策记录

1. 加密:Argon2id(m=64MiB, t=3, p=4, salt=16B)+ XChaCha20-Poly1305(key=32B, nonce=24B, tag=16B)。
2. 加密粒度:整库加密;解锁 = 解密 → 内存 SQLite(`:memory:`);保存 = dump → 加密(**复用解锁时派生并缓存的 `MasterKey`/salt,不再每次重跑 Argon2id**)→ 原子写回。
3. 数据模型:统一 `items` + JSON `data`;三类 password/note/card;FTS5 全文搜索 + 分类/标签过滤。
4. UI 主题:`ratatui-sci-fi` 0.2.0(默认 Cyberpunk;8 主题 Palette),作者即 Liangdi。
5. MVC:App(L4)= Model+Controller;UI(L5)= View(只读 App pub 状态 + 转发 `KeyEvent`)。
6. 安全:忘口令不可恢复;复制密码 20s 清空;`from_bytes` 用 backup 灌入真 `:memory:`(明文不落盘);`.zkv` 与临时文件均 0600,临时文件名取自 CSPRNG(不可预测);`MasterKey` 以 `ZeroizeOnDrop` 缓存于 App,`lock()` 即清零,App 不再驻留明文口令。
7. **无头 CLI 架构**:新增 `cli.rs` 作为与 TUI 平行的前端,直接调 L2/L3(`vault`/`store`/`search`/`clipboard`),**不复用 `App`**(它和 TUI 的 `Mode`/`handle_key` 强耦合)。`Unlocked` 封装 `unlock_full` + `save_with_key`,读写共用;口令来源 `env ZKV_PASSPHRASE` → `--passfile` → rpassword,全程 `Zeroizing` 包裹。
8. **TOTP**:新增 `totp.rs`(L1 纯计算,RFC 6238:HMAC-SHA1 + base32,依赖 `hmac`/`sha1`/`data-encoding`)。CLI `otp` 打印实时码、`cp -f otp` 复制码;TUI 详情页 password 条目显示**实时 6 位码 + 倒计时**而非掩码密钥,`o` 键复制。经 RFC 6238 官方测试向量 + Python 独立实现交叉验证。

## 模块架构与分层依赖

```
error(L0✅) → crypto/model/totp(L1✅) → db/vault(L2✅) → store/search/clipboard(L3✅) → app(L4✅) → ui(L5✅) → main(L6✅)
```

```
src/
├── lib.rs · main.rs(clap CLI + color-eyre panic hook 恢复终端)
├── error.rs   L0 ✅  统一 Error/Result
├── crypto.rs  L1 ✅  Argon2id + XChaCha20-Poly1305, MasterKey(ZeroizeOnDrop)
├── totp.rs    L1 ✅  RFC 6238(HMAC-SHA1 + base32),totp_at/current_totp
├── model.rs   L1 ✅  Item/ItemData/Category/Tag/Attachment
├── db.rs      L2 ✅  内存 SQLite + schema + FTS5 触发器 + dump/backup-to-memory
├── vault.rs   L2 ✅  .zkv 容器(58B 头)+ create/unlock_full/save_with_key(原子写,0600)
├── store.rs   L3 ✅  CRUD + search_text 自动刷新 + 标签挂载
├── search.rs  L3 ✅  FTS5 MATCH + sanitize_fts + 组合过滤
├── clipboard.rs L3 ✅ 系统命令后端(pbcopy/wl-copy/xclip/xsel)+ 定时清空
├── app.rs     L4 ✅  App/Mode/EditorState/handle_key 全状态机
├── ui/        L5 ✅  mod(主循环+TerminalGuard)/theme(sci-fi)/list/detail/input
└── cli.rs     · ✅  无头 CLI 前端(不依赖 App):init/ls/get/search/cp/otp/add/edit/rm + cat/tag/attach 管理 + gen + export/import
```

## 里程碑与任务进度(全部完成)

- ✅ **M0 脚手架** — Cargo.toml + lib.rs + 模块骨架
- ✅ **SA1 基础层** — error / crypto / model(15 单测)
- ✅ **SA2 数据/容器层** — db / vault(+ backup 安全改进)(+10 单测)
- ✅ **SA3 操作层** — store / search / clipboard(+19 单测)
- ✅ **SA4 应用层** — app 状态机(+13 单测)
- ✅ **SA5 UI 层** — ratatui-sci-fi 主题 + 三栏 + 主循环(+2 单测)
- ✅ **SA6 集成层** — main.rs(clap new/open)+ panic hook + 端到端 build/test/release
- ✅ **SA7 性能与加固** — MasterKey 缓存 / N+1 修复 / 剪贴板缓存 / 临时文件加固 / clippy 全清
- ✅ **SA8 无头 CLI + TOTP** — init/ls/get/search/cp/add/edit/rm/otp + RFC 6238 + TUI 实时码
- ✅ **SA9 无头 CLI 全功能** — cat/tag/attach 管理 · gen 密码生成 · export/import · edit 单字段 + 标签增删 + --otpauth · --find 标题定位
- ✅ **SA10 TUI 管理补全** — CategoryMgr/TagMgr 增删改面板 · Mode::Attachments 附件管理 · detail 附件摘要

## 最终端到端验证(2026-06-20)

- `cargo build` → exit 0,0 warning
- `cargo test` → **174 passed; 0 failed; 1 ignored**
- `cargo build --release` → exit 0,0 warning
- `cargo clippy --all-targets` → 0 warning
- `zkv --help` → 显示全部子命令(`new`/`open`/`init`/`gen`/`ls`/`get`/`search`/`otp`/`cp`/`add`/`edit`/`rm`/`cat`/`tag`/`attach`/`export`/`import`),exit 0
- **TUI PTY e2e**(`just e2e`,6 用例):CLI/启动屏/解锁(对错口令)/建库+建条目+落盘重开;6/6。
- **无头 CLI 真二进制冒烟**:`init`→`ls`(空)→`add`→`ls`→`get -f password`→`edit`→`rm` 全链路无需 TTY。
- **TOTP 交叉验证**:`zkv otp`(经典密钥 `JBSWY3DPEHPK3PXP`)与 Python 标准库独立 TOTP 同窗输出一致。
- **TUI 实时 TOTP**:PTY 驱动 `zkv open`,详情页渲染 `TOTP: <6位码> (~Ns)` 实时倒计时,`o` 键 `totp copied`,退出码 0。

## 已知限制 / 后续(非 MVP)

- 分类/标签管理:无头 CLI(`cat`/`tag` 增删改查)与 **TUI**(`c`/`t` 管理面板,增删改)均已全功能。
- 自定义数据结构(字段模板)未做;`data` 已是 JSON,扩展天然兼容。
- 大库优化:`dump_bytes` 仍用瞬时 VACUUM INTO 临时文件(SQLite 固有),超大库可考虑 per-page 加密。
- 跨平台:主开发 Linux;剪贴板后端已含 macOS/Wayland/X11 探测,Windows 暂无 CLI 后端。
- 导入/导出:无头 CLI 已支持(JSON 无损 / CSV 仅 password);**无同步**(纯本地,符合当前定位)。

## 变更日志

- **2026-06-18** 脚手架 + SA1(error/crypto/model)。
- **2026-06-18**(修正)确认 `ratatui-sci-fi 0.2.0` 存在(作者 Liangdi);撤回"自实现主题"误判。
- **2026-06-18** SA2(db/vault)+ 启用 rusqlite `backup`,`from_bytes` 灌入真 `:memory:`。
- **2026-06-18** SA3(store/search/clipboard)。
- **2026-06-18** SA4(应用状态机)。
- **2026-06-18** SA5(UI 层,ratatui-sci-fi Cyberpunk 主题)。
- **2026-06-18** SA6(main.rs 集成)+ 端到端验证通过。**MVP 完成。**
- **2026-06-18** PTY e2e 套件(`tests/e2e_pty.py`,`just e2e`):stdlib `pty` 驱动真实 `zkv` 二进制(80×24),6 用例覆盖 CLI/启动屏/解锁(对错口令)/建库+建条目+落盘重开;断言渲染文本 + exit 0。
- **2026-06-18** 截图脚本(`tests/screenshot.py`,`just shots`):改用**真终端渲染**——PTY 采集 zkv 原始 ANSI 流 → 在 Xvfb 里 `cat` 进真 `xterm`(Source Code Pro、深底)→ `xdotool`+`import` 按窗口截 PNG。取代之前的 pyte+Pillow 近似(字体/行高/抗锯齿/背景都对不上真终端)。依赖 `Xvfb`/`xterm`/`xdotool`/`ImageMagick`。**顺带暴露并修复**口令模态在 80×24 下高度不足(`centered_rect` 20%→40%→50%)导致口令输入框被布局压扁挤没的 bug([src/ui/mod.rs](../src/ui/mod.rs))。
- **2026-06-18** UI 重排(纯 View 层):浏览态改为 **header(品牌·消息·`N items · unlocked`)+ 两栏(list/detail,留缝)+ footer 键位栏**;列表项两行(配色类型标签 `[PW]`青/`[NO]`绿/`[CD]`品红 + 标题 + 弱化次要信息);Detail 动态标题、定宽标签列、密码掩码圆点、空值 `—` 占位、`[y] copy` 提示;移除常驻侧边栏(分类/标签计数折进 header,管理仍走 `c`/`t` 模态)。状态机/键位/加密零改动;`cargo test` 59 passed、`just e2e` 6/6。
- **2026-06-18** UI 科幻化:启用自家的 `ratatui-sci-fi` `Panel` 组件——list/detail/编辑器/口令模态全部换成**圆角霓虹面板**(主题级边框 + 1 内边距 + 级联标题),口令框内嵌圆角输入盒,小模态与输入框统一圆角;header 加 `●` 状态点。边框形态集中在 [theme.rs](../src/ui/theme.rs) 的 `PANEL_SHAPE` 常量(改一处可切 Rounded/Double/Thick)。`cargo test` 59、`just e2e` 6/6、`just shots` 7 张更新。
- **2026-06-20** 性能与加固优化(`cargo clippy --all-targets` 0 warning):
  - **缓存 MasterKey**(性能,主修复):[app.rs](../src/app.rs) 在 `unlock` 后缓存派生出的 `MasterKey`/salt/kdf,`save()` 只做 AEAD,不再每次新建/编辑/删除条目都重跑 64MiB/3/4 的 Argon2id(原每次 ~0.3–1s)。`lock()` 清零缓存的 key;**移除 `passphrase` 字段,App 不再驻留明文口令**。新增 [vault.rs](../src/vault.rs) `unlock_full`(返回 db+key+salt+kdf)与 `save_with_key`(仅 AEAD,不派生、不重读文件);`kdf` 一并回写文件头以保持解锁闭环一致。
  - **消除 N+1 标签查询**:[store.rs](../src/store.rs) `list_items` 与 [search.rs](../src/search.rs) `search` 改为单条 SQL + `GROUP_CONCAT`(`char(31)` 分隔)相关子查询一次性聚合标签,删除 per-item 的 `fill_tags` 循环(`get_item` 仍用,单条 O(1))。
  - **缓存剪贴板后端**:[clipboard.rs](../src/clipboard.rs) 用 `OnceLock` 缓存首次探测结果,`copy()` 不再每次 spawn 探测进程(清空线程也复用缓存)。
  - **临时文件加固 + 写入持久性**:[db.rs](../src/db.rs) 临时文件名改用 `getrandom` CSPRNG(原为可预测的纳秒+计数器);[vault.rs](../src/vault.rs) 原子 `rename` 后 fsync 父目录(Unix,best-effort;崩溃不丢重命名)。
  - **clippy 清扫(8→0)**:`single_match` ×3、`map_identity`、`op_ref`、`doc_nested_refdefs` ×2、`should_implement_trait`(`ItemType::from_str` 固有方法 → `std::str::FromStr` trait;UFCS 调用点不变)。
  - 验证:`cargo build` / `cargo test`(59 passed)/ `cargo clippy --all-targets` 全绿、0 warning。
- **2026-06-20** 无头 CLI + TOTP(可脚本化,无需 TTY;`cargo test` 98 passed):
  - **无头 CLI 命令面**(新增 [cli.rs](../src/cli.rs),与 TUI 解耦、直接调 L2/L3,不复用 `App`):`init`(非交互建库,口令取自 `ZKV_PASSPHRASE`/`--passfile`/交互,已存在则报错)、`ls`(过滤 + `--json`)、`get`(整条或 `-f <字段>` 原始值,便于管道)、`search`、`cp`(复制字段,`-f otp` 复制实时码,20s 清空)、`add`/`edit`/`rm`(写后 `save_with_key`,不重跑 Argon2)。口令全程 `Zeroizing` 包裹;`Unlocked` 封装 `unlock_full` + `save`。
  - **TOTP 验证码生成**(新增 [totp.rs](../src/totp.rs),RFC 6238:HMAC-SHA1 + base32,依赖 `hmac`/`sha1`/`data-encoding`):`otp <id>` 打印当前 6 位码到 stdout;`cp <id> -f otp` 复制实时码。经 RFC 6238 官方测试向量 + Python 独立实现交叉验证一致。
  - **TUI 实时 TOTP**([ui/detail.rs](../src/ui/detail.rs)):详情页 password 条目的 TOTP 行由掩码密钥改为**实时 6 位码 + `~Ns` 倒计时**(空 `—`、非法 base32 `(invalid)`);[app.rs](../src/app.rs) 加 `o` 键复制当前码(复用 `totp::current_totp` + 剪贴板);footer 加 `o:otp`。经 PTY 驱动真二进制确认 `TOTP: <6位码>` 实时渲染。
  - 验证:`cargo build` / `cargo clippy --all-targets` 0 warning;`cargo test` 98 passed;`just e2e` 6/6;无头命令 + TOTP 经真二进制端到端冒烟(含 `otp` 与 Python 交叉比对)。
- **2026-06-20** 无头 CLI 全功能补全(SA9;`cargo test` 156 passed,5 批次串行 + 真二进制端到端冒烟):
  - **分类/标签管理**(`cat add/rm/ls`、`tag ls/rm/mv`,nested subcommand):[store.rs](../src/store.rs) 补 `delete_tag`/`update_tag`;`cat rm` 按 id 或名解析,`tag rm` 级联清理 `item_tags`。
  - **附件 CLI**(`attach add/ls/get/rm`):驱动既有 store 附件 CRUD;`add` 按扩展名推断 MIME(`--mime` 覆盖);`get` 二进制安全输出到 `-o` 文件或 stdout(blob 字节往返一致);`ls` 不碰 blob;Get/Rm 校验附件归属 item。
  - **密码生成**(`gen` + `add --gen-password`):CSPRNG(getrandom)+ 拒绝采样(无模偏),`--no-symbols`/`--no-ambiguous`;`gen` 无需库;`--gen-password` 生成结果打到 stderr 不污染 stdout 的 id 行。
  - **导入/导出**(`export`/`import`,`--format json|csv`):JSON 无损 `Vec<Item>` 往返;CSV 仅 password(手写转义,逗号/引号/换行正确;tags 用 `;`)。逐条容错(`imported N (K failed)`);`-o` 文件 0600;输出明文已在 help 提示。
  - **增强**:`add`/`edit --otpauth <URI>` 从 otpauth:// 抽 secret 填 `totp_secret`;`edit` 单字段 flag(`--username`/`--password`/…,与 `--data` 互斥)+ 标签增删(`--add-tag`/`--rm-tag`,与 `--tag` 互斥);`get`/`edit`/`rm`/`cp`/`otp` 支持 `--find <标题>`(精确 → 唯一前缀)定位,`resolve_id` 复用。
  - 验证:`cargo build` / `cargo clippy --all-targets` 0 warning;`cargo test` 156 passed;`just e2e` 6/6(无回归)。
- **2026-06-21** TUI 管理补全(SA10;`cargo test` 174 passed;2 批次串行 + PTY 驱动确认渲染):
  - **分类/标签管理面板**(`Mode::CategoryMgr`/`TagMgr` 从 stub 补全):[app.rs](../src/app.rs) 加 `mgr_selected`/`mgr_edit` 状态(复用 `input` 做名称输入);浏览态 `j/k` 选择、`a` 新增、`r` 改名(预填)、`x` 删除、`Esc` 返回;编辑态 `Enter` 提交 / `Esc` 取消。[ui/mod.rs](../src/ui/mod.rs) `draw_mgr` 居中面板(列表+选中高亮+输入行+footer 提示)。复用 store cat/tag CRUD,写后 save+reload。
  - **附件管理**(`Mode::Attachments`):Normal 下 `a` 进入管理选中条目的附件;`a` 添加(路径输入→读文件→`guess_mime`→insert)、`e` 导出(路径→写 blob)、`x` 删除、`Esc` 返回;`att_list`/`att_edit` 状态。**列表/摘要一律不读 blob**(自写 SQL)。[ui/detail.rs](../src/ui/detail.rs) 只读视图末尾附 `📎 <filename> (<size>)` 摘要 + `press a to manage` 提示。`cli::guess_mime` 提为 `pub` 复用。
  - 验证:`cargo build` / `cargo clippy --all-targets` 0 warning;`cargo test` 174 passed;`just e2e` 6/6(无回归);PTY 驱动确认分类/附件管理面板真实渲染。
