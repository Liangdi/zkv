# zkv 开发进度

> 本文件是开发的**单一事实来源**(single source of truth)。
> 产品规格见 [PRD](prd/zkv.md)。

## 当前状态

- **阶段**:✅ **MVP 完成**(SA1–SA6 全部交付,端到端验证通过)
- **最后更新**:2026-06-20
- **验证**:`cargo build` / `cargo test`(59 passed, +1 ignored)/ `cargo build --release` / `cargo clippy --all-targets` 全绿、0 warning;PTY e2e 套件(`just e2e`,6 用例)通过。

## 使用方法

```bash
cargo run --release -- new   ~/my.zkv   # 创建新库(TUI 内设口令)
cargo run --release -- open  ~/my.zkv   # 打开已有库(TUI 内输口令)
```

TUI 快捷键:`n` 新建 · `e` 编辑 · `x` 删除 · `/` 搜索 · `y` 复制密码(20s 自动清空) · `l` 锁定 · `c/t` 分类/标签管理 · `q` 退出。三类条目:密码 / 笔记 / 卡片。

## 关键决策记录

1. 加密:Argon2id(m=64MiB, t=3, p=4, salt=16B)+ XChaCha20-Poly1305(key=32B, nonce=24B, tag=16B)。
2. 加密粒度:整库加密;解锁 = 解密 → 内存 SQLite(`:memory:`);保存 = dump → 加密(**复用解锁时派生并缓存的 `MasterKey`/salt,不再每次重跑 Argon2id**)→ 原子写回。
3. 数据模型:统一 `items` + JSON `data`;三类 password/note/card;FTS5 全文搜索 + 分类/标签过滤。
4. UI 主题:`ratatui-sci-fi` 0.2.0(默认 Cyberpunk;8 主题 Palette),作者即 Liangdi。
5. MVC:App(L4)= Model+Controller;UI(L5)= View(只读 App pub 状态 + 转发 `KeyEvent`)。
6. 安全:忘口令不可恢复;复制密码 20s 清空;`from_bytes` 用 backup 灌入真 `:memory:`(明文不落盘);`.zkv` 与临时文件均 0600,临时文件名取自 CSPRNG(不可预测);`MasterKey` 以 `ZeroizeOnDrop` 缓存于 App,`lock()` 即清零,App 不再驻留明文口令。

## 模块架构与分层依赖

```
error(L0✅) → crypto/model(L1✅) → db/vault(L2✅) → store/search/clipboard(L3✅) → app(L4✅) → ui(L5✅) → main(L6✅)
```

```
src/
├── lib.rs · main.rs(clap CLI + color-eyre panic hook 恢复终端)
├── error.rs   L0 ✅  统一 Error/Result
├── crypto.rs  L1 ✅  Argon2id + XChaCha20-Poly1305, MasterKey(ZeroizeOnDrop)
├── model.rs   L1 ✅  Item/ItemData/Category/Tag/Attachment
├── db.rs      L2 ✅  内存 SQLite + schema + FTS5 触发器 + dump/backup-to-memory
├── vault.rs   L2 ✅  .zkv 容器(58B 头)+ create/unlock/save(原子写,0600)
├── store.rs   L3 ✅  CRUD + search_text 自动刷新 + 标签挂载
├── search.rs  L3 ✅  FTS5 MATCH + sanitize_fts + 组合过滤
├── clipboard.rs L3 ✅ 系统命令后端(pbcopy/wl-copy/xclip/xsel)+ 定时清空
├── app.rs     L4 ✅  App/Mode/EditorState/handle_key 全状态机
└── ui/        L5 ✅  mod(主循环+TerminalGuard)/theme(sci-fi)/list/detail/input
```

## 里程碑与任务进度(全部完成)

- ✅ **M0 脚手架** — Cargo.toml + lib.rs + 模块骨架
- ✅ **SA1 基础层** — error / crypto / model(15 单测)
- ✅ **SA2 数据/容器层** — db / vault(+ backup 安全改进)(+10 单测)
- ✅ **SA3 操作层** — store / search / clipboard(+19 单测)
- ✅ **SA4 应用层** — app 状态机(+13 单测)
- ✅ **SA5 UI 层** — ratatui-sci-fi 主题 + 三栏 + 主循环(+2 单测)
- ✅ **SA6 集成层** — main.rs(clap new/open)+ panic hook + 端到端 build/test/release

## 最终端到端验证(2026-06-18)

- `cargo build` → exit 0,0 warning
- `cargo test` → **59 passed; 0 failed; 1 ignored**
- `cargo build --release` → exit 0,0 warning
- `zkv --help` → 正确显示 `new`/`open` 子命令,exit 0
- **TUI 冒烟**(python pty,80×24):启动 → 渲染「Create New Vault」口令屏(标题 + file: 路径 + 科幻边框)→ Esc 正常退出 → 终端恢复,**全程无 panic**。

## 已知限制 / 后续(非 MVP)

- 分类/标签管理(`c`/`t`)目前是最小实现(仅展示 + Esc 返回),增删交互留待后续。
- 自定义数据结构(字段模板)未做;`data` 已是 JSON,扩展天然兼容。
- 大库优化:`dump_bytes` 仍用瞬时 VACUUM INTO 临时文件(SQLite 固有),超大库可考虑 per-page 加密。
- 跨平台:主开发 Linux;剪贴板后端已含 macOS/Wayland/X11 探测,Windows 暂无 CLI 后端。
- 无导入/导出、无同步(纯本地,符合当前定位)。

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
