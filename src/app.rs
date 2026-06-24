//! 应用状态机:连接 UI 与数据层(MVC 中的 Model+Controller)。对应 PRD §8。
//!
//! ## MVC 边界
//! - **App = Model + Controller**:持有全部状态与业务逻辑。
//! - **UI = View**(SA5):只读 App 的 `pub` 字段来渲染,并把原始按键
//!   `crossterm::event::KeyEvent` 转发给 [`App::handle_key`]。UI 不做业务判断。
//!
//! 对外接口:
//! - [`App`] / [`Mode`] / [`PassKind`] / [`EditorState`] / [`Cursor`] / [`Action`]
//! - [`App::for_open`] / [`App::for_create`] / [`App::from_unlocked`]
//! - [`App::handle_key`] / [`App::reload`] / [`App::save`] / [`App::lock`] / [`App::selected_item`]
//!
//! 分层(L4):可依赖 `error`/`crypto`/`model`/`db`/`vault`/`store`/`search`/`clipboard`
//! 与外部 crate,**不得** `use crate::ui`。

use std::path::PathBuf;
use std::sync::mpsc;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::clipboard;
use crate::crypto::{KdfParams, MasterKey};
use crate::db::Database;
use crate::error::{Error, Result};
use crate::model::{instantiate_template, FieldKind, Item};
use crate::search::{self, Filter};
use crate::store;
use crate::vault;

// ---------------------------------------------------------------------------
// 类型定义
// ---------------------------------------------------------------------------

/// `handle_key` 的返回值:主循环据此决定重绘或退出。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 继续运行(状态可能已变,需要重绘)。
    Continue,
    /// 退出主循环。
    Quit,
}

/// 口令输入场景。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassKind {
    /// 打开已有库。
    Open,
    /// 创建新库。
    Create,
}

/// 应用当前所在模式(对应 PRD §8 的各交互态)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// 浏览列表。
    Normal,
    /// 搜索输入框。
    Search,
    /// 口令输入(打开/创建)。
    PromptPassphrase(PassKind),
    /// 选择模板(`n` 键进入,j/k 选,Enter 新建)。
    PickTemplate,
    /// 新建条目(编辑器),携带 template_id。
    NewItem(String),
    /// 编辑现有条目(编辑器)。
    EditItem,
    /// 确认删除。
    ConfirmDelete,
    /// 导入/配置 TOTP 弹窗(otpauth:// URI、本地二维码图片、或 http(s)/data: URL)。
    /// `self.editor` 仍持有草稿;完成后按 [`self.totp_return`] 返回编辑器。
    ImportTotp,
    /// 分类管理。
    CategoryMgr,
    /// 标签管理。
    TagMgr,
    /// 附件管理(锁定进入时选中的 item)。
    Attachments,
    /// 后台解锁中:口令已提交,后台线程跑 Argon2id 派生 + 解密,前台播 boot 动画。
    /// `main_loop` 每帧 `pump_boot` 取结果,成功切 Normal / 失败回口令态。
    Booting,
}

/// 后台解锁线程回传的结果:成功装 `(Database, MasterKey, KdfParams, salt)`,
/// 失败转 `String`(错误类型非 `Send`,统一序列化跨线程)。
pub type BootResult = std::result::Result<(Database, MasterKey, KdfParams, [u8; 16]), String>;

/// 管理模式(CategoryMgr/TagMgr)中,当前是否处于文本输入态及语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgrEdit {
    /// 新增。
    Add,
    /// 改名。
    Rename,
}

/// 附件元数据(不含 blob),用于 Attachments 模式列表渲染。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttMeta {
    pub id: i64,
    pub filename: String,
    pub mime_type: Option<String>,
    pub size: i64,
}

/// Attachments 模式的输入态语义:add 输入文件路径,export 输入输出路径。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttEdit {
    Add,
    Export,
}

/// ImportTotp 弹窗关闭后应恢复的编辑器来源(NewItem / EditItem)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TotpReturn {
    #[default]
    EditItem,
    NewItem,
}

/// 管理模式所操作的实体种类(供 `mgr_handle` 复用分发)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MgrEntity {
    Category,
    Tag,
}

/// 编辑器中当前正在编辑的光标位置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cursor {
    /// 标题。
    Title,
    /// 第 `i` 个字段(`draft.fields[i]`)。
    Field(usize),
}

/// 编辑器状态:当前草稿 + 正在编辑的光标位置。
#[derive(Debug, Clone)]
pub struct EditorState {
    pub draft: Item,
    pub field: Cursor,
}

/// 应用状态机。
pub struct App {
    /// 已解锁的数据库句柄;`None` 表示已锁定/未解锁。
    pub db: Option<Database>,
    /// 库文件路径。
    pub path: Option<PathBuf>,
    /// 解锁后缓存的已派生主密钥(用于 `save` 复用,跳过 Argon2id);`lock` 时清零。
    pub master_key: Option<MasterKey>,
    /// 解锁时读取的 salt(与 master_key 配套写回文件头)。
    pub salt: Option<[u8; 16]>,
    /// 解锁时读取的 KDF 参数(与 master_key 配套写回文件头)。
    pub kdf: Option<KdfParams>,
    /// 当前模式。
    pub mode: Mode,
    /// 当前搜索/过滤条件。
    pub filter: Filter,
    /// 过滤后的条目列表(`reload` 后刷新)。
    pub items: Vec<Item>,
    /// 列表选中索引。
    pub selected: usize,
    /// 全部分类(`reload` 后刷新)。
    pub categories: Vec<crate::model::Category>,
    /// 全部标签名(`reload` 后刷新)。
    pub tags: Vec<String>,
    /// 给用户的瞬态提示信息。
    pub message: Option<String>,
    /// 编辑器状态(NewItem/EditItem 模式)。
    pub editor: Option<EditorState>,
    /// ImportTotp 完成后恢复的编辑器来源(NewItem/EditItem)。
    pub totp_return: TotpReturn,
    /// 文本输入缓冲(搜索/口令/编辑器字段共用)。
    pub input: String,
    /// 是否掩码输入(口令=true,搜索/编辑器字段=false)。
    pub input_mask: bool,
    /// 管理模式(CategoryMgr/TagMgr)中的列表选中索引。
    pub mgr_selected: usize,
    /// 管理模式当前是否在文本输入(新增/改名),及语义。
    pub mgr_edit: Option<MgrEdit>,
    /// Attachments 模式锁定的目标 item id。
    pub att_item_id: Option<i64>,
    /// Attachments 模式的附件元数据列表(不含 blob)。
    pub att_list: Vec<AttMeta>,
    /// Attachments 模式选中索引。
    pub att_selected: usize,
    /// Attachments 模式输入态:add(文件路径) / export(输出路径)。
    pub att_edit: Option<AttEdit>,
    /// PickTemplate 模式的选中索引。
    pub tpl_selected: usize,
    /// 是否请求退出。
    pub quit: bool,
    /// 后台解锁结果通道(仅 `Booting` 态非 `None`);`main_loop` 每帧 `pump_boot` drain。
    pub boot_rx: Option<mpsc::Receiver<BootResult>>,
}

impl App {
    // -----------------------------------------------------------------------
    // 构造
    // -----------------------------------------------------------------------

    /// 打开已有库:进入口令输入态(`PromptPassphrase(Open)`)。
    pub fn for_open(path: PathBuf) -> App {
        App {
            db: None,
            path: Some(path),
            master_key: None,
            salt: None,
            kdf: None,
            mode: Mode::PromptPassphrase(PassKind::Open),
            filter: Filter::default(),
            items: Vec::new(),
            selected: 0,
            categories: Vec::new(),
            tags: Vec::new(),
            message: None,
            editor: None,
            totp_return: TotpReturn::default(),
            input: String::new(),
            input_mask: true,
            mgr_selected: 0,
            mgr_edit: None,
            att_item_id: None,
            att_list: Vec::new(),
            att_selected: 0,
            att_edit: None,
            tpl_selected: 0,
            quit: false,
            boot_rx: None,
        }
    }

    /// 创建新库:进入口令输入态(`PromptPassphrase(Create)`)。
    pub fn for_create(path: PathBuf) -> App {
        App {
            db: None,
            path: Some(path),
            master_key: None,
            salt: None,
            kdf: None,
            mode: Mode::PromptPassphrase(PassKind::Create),
            filter: Filter::default(),
            items: Vec::new(),
            selected: 0,
            categories: Vec::new(),
            tags: Vec::new(),
            message: None,
            editor: None,
            totp_return: TotpReturn::default(),
            input: String::new(),
            input_mask: true,
            mgr_selected: 0,
            mgr_edit: None,
            att_item_id: None,
            att_list: Vec::new(),
            att_selected: 0,
            att_edit: None,
            tpl_selected: 0,
            quit: false,
            boot_rx: None,
        }
    }

    /// 已解锁构造(测试用):载入 db + 口令,执行首次 `reload`,进入 Normal。
    ///
    /// `passphrase` 仅用于从 `path` 文件头读 salt+kdf 派生一次 key 并缓存(这样后续
    /// `save` 可复用、且用文件里存的 KDF 参数 —— 测试里用 fast KDF 创建的文件派生很快)。
    /// 文件不存在/读失败时 key 为 None(此类 App 不会调用 save)。`passphrase` 不再驻留 App。
    pub fn from_unlocked(db: Database, path: PathBuf, passphrase: String) -> Result<App> {
        let (master_key, salt, kdf) = match std::fs::read(&path) {
            Ok(file) => match crate::vault::VaultHeader::parse(&file) {
                Ok(h) => {
                    let key = crate::crypto::derive_key(passphrase.as_bytes(), &h.salt, &h.kdf)?;
                    (Some(key), Some(h.salt), Some(h.kdf))
                }
                Err(_) => (None, None, None),
            },
            Err(_) => (None, None, None),
        };
        let mut app = App {
            db: Some(db),
            path: Some(path),
            master_key,
            salt,
            kdf,
            mode: Mode::Normal,
            filter: Filter::default(),
            items: Vec::new(),
            selected: 0,
            categories: Vec::new(),
            tags: Vec::new(),
            message: None,
            editor: None,
            totp_return: TotpReturn::default(),
            input: String::new(),
            input_mask: false,
            mgr_selected: 0,
            mgr_edit: None,
            att_item_id: None,
            att_list: Vec::new(),
            att_selected: 0,
            att_edit: None,
            tpl_selected: 0,
            quit: false,
            boot_rx: None,
        };
        app.reload()?;
        Ok(app)
    }

    // -----------------------------------------------------------------------
    // 业务方法
    // -----------------------------------------------------------------------

    /// 刷新过滤结果、分类、标签;`selected` 越界则回退到末位。
    pub fn reload(&mut self) -> Result<()> {
        let Some(ref db) = self.db else {
            self.items.clear();
            self.categories.clear();
            self.tags.clear();
            return Ok(());
        };
        let conn = db.conn();
        self.items = search::search(conn, &self.filter)?;
        self.categories = store::list_categories(conn)?;
        // list_tags 返回 Vec<Tag>,这里取 name。
        self.tags = store::list_tags(conn)?
            .into_iter()
            .map(|t| t.name)
            .collect();
        if self.selected >= self.items.len() {
            self.selected = self.items.len().saturating_sub(1);
        }
        Ok(())
    }

    /// 保存(落盘)。复用缓存的 `master_key`/`salt`/`kdf`,只做 AEAD(微秒级),不再 Argon2id。
    pub fn save(&self) -> Result<()> {
        let path = self.path.as_ref().ok_or_else(|| {
            Error::Other("save: no vault path".into())
        })?;
        let key = self
            .master_key
            .as_ref()
            .ok_or_else(|| Error::Other("save: no master key (locked?)".into()))?;
        let salt = self
            .salt
            .ok_or_else(|| Error::Other("save: no salt (locked?)".into()))?;
        let kdf = self
            .kdf
            .ok_or_else(|| Error::Other("save: no kdf (locked?)".into()))?;
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| Error::Other("save: no database".into()))?;
        vault::save_with_key(path, key, &kdf, salt, db)
    }

    /// 锁定:清空 db/master_key/salt/kdf 与 items/categories/tags,切回口令输入态
    /// (`PromptPassphrase(Open)`)——保留 `self.path`,以便用户在 TUI 内原地重新输口令
    /// 解锁(Enter 走 `handle_passphrase(Open)` → `vault::unlock`)。手动 `l` 键与
    /// 自动锁定共用此路径。
    pub fn lock(&mut self) {
        self.db = None;
        self.master_key = None;
        self.salt = None;
        self.kdf = None;
        self.mode = Mode::PromptPassphrase(PassKind::Open);
        self.items.clear();
        self.categories.clear();
        self.tags.clear();
        self.selected = 0;
        self.filter = Filter::default();
        self.input.clear();
        self.input_mask = true;
        self.editor = None;
        self.message = Some("locked".into());
    }

    /// 当前选中的 item(不可变引用)。
    pub fn selected_item(&self) -> Option<&Item> {
        self.items.get(self.selected)
    }

    /// 复制选中条目的密码字段到剪贴板,20s 后清空。
    /// 按 kind 查找:优先 `name=="password"` 的 Secret,否则首个 Secret。无则 message。
    /// 剪贴板后端不可用时仅设 message,不传播错误。
    fn copy_password_of_selected(&mut self) {
        let Some(item) = self.items.get(self.selected).cloned() else {
            self.message = Some("no item selected".into());
            return;
        };
        let pw = item
            .fields
            .iter()
            .find(|f| f.name == "password" && f.kind == FieldKind::Secret)
            .or_else(|| item.fields.iter().find(|f| f.kind == FieldKind::Secret))
            .map(|f| f.value.clone());
        let Some(pw) = pw else {
            self.message = Some("selected item has no password".into());
            return;
        };
        match clipboard::copy_and_clear_after(&pw, 20) {
            Ok(()) => self.message = Some("password copied (clears in 20s)".into()),
            Err(e) => self.message = Some(format!("clipboard unavailable: {e}")),
        }
    }

    /// 复制选中条目的 TOTP 验证码到剪贴板,20s 后清空。
    /// 找首个 kind=Totp 字段;空 secret / 无 Totp 字段 / 计算失败仅设 message,不传播错误。
    fn copy_totp_of_selected(&mut self) {
        let Some(item) = self.items.get(self.selected).cloned() else {
            self.message = Some("no item selected".into());
            return;
        };
        let secret = match item.totp_value() {
            Some(s) => s.to_string(),
            None => {
                self.message = Some("no totp secret".into());
                return;
            }
        };
        if secret.trim().is_empty() {
            self.message = Some("no totp secret".into());
            return;
        }
        match crate::totp::current_totp(&secret) {
            Ok(code) => match clipboard::copy_and_clear_after(&code, 20) {
                Ok(()) => self.message = Some("totp copied (clears in 20s)".into()),
                Err(e) => self.message = Some(format!("clipboard unavailable: {e}")),
            },
            Err(e) => self.message = Some(format!("totp failed: {e}")),
        }
    }

    // -----------------------------------------------------------------------
    // handle_key 分发
    // -----------------------------------------------------------------------

    /// 按当前 `mode` 分发按键。返回 [`Action::Quit`] 表示主循环应退出。
    pub fn handle_key(&mut self, key: KeyEvent) -> Result<Action> {
        match self.mode.clone() {
            Mode::PromptPassphrase(kind) => self.handle_passphrase(key, kind),
            Mode::Normal => self.handle_normal(key),
            Mode::Search => self.handle_search(key),
            Mode::PickTemplate => self.handle_pick_template(key),
            Mode::NewItem(tpl) => self.handle_editor(key, true, tpl),
            Mode::EditItem => self.handle_editor(key, false, String::new()),
            Mode::ImportTotp => self.handle_import_totp(key),
            Mode::ConfirmDelete => self.handle_confirm_delete(key),
            Mode::CategoryMgr => self.handle_category_mgr(key),
            Mode::TagMgr => self.handle_tag_mgr(key),
            Mode::Attachments => self.handle_attachments(key),
            // Booting 期间忽略按键(动画 ~1s,派生完成由 pump_boot 推进)。
            Mode::Booting => Ok(Action::Continue),
        }
    }

    // ---- PickTemplate ----
    fn handle_pick_template(&mut self, key: KeyEvent) -> Result<Action> {
        let tpls = crate::model::builtin_templates();
        let len = tpls.len();
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if len > 0 && self.tpl_selected + 1 < len {
                    self.tpl_selected += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.tpl_selected > 0 {
                    self.tpl_selected -= 1;
                }
            }
            KeyCode::Enter => {
                let id = tpls
                    .get(self.tpl_selected)
                    .map(|t| t.id.clone());
                match id {
                    Some(tpl) => self.start_editor_new(&tpl),
                    None => self.message = Some("no template selected".into()),
                }
            }
            KeyCode::Esc => {
                self.mode = Mode::Normal;
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    // ---- PromptPassphrase ----
    fn handle_passphrase(&mut self, key: KeyEvent, kind: PassKind) -> Result<Action> {
        match key.code {
            KeyCode::Char(c) => {
                self.input.push(c);
                self.input_mask = true;
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Enter => {
                let pass = std::mem::take(&mut self.input);
                self.input_mask = false;
                let path = match self.path.as_ref() {
                    Some(p) => p.clone(),
                    None => {
                        self.message = Some("no vault path".into());
                        return Ok(Action::Continue);
                    }
                };
                // 异步解锁:后台线程跑 Argon2id 派生 + 解密(0.5–2s),前台播 boot 动画。
                // 结果经 channel 回传,main_loop 每帧 pump_boot 装载;pass/key move 进出线程。
                let (tx, rx) = mpsc::channel::<BootResult>();
                std::thread::spawn(move || {
                    let r = match kind {
                        PassKind::Create => {
                            vault::create(&path, &pass).and_then(|()| vault::unlock_full(&path, &pass))
                        }
                        PassKind::Open => vault::unlock_full(&path, &pass),
                    };
                    let _ = tx.send(r.map_err(|e| e.to_string()));
                });
                self.boot_rx = Some(rx);
                self.mode = Mode::Booting;
            }
            KeyCode::Esc => {
                self.quit = true;
                return Ok(Action::Quit);
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    /// drain 后台解锁结果(`Booting` 态每帧调一次)。用 `take()` 取出 receiver,避免与
    /// 后续 `self` 赋值的借用冲突;未就绪(`Empty`)时放回,下一帧再 pump。
    pub fn pump_boot(&mut self) -> Result<()> {
        use std::sync::mpsc::TryRecvError;
        let Some(rx) = self.boot_rx.take() else {
            return Ok(());
        };
        match rx.try_recv() {
            Ok(Ok((db, key, kdf, salt))) => {
                self.master_key = Some(key);
                self.salt = Some(salt);
                self.kdf = Some(kdf);
                self.db = Some(db);
                self.mode = Mode::Normal;
                self.reload()?;
                self.message = Some("unlocked".into());
            }
            Ok(Err(e)) => {
                // 错误口令 / 损坏:回口令态重试。
                self.mode = Mode::PromptPassphrase(PassKind::Open);
                self.input_mask = true;
                self.message = Some(format!("unlock failed: {e}"));
            }
            Err(TryRecvError::Empty) => {
                // 派生未完成:放回 receiver,继续 boot 动画。
                self.boot_rx = Some(rx);
            }
            Err(TryRecvError::Disconnected) => {
                // worker 线程 panic:回口令态。
                self.mode = Mode::PromptPassphrase(PassKind::Open);
                self.input_mask = true;
                self.message = Some("unlock failed: worker panic".into());
            }
        }
        Ok(())
    }

    // ---- Normal ----
    fn handle_normal(&mut self, key: KeyEvent) -> Result<Action> {
        // 未解锁状态下,Normal 仅响应 q。
        if self.db.is_none() {
            if matches!(key.code, KeyCode::Char('q')) {
                self.quit = true;
                return Ok(Action::Quit);
            }
            return Ok(Action::Continue);
        }
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if !self.items.is_empty() && self.selected + 1 < self.items.len() {
                    self.selected += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.selected > 0 {
                    self.selected -= 1;
                }
            }
            KeyCode::Char('/') => {
                self.mode = Mode::Search;
                self.input.clear();
                self.input_mask = false;
            }
            KeyCode::Char('n') => {
                self.tpl_selected = 0;
                self.mode = Mode::PickTemplate;
            }
            KeyCode::Char('e') => {
                self.start_editor_edit();
            }
            KeyCode::Char('x') => {
                if self.selected_item().is_some() {
                    self.mode = Mode::ConfirmDelete;
                } else {
                    self.message = Some("no item selected".into());
                }
            }
            KeyCode::Char('y') => {
                self.copy_password_of_selected();
            }
            KeyCode::Char('o') => {
                self.copy_totp_of_selected();
            }
            KeyCode::Char('l') => {
                self.lock();
            }
            KeyCode::Char('c') => {
                self.enter_mgr(MgrEntity::Category);
            }
            KeyCode::Char('t') => {
                self.enter_mgr(MgrEntity::Tag);
            }
            KeyCode::Char('a') => {
                self.enter_attachments();
            }
            KeyCode::Char('q') => {
                self.quit = true;
                return Ok(Action::Quit);
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    // ---- Search ----
    fn handle_search(&mut self, key: KeyEvent) -> Result<Action> {
        match key.code {
            KeyCode::Char(c) => {
                self.input.push(c);
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Enter => {
                self.filter.query = Some(self.input.clone());
                self.reload()?;
                self.mode = Mode::Normal;
            }
            KeyCode::Esc => {
                // 不 apply,直接返回 Normal。
                self.mode = Mode::Normal;
                self.input.clear();
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    // ---- Editor (NewItem / EditItem) ----
    fn handle_editor(
        &mut self,
        key: KeyEvent,
        is_new: bool,
        _tpl: String,
    ) -> Result<Action> {
        // Ctrl+T:打开 TOTP 导入弹窗(otpauth:// URI / 本地二维码图片 / http(s)/data: URL)。
        // 用 Ctrl 组合而非裸字母,避免抢占字段输入字符。在借用 self.editor 之前处理。
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('t') | KeyCode::Char('T'))
        {
            self.enter_import_totp(is_new);
            return Ok(Action::Continue);
        }
        let Some(ref mut ed) = self.editor else {
            self.mode = Mode::Normal;
            return Ok(Action::Continue);
        };
        match key.code {
            KeyCode::Char(c) => {
                // Ctrl+按键不作为普通字符输入。
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(Action::Continue);
                }
                Self::write_field(&mut ed.draft, &ed.field, c);
            }
            KeyCode::Backspace => {
                Self::backspace_field(&mut ed.draft, &ed.field);
            }
            KeyCode::Tab | KeyCode::Down => {
                ed.field = Self::next_cursor(ed.draft.fields.len(), &ed.field);
            }
            KeyCode::Up => {
                ed.field = Self::prev_cursor(ed.draft.fields.len(), &ed.field);
            }
            KeyCode::Enter => {
                // 保存。
                let draft = ed.draft.clone();
                let saved = if is_new {
                    self.save_new_item(draft)
                } else {
                    self.save_edit_item(draft)
                };
                match saved {
                    Ok(()) => {
                        self.editor = None;
                        self.mode = Mode::Normal;
                    }
                    Err(e) => {
                        self.message = Some(format!("save failed: {e}"));
                    }
                }
            }
            KeyCode::Esc => {
                self.editor = None;
                self.mode = Mode::Normal;
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    // ---- ConfirmDelete ----
    fn handle_confirm_delete(&mut self, key: KeyEvent) -> Result<Action> {
        match key.code {
            KeyCode::Char('y') => {
                if let Some(id) = self
                    .items
                    .get(self.selected)
                    .and_then(|i| i.id)
                {
                    let res = (|| -> Result<()> {
                        let db = self.db.as_ref().ok_or_else(|| {
                            Error::Other("delete: no database".into())
                        })?;
                        store::delete_item(db.conn(), id)?;
                        self.save()?;
                        self.reload()?;
                        Ok(())
                    })();
                    match res {
                        Ok(()) => self.message = Some("deleted".into()),
                        Err(e) => self.message = Some(format!("delete failed: {e}")),
                    }
                }
                self.mode = Mode::Normal;
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.mode = Mode::Normal;
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    // ---- CategoryMgr ----
    fn handle_category_mgr(&mut self, key: KeyEvent) -> Result<Action> {
        self.mgr_handle(key, MgrEntity::Category)
    }

    // ---- TagMgr ----
    fn handle_tag_mgr(&mut self, key: KeyEvent) -> Result<Action> {
        self.mgr_handle(key, MgrEntity::Tag)
    }

    // -----------------------------------------------------------------------
    // 管理模式(CategoryMgr / TagMgr)
    // -----------------------------------------------------------------------

    /// 进入管理模式:重置选中/编辑态/输入缓冲,设操作提示。
    fn enter_mgr(&mut self, entity: MgrEntity) {
        self.mgr_selected = 0;
        self.mgr_edit = None;
        self.input.clear();
        self.mode = match entity {
            MgrEntity::Category => Mode::CategoryMgr,
            MgrEntity::Tag => Mode::TagMgr,
        };
        self.message = Some("a:add  r:rename  x:del  Esc:back".into());
    }

    /// 当前列表条目数(分类用 categories,标签用 tags)。
    fn mgr_list_len(&self, entity: MgrEntity) -> usize {
        match entity {
            MgrEntity::Category => self.categories.len(),
            MgrEntity::Tag => self.tags.len(),
        }
    }

    /// 夹紧 `mgr_selected` 到 [0, len)。
    fn mgr_clamp(&mut self, entity: MgrEntity) {
        let len = self.mgr_list_len(entity);
        if len == 0 {
            self.mgr_selected = 0;
        } else if self.mgr_selected >= len {
            self.mgr_selected = len - 1;
        }
    }

    /// 管理模式统一键处理(分类/标签共用)。
    fn mgr_handle(&mut self, key: KeyEvent, entity: MgrEntity) -> Result<Action> {
        match self.mgr_edit {
            Some(_) => self.mgr_handle_edit(key, entity),
            None => self.mgr_handle_browse(key, entity),
        }
    }

    /// 浏览态:移动 / 进入新增 / 改名 / 删除 / 返回。
    fn mgr_handle_browse(&mut self, key: KeyEvent, entity: MgrEntity) -> Result<Action> {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                let len = self.mgr_list_len(entity);
                if len > 0 && self.mgr_selected + 1 < len {
                    self.mgr_selected += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.mgr_selected > 0 {
                    self.mgr_selected -= 1;
                }
            }
            KeyCode::Char('a') => {
                self.mgr_edit = Some(MgrEdit::Add);
                self.input.clear();
                self.message = Some("add: type name, Enter to confirm".into());
            }
            KeyCode::Char('r') => {
                if self.mgr_list_len(entity) > 0 {
                    // 预填当前选中条目的 name。
                    let name = match entity {
                        MgrEntity::Category => self
                            .categories
                            .get(self.mgr_selected)
                            .map(|c| c.name.clone()),
                        MgrEntity::Tag => self.tags.get(self.mgr_selected).cloned(),
                    };
                    if let Some(n) = name {
                        self.input = n;
                        self.mgr_edit = Some(MgrEdit::Rename);
                        self.message = Some("rename: edit, Enter to confirm".into());
                    }
                } else {
                    self.message = Some("nothing to rename".into());
                }
            }
            KeyCode::Char('x') => {
                self.mgr_delete(entity)?;
            }
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.input.clear();
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    /// 编辑态(新增/改名):字符 / 退格 / 提交 / 取消。
    fn mgr_handle_edit(&mut self, key: KeyEvent, entity: MgrEntity) -> Result<Action> {
        match key.code {
            KeyCode::Char(c) => {
                // Ctrl 组合不作为普通字符。
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(Action::Continue);
                }
                self.input.push(c);
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Enter => {
                let edit = self.mgr_edit;
                self.mgr_commit(edit, entity)?;
            }
            KeyCode::Esc => {
                // 取消,留在管理模式浏览态。
                self.mgr_edit = None;
                self.input.clear();
                self.message = Some("a:add  r:rename  x:del  Esc:back".into());
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    /// 提交新增/改名。空名报错不提交。
    fn mgr_commit(&mut self, edit: Option<MgrEdit>, entity: MgrEntity) -> Result<()> {
        let name = self.input.trim().to_string();
        if name.is_empty() {
            self.message = Some("name cannot be empty".into());
            return Ok(());
        }
        let res = (|| -> Result<String> {
            let db = self
                .db
                .as_ref()
                .ok_or_else(|| Error::Other("mgr: no database".into()))?;
            let conn = db.conn();
            match (edit, entity) {
                (Some(MgrEdit::Add), MgrEntity::Category) => {
                    let mut cat = crate::model::Category {
                        id: None,
                        name: name.clone(),
                        parent_id: None,
                        sort_order: 0,
                    };
                    store::insert_category(conn, &mut cat)?;
                }
                (Some(MgrEdit::Add), MgrEntity::Tag) => {
                    store::ensure_tag(conn, &name)?;
                }
                (Some(MgrEdit::Rename), MgrEntity::Category) => {
                    let cur = self
                        .categories
                        .get(self.mgr_selected)
                        .ok_or_else(|| Error::Other("rename: no category selected".into()))?;
                    let mut updated = cur.clone();
                    updated.name = name.clone();
                    store::update_category(conn, &updated)?;
                }
                (Some(MgrEdit::Rename), MgrEntity::Tag) => {
                    let id = self.tag_id_at(self.mgr_selected)?;
                    store::update_tag(conn, id, &name)?;
                }
                // 无 edit 不应进入此函数;防御性返回。
                _ => return Ok(name),
            }
            Ok(name)
        })();
        match res {
            Ok(n) => {
                self.save()?;
                self.reload()?;
                self.mgr_clamp(entity);
                self.mgr_edit = None;
                self.input.clear();
                let verb = match edit {
                    Some(MgrEdit::Add) => "added",
                    Some(MgrEdit::Rename) => "renamed",
                    None => "added",
                };
                self.message = Some(format!("{verb} \"{n}\""));
                self.mgr_clamp(entity);
            }
            Err(e) => {
                self.message = Some(format!("mgr failed: {e}"));
            }
        }
        Ok(())
    }

    /// 删除当前选中条目(分类/标签)。
    fn mgr_delete(&mut self, entity: MgrEntity) -> Result<()> {
        let res = (|| -> Result<String> {
            let db = self
                .db
                .as_ref()
                .ok_or_else(|| Error::Other("delete: no database".into()))?;
            let conn = db.conn();
            match entity {
                MgrEntity::Category => {
                    let cur = self
                        .categories
                        .get(self.mgr_selected)
                        .ok_or_else(|| Error::Other("delete: no category selected".into()))?;
                    let name = cur.name.clone();
                    let id = cur
                        .id
                        .ok_or_else(|| Error::Other("delete: category has no id".into()))?;
                    store::delete_category(conn, id)?;
                    Ok(name)
                }
                MgrEntity::Tag => {
                    let name = self
                        .tags
                        .get(self.mgr_selected)
                        .cloned()
                        .ok_or_else(|| Error::Other("delete: no tag selected".into()))?;
                    let id = self.tag_id_at(self.mgr_selected)?;
                    store::delete_tag(conn, id)?;
                    Ok(name)
                }
            }
        })();
        match res {
            Ok(n) => {
                self.save()?;
                self.reload()?;
                self.mgr_clamp(entity);
                self.message = Some(format!("deleted \"{n}\""));
            }
            Err(e) => {
                self.message = Some(format!("delete failed: {e}"));
            }
        }
        Ok(())
    }

    /// 查 `tags` 列表中第 `idx` 项对应的标签 id(需从 db 查 name→id)。
    fn tag_id_at(&self, idx: usize) -> Result<i64> {
        let name = self
            .tags
            .get(idx)
            .ok_or_else(|| Error::Other("tag: index out of range".into()))?;
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| Error::Other("tag: no database".into()))?;
        let tags = store::list_tags(db.conn())?;
        tags.into_iter()
            .find(|t| &t.name == name)
            .map(|t| t.id)
            .ok_or_else(|| Error::Other("tag: not found".into()))
    }

    // -----------------------------------------------------------------------
    // 附件管理(Attachments)
    // -----------------------------------------------------------------------

    /// 进入附件管理:锁定当前选中 item,刷新附件元数据列表。
    fn enter_attachments(&mut self) {
        let Some(item) = self.selected_item() else {
            self.message = Some("no item selected".into());
            return;
        };
        let id = match item.id {
            Some(id) => id,
            None => {
                self.message = Some("no item id".into());
                return;
            }
        };
        self.att_item_id = Some(id);
        self.att_selected = 0;
        self.att_edit = None;
        self.input.clear();
        self.mode = Mode::Attachments;
        if let Err(e) = self.reload_att() {
            self.message = Some(format!("load attachments failed: {e}"));
            return;
        }
        self.message = Some("a:add  e:export  x:del  Esc:back".into());
    }

    /// 刷新 `att_list`(不含 blob);夹紧 `att_selected`。
    fn reload_att(&mut self) -> Result<()> {
        let item_id = match self.att_item_id {
            Some(id) => id,
            None => {
                self.att_list.clear();
                self.att_selected = 0;
                return Ok(());
            }
        };
        let Some(ref db) = self.db else {
            self.att_list.clear();
            return Ok(());
        };
        let conn = db.conn();
        let mut stmt = conn.prepare(
            "SELECT id, filename, mime_type, size FROM attachments
             WHERE item_id = ?1 ORDER BY id ASC",
        )?;
        let list: Vec<AttMeta> = stmt
            .query_map(rusqlite::params![item_id], |r| {
                Ok(AttMeta {
                    id: r.get::<_, i64>(0)?,
                    filename: r.get::<_, String>(1)?,
                    mime_type: r.get::<_, Option<String>>(2)?,
                    size: r.get::<_, i64>(3)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        self.att_list = list;
        if self.att_selected >= self.att_list.len() {
            self.att_selected = self.att_list.len().saturating_sub(1);
        }
        Ok(())
    }

    /// Attachments 模式键分发:编辑态 / 浏览态。
    fn handle_attachments(&mut self, key: KeyEvent) -> Result<Action> {
        match self.att_edit {
            Some(_) => self.handle_att_edit(key),
            None => self.handle_att_browse(key),
        }
    }

    /// 浏览态:移动 / add / export / delete / 返回。
    fn handle_att_browse(&mut self, key: KeyEvent) -> Result<Action> {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if !self.att_list.is_empty() && self.att_selected + 1 < self.att_list.len() {
                    self.att_selected += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.att_selected > 0 {
                    self.att_selected -= 1;
                }
            }
            KeyCode::Char('a') => {
                self.att_edit = Some(AttEdit::Add);
                self.input.clear();
                self.message = Some("add: type file path, Enter to confirm".into());
            }
            KeyCode::Char('e') => {
                if self.att_list.is_empty() {
                    self.message = Some("nothing to export".into());
                } else {
                    self.att_edit = Some(AttEdit::Export);
                    self.input.clear();
                    self.message = Some("export: type output path, Enter to confirm".into());
                }
            }
            KeyCode::Char('x') => {
                self.att_delete()?;
            }
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.input.clear();
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    /// 编辑态(add/export):字符 / 退格 / 提交 / 取消。
    fn handle_att_edit(&mut self, key: KeyEvent) -> Result<Action> {
        match key.code {
            KeyCode::Char(c) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(Action::Continue);
                }
                self.input.push(c);
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Enter => {
                let edit = self.att_edit;
                match edit {
                    Some(AttEdit::Add) => self.att_add()?,
                    Some(AttEdit::Export) => self.att_export()?,
                    None => {}
                }
            }
            KeyCode::Esc => {
                self.att_edit = None;
                self.input.clear();
                self.message = Some("a:add  e:export  x:del  Esc:back".into());
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    /// 新增附件:读文件 → insert → save → reload。
    fn att_add(&mut self) -> Result<()> {
        let path = self.input.clone();
        let item_id = self
            .att_item_id
            .ok_or_else(|| Error::Other("attachments: no item id".into()))?;
        let res = (|| -> Result<(String, i64)> {
            let p = std::path::Path::new(&path);
            let blob = std::fs::read(p).map_err(|e| {
                Error::Other(format!("read {path:?} failed: {e}"))
            })?;
            let filename = p
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| path.clone());
            let mime_type = crate::cli::guess_mime(p);
            let size = blob.len() as i64;
            let db = self
                .db
                .as_ref()
                .ok_or_else(|| Error::Other("attachments: no database".into()))?;
            let conn = db.conn();
            let mut att = crate::model::Attachment {
                id: None,
                item_id,
                filename: filename.clone(),
                mime_type,
                size: 0,
                blob,
            };
            store::insert_attachment(conn, &mut att)?;
            Ok((filename, size))
        })();
        match res {
            Ok((name, size)) => {
                self.save()?;
                self.reload_att()?;
                self.att_edit = None;
                self.input.clear();
                self.message = Some(format!("attached {name} ({size})"));
            }
            Err(e) => {
                // 不退出编辑态,允许修正路径。
                self.message = Some(format!("add failed: {e}"));
            }
        }
        Ok(())
    }

    /// 导出附件:get(校验归属) → 写文件。
    fn att_export(&mut self) -> Result<()> {
        let out_path = self.input.clone();
        let item_id = self
            .att_item_id
            .ok_or_else(|| Error::Other("attachments: no item id".into()))?;
        let Some(att) = self.att_list.get(self.att_selected).cloned() else {
            self.message = Some("no attachment selected".into());
            self.att_edit = None;
            self.input.clear();
            return Ok(());
        };
        let res = (|| -> Result<(String, i64)> {
            let db = self
                .db
                .as_ref()
                .ok_or_else(|| Error::Other("attachments: no database".into()))?;
            let conn = db.conn();
            let got = store::get_attachment(conn, att.id)?
                .ok_or_else(|| Error::Other("export: attachment not found".into()))?;
            if got.item_id != item_id {
                return Err(Error::Other("export: attachment belongs to another item".into()));
            }
            std::fs::write(&out_path, &got.blob).map_err(|e| {
                Error::Other(format!("write {out_path:?} failed: {e}"))
            })?;
            Ok((got.filename, got.size))
        })();
        match res {
            Ok((name, size)) => {
                self.message = Some(format!("wrote {name} ({size})"));
                self.att_edit = None;
                self.input.clear();
            }
            Err(e) => {
                self.message = Some(format!("export failed: {e}"));
            }
        }
        Ok(())
    }

    /// 删除当前选中附件。
    fn att_delete(&mut self) -> Result<()> {
        let Some(att) = self.att_list.get(self.att_selected).cloned() else {
            self.message = Some("no attachment selected".into());
            return Ok(());
        };
        let name = att.filename.clone();
        let res = (|| -> Result<()> {
            let db = self
                .db
                .as_ref()
                .ok_or_else(|| Error::Other("delete: no database".into()))?;
            store::delete_attachment(db.conn(), att.id)?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                self.save()?;
                self.reload_att()?;
                self.message = Some(format!("deleted {name}"));
            }
            Err(e) => {
                self.message = Some(format!("delete failed: {e}"));
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // ImportTotp(2FA 配置弹窗)
    // -----------------------------------------------------------------------

    /// 进入 TOTP 导入弹窗:记下来源(NewItem/EditItem)以便完成后恢复,清空输入缓冲。
    fn enter_import_totp(&mut self, is_new: bool) {
        self.totp_return = if is_new {
            TotpReturn::NewItem
        } else {
            TotpReturn::EditItem
        };
        self.input.clear();
        self.input_mask = false;
        self.mode = Mode::ImportTotp;
        self.message =
            Some("paste otpauth:// · local image path · or http(s)/data: url".into());
    }

    /// ImportTotp 按键:字符 / 退格 / Enter 提交 / Esc 取消。
    fn handle_import_totp(&mut self, key: KeyEvent) -> Result<Action> {
        match key.code {
            KeyCode::Char(c) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(Action::Continue);
                }
                self.input.push(c);
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Enter => self.submit_import_totp()?,
            KeyCode::Esc => {
                self.input.clear();
                self.restore_editor_mode();
                self.message = Some("totp import canceled".into());
            }
            _ => {}
        }
        Ok(Action::Continue)
    }

    /// 提交 ImportTotp:自动识别来源 → 解析成 otpauth URI → 写入草稿首个 Totp 字段。
    ///
    /// 远程 URL 取图走阻塞式 `crate::cli::fetch_url_bytes`(15s 超时),期间界面会
    /// 短暂冻结;成功才返回编辑器,失败则留在弹窗内允许修正输入。
    fn submit_import_totp(&mut self) -> Result<()> {
        let input = self.input.clone();
        let res = (|| -> Result<()> {
            let uri = Self::resolve_totp_input(&input)?
                .ok_or_else(|| Error::Other("totp: empty input".into()))?;
            let ed = self
                .editor
                .as_mut()
                .ok_or_else(|| Error::Other("totp: no editor draft".into()))?;
            Self::apply_totp_to_draft(&mut ed.draft, &uri)?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                self.input.clear();
                self.restore_editor_mode();
                self.message = Some("totp secret set · Enter to save".into());
            }
            Err(e) => {
                self.message = Some(format!("totp import failed: {e}"));
            }
        }
        Ok(())
    }

    /// 按 [`totp_return`](Self::totp_return) 恢复编辑器模式(NewItem 需回填 template_id)。
    fn restore_editor_mode(&mut self) {
        let tpl = self
            .editor
            .as_ref()
            .map(|e| e.draft.template_id.clone())
            .unwrap_or_default();
        self.mode = match self.totp_return {
            TotpReturn::NewItem => Mode::NewItem(tpl),
            TotpReturn::EditItem => Mode::EditItem,
        };
    }

    /// 自动识别单条输入是哪种 TOTP 来源,复用 [`crate::cli::resolve_totp_source`]:
    /// - `otpauth://` → 直接当 URI;
    /// - `http(s)://` 或 `data:` → 当远程/data 图像 URL;
    /// - 其余 → 当本地二维码图片路径(`fs::read` 失败会给出友好错误)。
    fn resolve_totp_input(input: &str) -> Result<Option<String>> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        if trimmed.starts_with("otpauth://") {
            return crate::cli::resolve_totp_source(Some(trimmed), None, None);
        }
        if trimmed.starts_with("http://")
            || trimmed.starts_with("https://")
            || trimmed.starts_with("data:")
        {
            return crate::cli::resolve_totp_source(None, None, Some(trimmed));
        }
        crate::cli::resolve_totp_source(None, Some(std::path::Path::new(trimmed)), None)
    }

    /// 把 otpauth URI 的 secret 写入草稿首个 `kind=Totp` 字段;无则补一个。
    /// (CLI 的 run_add/run_edit 在缺失时报错;TUI 选择自动补字段,对 note 等模板更友好。)
    fn apply_totp_to_draft(draft: &mut Item, uri: &str) -> Result<()> {
        let secret = crate::cli::parse_otpauth(uri)?;
        if let Some(f) = draft.fields.iter_mut().find(|f| f.kind == FieldKind::Totp) {
            f.value = secret;
        } else {
            draft.fields.push(crate::model::Field {
                name: "totp".into(),
                value: secret,
                kind: FieldKind::Totp,
                protected: true,
            });
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // 编辑器辅助
    // -----------------------------------------------------------------------

    /// 进入 NewItem 编辑器:给定 template_id,草稿为空标题 + 该模板实例化的空字段。
    fn start_editor_new(&mut self, template_id: &str) {
        let fields = instantiate_template(template_id).unwrap_or_default();
        let draft = Item {
            id: None,
            template_id: template_id.to_string(),
            title: String::new(),
            category_id: None,
            fields,
            favorite: false,
            tags: Vec::new(),
            created_at: 0,
            updated_at: 0,
        };
        self.editor = Some(EditorState {
            draft,
            field: Cursor::Title,
        });
        self.mode = Mode::NewItem(template_id.to_string());
    }

    /// 进入 EditItem 编辑器:复制选中 item 为草稿。
    fn start_editor_edit(&mut self) {
        let Some(item) = self.items.get(self.selected).cloned() else {
            self.message = Some("no item selected".into());
            return;
        };
        self.editor = Some(EditorState {
            draft: item,
            field: Cursor::Title,
        });
        self.mode = Mode::EditItem;
    }

    /// 保存新建条目:insert_item + save + reload。
    fn save_new_item(&mut self, mut draft: Item) -> Result<()> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| Error::Other("save_new: no database".into()))?;
        store::insert_item(db.conn(), &mut draft)?;
        self.save()?;
        self.reload()?;
        Ok(())
    }

    /// 保存编辑条目:update_item + save + reload。
    fn save_edit_item(&mut self, draft: Item) -> Result<()> {
        let db = self
            .db
            .as_ref()
            .ok_or_else(|| Error::Other("save_edit: no database".into()))?;
        store::update_item(db.conn(), &draft)?;
        self.save()?;
        self.reload()?;
        Ok(())
    }

    /// 写入一个字符到当前光标位置(Title 或某字段)。
    fn write_field(draft: &mut Item, cur: &Cursor, c: char) {
        match cur {
            Cursor::Title => draft.title.push(c),
            Cursor::Field(i) => {
                if let Some(f) = draft.fields.get_mut(*i) {
                    f.value.push(c);
                }
            }
        }
    }

    /// 退格删除当前光标位置末尾字符。
    fn backspace_field(draft: &mut Item, cur: &Cursor) {
        match cur {
            Cursor::Title => {
                draft.title.pop();
            }
            Cursor::Field(i) => {
                if let Some(f) = draft.fields.get_mut(*i) {
                    f.value.pop();
                }
            }
        }
    }

    /// 下一个光标(循环):序列 = [Title, Field(0..n)]。
    fn next_cursor(n_fields: usize, cur: &Cursor) -> Cursor {
        let total = 1 + n_fields; // Title + n fields
        if total == 0 {
            return Cursor::Title;
        }
        let idx = cur_index(cur);
        let next = (idx + 1) % total.max(1);
        index_to_cursor(next)
    }

    /// 上一个光标(循环)。
    fn prev_cursor(n_fields: usize, cur: &Cursor) -> Cursor {
        let total = 1 + n_fields;
        if total == 0 {
            return Cursor::Title;
        }
        let idx = cur_index(cur);
        let prev = if idx == 0 {
            total.saturating_sub(1)
        } else {
            idx - 1
        };
        index_to_cursor(prev)
    }
}

/// `Cursor` → 线性索引(Title=0, Field(i)=i+1)。
fn cur_index(cur: &Cursor) -> usize {
    match cur {
        Cursor::Title => 0,
        Cursor::Field(i) => *i + 1,
    }
}

/// 线性索引 → `Cursor`。
fn index_to_cursor(idx: usize) -> Cursor {
    if idx == 0 {
        Cursor::Title
    } else {
        Cursor::Field(idx - 1)
    }
}

/// 把一个 `&str` 喂给 `KeyCode::Char` 序列的辅助(测试用)。
#[allow(dead_code)]
fn str_to_keys(s: &str) -> Vec<KeyEvent> {
    s.chars()
        .map(|c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
        .collect()
}

// Helper to make a KeyDown KeyEvent in tests.
#[cfg(test)]
fn key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

#[cfg(test)]
fn key_code(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

// ---------------------------------------------------------------------------
// 单元测试(纯逻辑,避开慢 KDF)
// ---------------------------------------------------------------------------


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::db::Database;
    use crate::model::FieldKind;
    use crate::store;
    use crate::test_support::{mk_item, mk_password_item};

    /// 构造一个内存库 + 插入若干 password item 的 App(从 from_unlocked 入口)。
    fn app_with_items(n: usize) -> App {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();
        for i in 0..n {
            let mut it = mk_item(
                "password",
                &format!("item-{i}"),
                &[
                    ("username", &format!("user-{i}"), FieldKind::Text),
                    ("password", &format!("pw-{i}"), FieldKind::Secret),
                    ("url", "", FieldKind::Text),
                    ("totp", "", FieldKind::Totp),
                    ("notes", "", FieldKind::Multiline),
                ],
            );
            store::insert_item(conn, &mut it).unwrap();
        }
        App::from_unlocked(db, std::path::PathBuf::from("/tmp/zkv_unused.zkv"), "dummy".into())
            .unwrap()
    }

    #[test]
    fn from_unlocked_loads_items() {
        let app = app_with_items(3);
        assert_eq!(app.items.len(), 3);
        assert!(matches!(app.mode, Mode::Normal));
        assert!(app.db.is_some());
    }

    #[test]
    fn normal_n_enters_pick_template() {
        let mut app = app_with_items(1);
        let act = app.handle_key(key('n')).unwrap();
        assert_eq!(act, Action::Continue);
        assert!(matches!(app.mode, Mode::PickTemplate));
        assert_eq!(app.tpl_selected, 0);
    }

    #[test]
    fn pick_template_jk_and_enter_starts_editor() {
        let mut app = app_with_items(0);
        // n -> PickTemplate
        app.handle_key(key('n')).unwrap();
        assert!(matches!(app.mode, Mode::PickTemplate));
        // j 移动选中(模板清单 8 个)
        app.handle_key(key('j')).unwrap();
        assert_eq!(app.tpl_selected, 1);
        // Enter 进入编辑器,template_id = builtin_templates()[1].id = "note"
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(matches!(app.mode, Mode::NewItem(_)));
        let ed = app.editor.as_ref().unwrap();
        assert_eq!(ed.draft.template_id, "note");
        // note 模板字段:format + content
        assert_eq!(ed.draft.fields.len(), 2);
    }

    #[test]
    fn pick_template_esc_returns_normal() {
        let mut app = app_with_items(0);
        app.handle_key(key('n')).unwrap();
        app.handle_key(key_code(KeyCode::Esc)).unwrap();
        assert!(matches!(app.mode, Mode::Normal));
    }

    #[test]
    fn create_item_increments_count() {
        let path = tmp_path("create_item");
        cleanup(&path);
        let kdf = KdfParams { m_kib: 4096, t_cost: 1, p_cost: 1 };
        crate::vault::create_with_params(&path, "pw", &kdf).unwrap();

        let db = crate::vault::unlock(&path, "pw").unwrap();
        {
            let conn = db.conn();
            let mut seed = mk_password_item("u", "p");
            seed.title = "seed".into();
            store::insert_item(conn, &mut seed).unwrap();
        }
        let mut app = App::from_unlocked(db, path.clone(), "pw".into()).unwrap();
        let before = app.items.len();

        // n -> PickTemplate -> Enter(password 是首个) -> NewItem
        app.handle_key(key('n')).unwrap();
        assert!(matches!(app.mode, Mode::PickTemplate));
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(matches!(app.mode, Mode::NewItem(_)));
        // 输入标题 "new"
        for c in "new".chars() {
            app.handle_key(key(c)).unwrap();
        }
        // Tab 到第一个字段(username),输入 "bob"
        app.handle_key(key_code(KeyCode::Tab)).unwrap();
        for c in "bob".chars() {
            app.handle_key(key(c)).unwrap();
        }
        // Enter 保存
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(matches!(app.mode, Mode::Normal));
        assert_eq!(app.items.len(), before + 1);
        // 验证落盘后再解锁仍能看到
        let db2 = crate::vault::unlock(&path, "pw").unwrap();
        let cnt = db2
            .conn()
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get::<_, i64>(0))
            .unwrap();
        assert_eq!(cnt as usize, before + 1);
        cleanup(&path);
    }

    #[test]
    fn normal_q_returns_quit() {
        let mut app = app_with_items(1);
        let act = app.handle_key(key('q')).unwrap();
        assert_eq!(act, Action::Quit);
        assert!(app.quit);
    }

    #[test]
    fn normal_l_locks_clears_db() {
        let mut app = app_with_items(2);
        app.handle_key(key('l')).unwrap();
        assert!(app.db.is_none());
        assert!(app.master_key.is_none());
        assert!(app.items.is_empty());
        assert!(matches!(app.mode, Mode::PromptPassphrase(PassKind::Open)));
    }

    #[test]
    fn lock_keeps_path_and_enters_prompt_for_reunlock() {
        let mut app = app_with_items(1);
        let kept_path = app.path.clone();
        app.lock();
        assert_eq!(app.path, kept_path, "lock must not clear path");
        assert!(matches!(app.mode, Mode::PromptPassphrase(PassKind::Open)));
        assert!(app.db.is_none());
        assert!(app.input_mask, "lock should enable passphrase masking");
    }

    #[test]
    fn boot_async_unlock_completes() {
        let path = tmp_path("boot_async_unlock");
        cleanup(&path);
        let kdf = KdfParams { m_kib: 4096, t_cost: 1, p_cost: 1 };
        crate::vault::create_with_params(&path, "pw", &kdf).unwrap();
        let mut app = App::for_open(path.clone());
        app.input = "pw".into();
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(matches!(app.mode, Mode::Booting), "Enter should enter Booting");
        // pump 直到完成(fast KDF 很快);最多等 ~2s 防死循环。
        for _ in 0..2000 {
            app.pump_boot().unwrap();
            if matches!(app.mode, Mode::Normal) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(matches!(app.mode, Mode::Normal));
        assert!(app.db.is_some());
        cleanup(&path);
    }

    #[test]
    fn boot_async_wrong_pass_returns_to_prompt() {
        let path = tmp_path("boot_async_wrong");
        cleanup(&path);
        let kdf = KdfParams { m_kib: 4096, t_cost: 1, p_cost: 1 };
        crate::vault::create_with_params(&path, "pw", &kdf).unwrap();
        let mut app = App::for_open(path.clone());
        app.input = "wrong".into();
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(matches!(app.mode, Mode::Booting));
        for _ in 0..2000 {
            app.pump_boot().unwrap();
            if !matches!(app.mode, Mode::Booting) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(matches!(app.mode, Mode::PromptPassphrase(PassKind::Open)));
        assert!(app.message.is_some());
        cleanup(&path);
    }

    #[test]
    fn normal_y_does_not_panic_without_clipboard() {
        let mut app = app_with_items(1);
        app.selected = 0;
        app.handle_key(key('y')).unwrap();
        assert!(app.message.is_some());
    }

    #[test]
    fn normal_o_handles_no_totp() {
        // password 条目 totp 字段为空 → 按 o 应不 panic 且设置 message。
        let mut app = app_with_items(1);
        app.selected = 0;
        app.handle_key(key('o')).unwrap();
        assert!(app.message.is_some());
        assert!(
            app.message.as_deref().unwrap_or("").contains("no totp secret"),
            "expected no-totp hint, got {:?}",
            app.message
        );
    }

    #[test]
    fn copy_totp_finds_totp_field() {
        // 构造一个含非空 totp 字段的条目;按 o 应尝试生成(可能因剪贴板失败但非「no secret」)。
        let db = Database::open_in_memory().unwrap();
        {
            let conn = db.conn();
            let mut it = mk_item(
                "password",
                "T",
                &[
                    ("username", "u", FieldKind::Text),
                    ("password", "p", FieldKind::Secret),
                    ("url", "", FieldKind::Text),
                    ("totp", "JBSWY3DPEHPK3PXP", FieldKind::Totp),
                    ("notes", "", FieldKind::Multiline),
                ],
            );
            store::insert_item(conn, &mut it).unwrap();
        }
        let mut app =
            App::from_unlocked(db, std::path::PathBuf::from("/tmp/zkv_unused.zkv"), "x".into())
                .unwrap();
        app.selected = 0;
        app.copy_totp_of_selected();
        // 有合法 secret:不是「no totp secret」提示。
        assert!(
            !app.message.as_deref().unwrap_or("").contains("no totp secret"),
            "got {:?}",
            app.message
        );
    }

    #[test]
    fn normal_jk_moves_selection() {
        let mut app = app_with_items(3);
        app.selected = 0;
        app.handle_key(key('j')).unwrap();
        assert_eq!(app.selected, 1);
        app.handle_key(key('j')).unwrap();
        assert_eq!(app.selected, 2);
        app.handle_key(key('j')).unwrap();
        assert_eq!(app.selected, 2);
        app.handle_key(key('k')).unwrap();
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn search_filters_items() {
        let db = Database::open_in_memory().unwrap();
        {
            let conn = db.conn();
            let mut a = mk_item(
                "password",
                "GitHub",
                &[("username", "u", FieldKind::Text), ("password", "p", FieldKind::Secret)],
            );
            let mut b = mk_item(
                "password",
                "GitLab",
                &[("username", "u", FieldKind::Text), ("password", "p", FieldKind::Secret)],
            );
            store::insert_item(conn, &mut a).unwrap();
            store::insert_item(conn, &mut b).unwrap();
        }
        let mut app =
            App::from_unlocked(db, std::path::PathBuf::from("/tmp/zkv_unused.zkv"), "x".into())
                .unwrap();
        assert_eq!(app.items.len(), 2);

        app.handle_key(key('/')).unwrap();
        assert!(matches!(app.mode, Mode::Search));
        for c in "github".chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(matches!(app.mode, Mode::Normal));
        assert_eq!(app.items.len(), 1, "应只命中 GitHub");
        assert_eq!(app.filter.query.as_deref(), Some("github"));
    }

    #[test]
    fn search_esc_does_not_apply() {
        let mut app = app_with_items(3);
        app.handle_key(key('/')).unwrap();
        for c in "zzz".chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Esc)).unwrap();
        assert!(matches!(app.mode, Mode::Normal));
        assert!(app.filter.query.is_none());
        assert_eq!(app.items.len(), 3);
    }

    #[test]
    fn confirm_delete_y_removes_item() {
        let path = tmp_path("del_item");
        cleanup(&path);
        let kdf = KdfParams { m_kib: 4096, t_cost: 1, p_cost: 1 };
        crate::vault::create_with_params(&path, "pw", &kdf).unwrap();
        let db = crate::vault::unlock(&path, "pw").unwrap();
        {
            let conn = db.conn();
            let mut it = mk_password_item("u", "p");
            it.title = "to-delete".into();
            store::insert_item(conn, &mut it).unwrap();
        }
        let mut app = App::from_unlocked(db, path.clone(), "pw".into()).unwrap();
        assert_eq!(app.items.len(), 1);

        app.handle_key(key('x')).unwrap();
        assert!(matches!(app.mode, Mode::ConfirmDelete));
        app.handle_key(key('y')).unwrap();
        assert!(matches!(app.mode, Mode::Normal));
        assert_eq!(app.items.len(), 0);
        cleanup(&path);
    }

    #[test]
    fn editor_tab_cycles_cursors() {
        // password 模板 5 字段:序列 = [Title, Field(0..5)],共 6 个光标位。
        let n = 5;
        // Title -> Field(0)
        let next = App::next_cursor(n, &Cursor::Title);
        assert_eq!(next, Cursor::Field(0));
        // 末位 Field(4) -> Title(循环)
        let wrap = App::next_cursor(n, &Cursor::Field(4));
        assert_eq!(wrap, Cursor::Title);
        // prev: Title -> Field(4)
        let prev = App::prev_cursor(n, &Cursor::Title);
        assert_eq!(prev, Cursor::Field(4));
    }

    #[test]
    fn write_and_backspace_field_by_cursor() {
        let mut draft = mk_item(
            "password",
            "",
            &[
                ("username", "", FieldKind::Text),
                ("password", "", FieldKind::Secret),
            ],
        );
        // Title
        App::write_field(&mut draft, &Cursor::Title, 'A');
        assert_eq!(draft.title, "A");
        App::backspace_field(&mut draft, &Cursor::Title);
        assert_eq!(draft.title, "");
        // Field(0) = username
        App::write_field(&mut draft, &Cursor::Field(0), 'b');
        assert_eq!(draft.fields[0].value, "b");
        // Field(1) = password
        App::write_field(&mut draft, &Cursor::Field(1), 'x');
        assert_eq!(draft.fields[1].value, "x");
        App::backspace_field(&mut draft, &Cursor::Field(1));
        assert_eq!(draft.fields[1].value, "");
        // 越界光标不 panic
        App::write_field(&mut draft, &Cursor::Field(99), 'z');
        App::backspace_field(&mut draft, &Cursor::Field(99));
    }

    // ---- ImportTotp(2FA 配置弹窗)----

    #[test]
    fn resolve_totp_input_routes_otpauth_uri() {
        let uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
        // otpauth:// 原样透传。
        let got = App::resolve_totp_input(uri).unwrap();
        assert_eq!(got.as_deref(), Some(uri));
    }

    #[test]
    fn resolve_totp_input_empty_is_none() {
        assert_eq!(App::resolve_totp_input("").unwrap(), None);
        assert_eq!(App::resolve_totp_input("   ").unwrap(), None);
    }

    #[test]
    fn resolve_totp_input_local_path_missing_errors() {
        // 非 otpauth / 非 url → 当本地路径;文件不存在应报错(而非静默 None)。
        let res = App::resolve_totp_input("/definitely/not/a/real/path/12345.png");
        assert!(res.is_err());
    }

    #[test]
    fn apply_totp_to_draft_overwrites_totp_field() {
        let mut draft = mk_item(
            "password",
            "",
            &[
                ("username", "", FieldKind::Text),
                ("password", "", FieldKind::Secret),
                ("totp", "OLDFIELD", FieldKind::Totp),
            ],
        );
        // 首个 Totp 字段被覆盖,字段数不变。
        App::apply_totp_to_draft(&mut draft, "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP").unwrap();
        let totp = draft
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .unwrap();
        assert_eq!(totp.value, "JBSWY3DPEHPK3PXP");
        assert_eq!(draft.fields.len(), 3);
    }

    #[test]
    fn apply_totp_to_draft_adds_field_when_absent() {
        // note 模板无 Totp 字段 → 自动补一个。
        let mut draft = mk_item("note", "", &[("content", "", FieldKind::Multiline)]);
        let before = draft.fields.len();
        App::apply_totp_to_draft(&mut draft, "otpauth://totp/X?secret=GEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(draft.fields.len(), before + 1);
        let totp = draft
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .unwrap();
        assert_eq!(totp.value, "GEZDGNBVGY3TQOJQ");
        assert!(totp.protected);
    }

    #[test]
    fn editor_ctrl_t_import_totp_sets_secret() {
        let mut app = app_with_items(1);
        // e -> EditItem(选中 item 含空 totp 字段)。
        app.handle_key(key('e')).unwrap();
        assert!(matches!(app.mode, Mode::EditItem));
        // Ctrl+T -> ImportTotp 弹窗。
        let ctrl_t = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::CONTROL);
        app.handle_key(ctrl_t).unwrap();
        assert!(matches!(app.mode, Mode::ImportTotp));
        // 粘贴 otpauth URI 并提交。
        let uri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP";
        for c in uri.chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        // 返回编辑器;草稿首个 Totp 字段已写入 secret。
        assert!(matches!(app.mode, Mode::EditItem));
        let ed = app.editor.as_ref().unwrap();
        let totp = ed
            .draft
            .fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .unwrap();
        assert_eq!(totp.value, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn import_totp_esc_cancels_back_to_editor() {
        let mut app = app_with_items(1);
        app.handle_key(key('e')).unwrap();
        let ctrl_t = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::CONTROL);
        app.handle_key(ctrl_t).unwrap();
        assert!(matches!(app.mode, Mode::ImportTotp));
        app.handle_key(key_code(KeyCode::Esc)).unwrap();
        // 取消返回编辑器;totp 字段保持原值(空)。
        assert!(matches!(app.mode, Mode::EditItem));
        let ed = app.editor.as_ref().unwrap();
        assert!(ed.draft.totp_value().unwrap_or_default().is_empty());
    }

    #[test]
    fn import_totp_bad_input_stays_in_modal() {
        let mut app = app_with_items(1);
        app.handle_key(key('e')).unwrap();
        let ctrl_t = KeyEvent::new(KeyCode::Char('t'), KeyModifiers::CONTROL);
        app.handle_key(ctrl_t).unwrap();
        // 不是 otpauth/也不是存在的文件 → 解析失败,留在弹窗。
        for c in "garbage input".chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(matches!(app.mode, Mode::ImportTotp));
        assert!(app.message.as_deref().unwrap_or("").contains("failed"));
    }

    #[test]
    fn passphrase_wrong_stays_in_prompt() {
        let path = tmp_path("wrong_pass");
        cleanup(&path);
        let kdf = KdfParams { m_kib: 4096, t_cost: 1, p_cost: 1 };
        crate::vault::create_with_params(&path, "correct", &kdf).unwrap();

        let mut app = App::for_open(path.clone());
        for c in "wrong".chars() {
            app.handle_key(key(c)).unwrap();
        }
        let act = app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert_eq!(act, Action::Continue);
        assert!(matches!(app.mode, Mode::Booting));
        // 异步解锁:pump 直到离开 Booting(错误口令 → 回口令态)。
        for _ in 0..2000 {
            app.pump_boot().unwrap();
            if !matches!(app.mode, Mode::Booting) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(matches!(app.mode, Mode::PromptPassphrase(PassKind::Open)));
        assert!(app.db.is_none());
        assert!(app.message.is_some());
        cleanup(&path);
    }

    #[test]
    fn passphrase_correct_opens() {
        let path = tmp_path("right_pass");
        cleanup(&path);
        let kdf = KdfParams { m_kib: 4096, t_cost: 1, p_cost: 1 };
        crate::vault::create_with_params(&path, "correct", &kdf).unwrap();

        let mut app = App::for_open(path.clone());
        for c in "correct".chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(matches!(app.mode, Mode::Booting));
        // 异步解锁:pump 直到完成(正确口令 → Normal)。
        for _ in 0..2000 {
            app.pump_boot().unwrap();
            if matches!(app.mode, Mode::Normal) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(matches!(app.mode, Mode::Normal));
        assert!(app.db.is_some());
        cleanup(&path);
    }

    // ---- 管理模式(CategoryMgr / TagMgr)测试 ----

    fn app_with_path(tag: &str) -> (App, std::path::PathBuf) {
        let path = tmp_path(tag);
        cleanup(&path);
        let kdf = KdfParams { m_kib: 4096, t_cost: 1, p_cost: 1 };
        crate::vault::create_with_params(&path, "pw", &kdf).unwrap();
        let db = crate::vault::unlock(&path, "pw").unwrap();
        let app = App::from_unlocked(db, path.clone(), "pw".into()).unwrap();
        (app, path)
    }

    #[test]
    fn mgr_enter_resets_state() {
        let (mut app, _p) = app_with_path("mgr_enter");
        app.mgr_selected = 9;
        app.mgr_edit = Some(MgrEdit::Add);
        app.input = "junk".into();
        app.handle_key(key('c')).unwrap();
        assert!(matches!(app.mode, Mode::CategoryMgr));
        assert_eq!(app.mgr_selected, 0);
        assert_eq!(app.mgr_edit, None);
        assert!(app.input.is_empty());
    }

    #[test]
    fn category_mgr_add_works() {
        let (mut app, path) = app_with_path("cat_add");
        app.handle_key(key('c')).unwrap();
        assert!(matches!(app.mode, Mode::CategoryMgr));
        app.handle_key(key('a')).unwrap();
        assert_eq!(app.mgr_edit, Some(MgrEdit::Add));
        for c in "Work".chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(app.categories.iter().any(|c| c.name == "Work"));
        assert!(matches!(app.mode, Mode::CategoryMgr));
        assert_eq!(app.mgr_edit, None);
        let db2 = crate::vault::unlock(&path, "pw").unwrap();
        let cats = store::list_categories(db2.conn()).unwrap();
        assert!(cats.iter().any(|c| c.name == "Work"));
        cleanup(&path);
    }

    #[test]
    fn category_mgr_add_empty_name_aborts() {
        let (mut app, path) = app_with_path("cat_add_empty");
        app.handle_key(key('c')).unwrap();
        app.handle_key(key('a')).unwrap();
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(app.categories.is_empty());
        assert!(app.message.as_deref().unwrap_or("").contains("empty"));
        cleanup(&path);
    }

    #[test]
    fn category_mgr_rename_works() {
        let (mut app, path) = app_with_path("cat_rename");
        {
            let conn = app.db.as_ref().unwrap().conn();
            let mut cat = crate::model::Category {
                id: None,
                name: "Old".into(),
                parent_id: None,
                sort_order: 0,
            };
            store::insert_category(conn, &mut cat).unwrap();
        }
        app.reload().unwrap();
        app.mgr_clamp(MgrEntity::Category);
        app.handle_key(key('c')).unwrap();
        app.mgr_selected = 0;
        app.handle_key(key('r')).unwrap();
        assert_eq!(app.mgr_edit, Some(MgrEdit::Rename));
        assert_eq!(app.input, "Old");
        app.input.clear();
        for c in "New".chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(app.categories.iter().any(|c| c.name == "New"));
        assert!(!app.categories.iter().any(|c| c.name == "Old"));
        cleanup(&path);
    }

    #[test]
    fn category_mgr_delete_works() {
        let (mut app, path) = app_with_path("cat_del");
        {
            let conn = app.db.as_ref().unwrap().conn();
            let mut cat = crate::model::Category {
                id: None,
                name: "Tmp".into(),
                parent_id: None,
                sort_order: 0,
            };
            store::insert_category(conn, &mut cat).unwrap();
        }
        app.reload().unwrap();
        app.handle_key(key('c')).unwrap();
        app.mgr_selected = 0;
        app.handle_key(key('x')).unwrap();
        assert!(app.categories.is_empty());
        assert!(app.message.as_deref().unwrap_or("").contains("deleted"));
        cleanup(&path);
    }

    #[test]
    fn tag_mgr_add_works() {
        let (mut app, path) = app_with_path("tag_add");
        app.handle_key(key('t')).unwrap();
        assert!(matches!(app.mode, Mode::TagMgr));
        app.handle_key(key('a')).unwrap();
        for c in "vip".chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(app.tags.iter().any(|t| t == "vip"));
        cleanup(&path);
    }

    #[test]
    fn tag_mgr_rename_works() {
        let (mut app, path) = app_with_path("tag_rename");
        {
            let conn = app.db.as_ref().unwrap().conn();
            store::ensure_tag(conn, "old").unwrap();
        }
        app.reload().unwrap();
        app.handle_key(key('t')).unwrap();
        app.mgr_selected = 0;
        app.handle_key(key('r')).unwrap();
        assert_eq!(app.input, "old");
        app.input.clear();
        for c in "fresh".chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(app.tags.iter().any(|t| t == "fresh"));
        assert!(!app.tags.iter().any(|t| t == "old"));
        cleanup(&path);
    }

    #[test]
    fn tag_mgr_delete_works() {
        let (mut app, path) = app_with_path("tag_del");
        {
            let conn = app.db.as_ref().unwrap().conn();
            store::ensure_tag(conn, "gone").unwrap();
        }
        app.reload().unwrap();
        app.handle_key(key('t')).unwrap();
        app.mgr_selected = 0;
        app.handle_key(key('x')).unwrap();
        assert!(app.tags.is_empty());
        cleanup(&path);
    }

    #[test]
    fn mgr_edit_esc_cancels() {
        let (mut app, path) = app_with_path("mgr_esc");
        app.handle_key(key('c')).unwrap();
        app.handle_key(key('a')).unwrap();
        for c in "Z".chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Esc)).unwrap();
        assert_eq!(app.mgr_edit, None);
        assert!(app.input.is_empty());
        assert!(matches!(app.mode, Mode::CategoryMgr));
        assert!(app.categories.is_empty());
        cleanup(&path);
    }

    #[test]
    fn mgr_browse_esc_returns_normal() {
        let (mut app, _p) = app_with_path("mgr_back");
        app.handle_key(key('t')).unwrap();
        app.handle_key(key_code(KeyCode::Esc)).unwrap();
        assert!(matches!(app.mode, Mode::Normal));
    }

    #[test]
    fn mgr_browse_jk_moves_selection() {
        let (mut app, _p) = app_with_path("mgr_jk");
        {
            let conn = app.db.as_ref().unwrap().conn();
            for n in ["a", "b", "c"] {
                store::ensure_tag(conn, n).unwrap();
            }
        }
        app.reload().unwrap();
        app.handle_key(key('t')).unwrap();
        assert_eq!(app.mgr_selected, 0);
        app.handle_key(key('j')).unwrap();
        assert_eq!(app.mgr_selected, 1);
        app.handle_key(key('j')).unwrap();
        assert_eq!(app.mgr_selected, 2);
        app.handle_key(key('j')).unwrap();
        assert_eq!(app.mgr_selected, 2);
        app.handle_key(key('k')).unwrap();
        assert_eq!(app.mgr_selected, 1);
    }

    // ---- 附件管理(Attachments)测试 ----

    fn app_with_one_item(tag: &str) -> (App, std::path::PathBuf, i64) {
        let (mut app, path) = app_with_path(tag);
        let mut it = mk_password_item("u", "p");
        it.title = "att-host".into();
        let conn = app.db.as_ref().unwrap().conn();
        store::insert_item(conn, &mut it).unwrap();
        let id = it.id.unwrap();
        app.reload().unwrap();
        app.selected = 0;
        (app, path, id)
    }

    #[test]
    fn attachments_a_enters_mode_and_targets_selected() {
        let (mut app, _p, id) = app_with_one_item("att_enter");
        app.handle_key(key('a')).unwrap();
        assert!(matches!(app.mode, Mode::Attachments));
        assert_eq!(app.att_item_id, Some(id));
        assert_eq!(app.att_selected, 0);
        assert!(app.att_edit.is_none());
        assert!(app.att_list.is_empty());
    }

    #[test]
    fn attachments_a_without_item_errors() {
        let (mut app, path, _id) = app_with_one_item("att_noitem");
        {
            let conn = app.db.as_ref().unwrap().conn();
            store::delete_item(conn, app.items[0].id.unwrap()).unwrap();
        }
        app.reload().unwrap();
        app.handle_key(key('a')).unwrap();
        assert!(matches!(app.mode, Mode::Normal));
        assert!(app.message.as_deref().unwrap_or("").contains("no item"));
        cleanup(&path);
    }

    #[test]
    fn attachments_add_inserts_and_lists() {
        let (mut app, path, _id) = app_with_one_item("att_add");
        let src = std::env::temp_dir().join(format!(
            "zkv_att_src_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&src, b"hello-bytes").unwrap();

        app.handle_key(key('a')).unwrap();
        app.handle_key(key('a')).unwrap();
        assert_eq!(app.att_edit, Some(AttEdit::Add));
        for c in src.to_string_lossy().chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();

        assert_eq!(app.att_edit, None);
        assert!(app.input.is_empty());
        assert_eq!(app.att_list.len(), 1);
        let fname = src.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(app.att_list[0].filename, fname);
        assert_eq!(app.att_list[0].size, 11);
        assert!(
            app.message.as_deref().unwrap_or("").contains("attached"),
            "got {:?}",
            app.message
        );

        let db2 = crate::vault::unlock(&path, "pw").unwrap();
        let cnt: i64 = db2
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM attachments",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(cnt, 1);

        let _ = std::fs::remove_file(&src);
        cleanup(&path);
    }

    #[test]
    fn attachments_export_roundtrips_blob() {
        let (mut app, path, _id) = app_with_one_item("att_export");
        let blob = b"binary-payload-123".to_vec();
        let src = std::env::temp_dir().join(format!(
            "zkv_att_src2_{}_{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&src, &blob).unwrap();

        app.handle_key(key('a')).unwrap();
        app.handle_key(key('a')).unwrap();
        for c in src.to_string_lossy().chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert_eq!(app.att_list.len(), 1);

        let out = std::env::temp_dir().join(format!(
            "zkv_att_out_{}_{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        app.handle_key(key('e')).unwrap();
        assert_eq!(app.att_edit, Some(AttEdit::Export));
        for c in out.to_string_lossy().chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();

        assert_eq!(app.att_edit, None);
        assert!(app.message.as_deref().unwrap_or("").contains("wrote"));
        let read_back = std::fs::read(&out).unwrap();
        assert_eq!(read_back, blob);

        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&out);
        cleanup(&path);
    }

    #[test]
    fn attachments_delete_empties_list() {
        let (mut app, path, _id) = app_with_one_item("att_del");
        let src = std::env::temp_dir().join(format!(
            "zkv_att_del_{}_{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&src, b"x").unwrap();

        app.handle_key(key('a')).unwrap();
        app.handle_key(key('a')).unwrap();
        for c in src.to_string_lossy().chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert_eq!(app.att_list.len(), 1);

        app.handle_key(key('x')).unwrap();
        assert!(app.att_list.is_empty());
        assert!(app.message.as_deref().unwrap_or("").contains("deleted"));

        let _ = std::fs::remove_file(&src);
        cleanup(&path);
    }

    #[test]
    fn attachments_add_esc_cancels() {
        let (mut app, path, _id) = app_with_one_item("att_esc");
        app.handle_key(key('a')).unwrap();
        app.handle_key(key('a')).unwrap();
        for c in "nope.txt".chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Esc)).unwrap();
        assert_eq!(app.att_edit, None);
        assert!(app.input.is_empty());
        assert!(app.att_list.is_empty(), "取消不应提交");
        assert!(matches!(app.mode, Mode::Attachments));
        cleanup(&path);
    }

    #[test]
    fn attachments_jk_moves_selection() {
        let (mut app, path, _id) = app_with_one_item("att_jk");
        {
            let conn = app.db.as_ref().unwrap().conn();
            for i in 0..2 {
                let mut a = crate::model::Attachment {
                    id: None,
                    item_id: app.att_item_id.unwrap_or_else(|| app.items[0].id.unwrap()),
                    filename: format!("f{i}.bin"),
                    mime_type: None,
                    size: 0,
                    blob: vec![i],
                };
                store::insert_attachment(conn, &mut a).unwrap();
            }
        }
        app.handle_key(key('a')).unwrap();
        assert_eq!(app.att_list.len(), 2);
        assert_eq!(app.att_selected, 0);
        app.handle_key(key('j')).unwrap();
        assert_eq!(app.att_selected, 1);
        app.handle_key(key('j')).unwrap();
        assert_eq!(app.att_selected, 1);
        app.handle_key(key('k')).unwrap();
        assert_eq!(app.att_selected, 0);
        cleanup(&path);
    }

    // ---- 测试辅助:临时文件 ----
    fn tmp_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("zkv_app_{tag}_{}_{}", std::process::id(), n));
        p
    }

    fn cleanup(p: &std::path::Path) {
        let _ = std::fs::remove_file(p);
        let mut t = p.as_os_str().to_owned();
        t.push(".tmp");
        let _ = std::fs::remove_file(std::path::PathBuf::from(t));
    }
}
