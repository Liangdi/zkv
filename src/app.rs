//! 应用状态机:连接 UI 与数据层(MVC 中的 Model+Controller)。对应 PRD §8。
//!
//! ## MVC 边界
//! - **App = Model + Controller**:持有全部状态与业务逻辑。
//! - **UI = View**(SA5):只读 App 的 `pub` 字段来渲染,并把原始按键
//!   `crossterm::event::KeyEvent` 转发给 [`App::handle_key`]。UI 不做业务判断。
//!
//! 对外接口:
//! - [`App`] / [`Mode`] / [`PassKind`] / [`EditorState`] / [`Field`] / [`DataField`] / [`Action`]
//! - [`App::for_open`] / [`App::for_create`] / [`App::from_unlocked`]
//! - [`App::handle_key`] / [`App::reload`] / [`App::save`] / [`App::lock`] / [`App::selected_item`]
//!
//! 分层(L4):可依赖 `error`/`crypto`/`model`/`db`/`vault`/`store`/`search`/`clipboard`
//! 与外部 crate,**不得** `use crate::ui`。

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::clipboard;
use crate::crypto::{KdfParams, MasterKey};
use crate::db::Database;
use crate::error::{Error, Result};
use crate::model::{Item, ItemData, ItemType};
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
    /// 新建条目(编辑器)。
    NewItem(ItemType),
    /// 编辑现有条目(编辑器)。
    EditItem,
    /// 确认删除。
    ConfirmDelete,
    /// 分类管理。
    CategoryMgr,
    /// 标签管理。
    TagMgr,
}

/// 管理模式(CategoryMgr/TagMgr)中,当前是否处于文本输入态及语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgrEdit {
    /// 新增。
    Add,
    /// 改名。
    Rename,
}

/// 管理模式所操作的实体种类(供 `mgr_handle` 复用分发)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MgrEntity {
    Category,
    Tag,
}

/// 编辑器中当前正在编辑的字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    /// 标题(三类通用)。
    Title,
    /// 数据子字段(随 `ItemType` 变化)。
    Data(DataField),
}

/// 三类条目各自可编辑的子字段。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataField {
    // password
    Username,
    Password,
    Url,
    TotpSecret,
    Notes,
    // note
    Format,
    Content,
    // card
    Holder,
    Number,
    Expiry,
    Cvv,
    Bank,
    // CardNotes 复用 Notes 变体,通过 draft.item_type 区分语义。
}

/// 编辑器状态:当前草稿 + 正在编辑的字段。
#[derive(Debug, Clone)]
pub struct EditorState {
    pub draft: Item,
    pub field: Field,
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
    /// 文本输入缓冲(搜索/口令/编辑器字段共用)。
    pub input: String,
    /// 是否掩码输入(口令=true,搜索/编辑器字段=false)。
    pub input_mask: bool,
    /// 管理模式(CategoryMgr/TagMgr)中的列表选中索引。
    pub mgr_selected: usize,
    /// 管理模式当前是否在文本输入(新增/改名),及语义。
    pub mgr_edit: Option<MgrEdit>,
    /// 是否请求退出。
    pub quit: bool,
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
            input: String::new(),
            input_mask: true,
            mgr_selected: 0,
            mgr_edit: None,
            quit: false,
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
            input: String::new(),
            input_mask: true,
            mgr_selected: 0,
            mgr_edit: None,
            quit: false,
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
            input: String::new(),
            input_mask: false,
            mgr_selected: 0,
            mgr_edit: None,
            quit: false,
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

    /// 锁定:清空 db/passphrase,切回 Normal,清空 items/categories/tags。
    pub fn lock(&mut self) {
        self.db = None;
        self.master_key = None;
        self.salt = None;
        self.kdf = None;
        self.mode = Mode::Normal;
        self.items.clear();
        self.categories.clear();
        self.tags.clear();
        self.selected = 0;
        self.filter = Filter::default();
        self.input.clear();
        self.input_mask = false;
        self.editor = None;
        self.message = Some("locked".into());
    }

    /// 当前选中的 item(不可变引用)。
    pub fn selected_item(&self) -> Option<&Item> {
        self.items.get(self.selected)
    }

    /// 复制选中条目的密码字段到剪贴板,20s 后清空。
    /// 剪贴板后端不可用时仅设 message,不传播错误。
    fn copy_password_of_selected(&mut self) {
        let Some(item) = self.items.get(self.selected).cloned() else {
            self.message = Some("no item selected".into());
            return;
        };
        let pw = match &item.data {
            ItemData::Password { password, .. } => password.clone(),
            _ => {
                self.message = Some("selected item has no password".into());
                return;
            }
        };
        match clipboard::copy_and_clear_after(&pw, 20) {
            Ok(()) => self.message = Some("password copied (clears in 20s)".into()),
            Err(e) => self.message = Some(format!("clipboard unavailable: {e}")),
        }
    }

    /// 复制选中条目的 TOTP 验证码到剪贴板,20s 后清空。
    /// 非 password 类型 / 空 secret / totp 计算失败仅设 message,不传播错误。
    fn copy_totp_of_selected(&mut self) {
        let Some(item) = self.items.get(self.selected).cloned() else {
            self.message = Some("no item selected".into());
            return;
        };
        let secret = match &item.data {
            ItemData::Password { totp_secret, .. } => totp_secret.clone(),
            _ => {
                self.message = Some("no totp secret".into());
                return;
            }
        };
        if secret.is_empty() {
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
            Mode::NewItem(ty) => self.handle_editor(key, true, ty),
            Mode::EditItem => self.handle_editor(key, false, ItemType::Password),
            Mode::ConfirmDelete => self.handle_confirm_delete(key),
            Mode::CategoryMgr => self.handle_category_mgr(key),
            Mode::TagMgr => self.handle_tag_mgr(key),
        }
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
                match kind {
                    PassKind::Create => {
                        match vault::create(&path, &pass) {
                            Ok(()) => {
                                match vault::unlock_full(&path, &pass) {
                                    Ok((db, key, kdf, salt)) => {
                                        self.master_key = Some(key);
                                        self.salt = Some(salt);
                                        self.kdf = Some(kdf);
                                        self.db = Some(db);
                                        self.mode = Mode::Normal;
                                        self.reload()?;
                                        self.message = Some("vault created".into());
                                    }
                                    Err(e) => {
                                        self.message =
                                            Some(format!("unlock after create failed: {e}"));
                                    }
                                }
                            }
                            Err(e) => {
                                self.message =
                                    Some(format!("create failed: {e}"));
                            }
                        }
                    }
                    PassKind::Open => match vault::unlock_full(&path, &pass) {
                        Ok((db, key, kdf, salt)) => {
                            self.master_key = Some(key);
                            self.salt = Some(salt);
                            self.kdf = Some(kdf);
                            self.db = Some(db);
                            self.mode = Mode::Normal;
                            self.reload()?;
                            self.message = Some("unlocked".into());
                        }
                        Err(e) => {
                            // 错误口令 / 损坏:停留口令态,清空 input(已 take)。
                            self.message = Some(format!("unlock failed: {e}"));
                        }
                    },
                }
            }
            KeyCode::Esc => {
                self.quit = true;
                return Ok(Action::Quit);
            }
            _ => {}
        }
        Ok(Action::Continue)
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
                self.start_editor_new(ItemType::Password);
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
        _ty: ItemType,
    ) -> Result<Action> {
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
                ed.field = Self::next_field(&ed.draft.item_type, &ed.field);
            }
            KeyCode::Up => {
                ed.field = Self::prev_field(&ed.draft.item_type, &ed.field);
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
    // 编辑器辅助
    // -----------------------------------------------------------------------

    /// 进入 NewItem 编辑器:给定类型,草稿为空标题 + 该类型默认 data。
    fn start_editor_new(&mut self, ty: ItemType) {
        let draft = Item {
            id: None,
            item_type: ty,
            title: String::new(),
            category_id: None,
            data: default_data(ty),
            favorite: false,
            tags: Vec::new(),
            created_at: 0,
            updated_at: 0,
        };
        self.editor = Some(EditorState {
            draft,
            field: Field::Title,
        });
        self.mode = Mode::NewItem(ty);
    }

    /// 进入 EditItem 编辑器:复制选中 item 为草稿。
    fn start_editor_edit(&mut self) {
        let Some(item) = self.items.get(self.selected).cloned() else {
            self.message = Some("no item selected".into());
            return;
        };
        self.editor = Some(EditorState {
            draft: item,
            field: Field::Title,
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

    /// 写入一个字符到当前字段。
    fn write_field(draft: &mut Item, field: &Field, c: char) {
        match field {
            Field::Title => draft.title.push(c),
            Field::Data(d) => match (&mut draft.data, d) {
                (ItemData::Password { username, .. }, DataField::Username) => username.push(c),
                (ItemData::Password { password, .. }, DataField::Password) => password.push(c),
                (ItemData::Password { url, .. }, DataField::Url) => url.push(c),
                (ItemData::Password { totp_secret, .. }, DataField::TotpSecret) => {
                    totp_secret.push(c)
                }
                (ItemData::Password { notes, .. }, DataField::Notes) => notes.push(c),
                (ItemData::Note { format, .. }, DataField::Format) => format.push(c),
                (ItemData::Note { content, .. }, DataField::Content) => content.push(c),
                (ItemData::Card { holder, .. }, DataField::Holder) => holder.push(c),
                (ItemData::Card { number, .. }, DataField::Number) => number.push(c),
                (ItemData::Card { expiry, .. }, DataField::Expiry) => expiry.push(c),
                (ItemData::Card { cvv, .. }, DataField::Cvv) => cvv.push(c),
                (ItemData::Card { bank, .. }, DataField::Bank) => bank.push(c),
                (ItemData::Card { notes, .. }, DataField::Notes) => notes.push(c),
                _ => {}
            },
        }
    }

    /// 退格删除当前字段末尾字符。
    fn backspace_field(draft: &mut Item, field: &Field) {
        match field {
            Field::Title => {
                draft.title.pop();
            }
            Field::Data(d) => match (&mut draft.data, d) {
                (ItemData::Password { username, .. }, DataField::Username) => {
                    username.pop();
                }
                (ItemData::Password { password, .. }, DataField::Password) => {
                    password.pop();
                }
                (ItemData::Password { url, .. }, DataField::Url) => {
                    url.pop();
                }
                (ItemData::Password { totp_secret, .. }, DataField::TotpSecret) => {
                    totp_secret.pop();
                }
                (ItemData::Password { notes, .. }, DataField::Notes) => {
                    notes.pop();
                }
                (ItemData::Note { format, .. }, DataField::Format) => {
                    format.pop();
                }
                (ItemData::Note { content, .. }, DataField::Content) => {
                    content.pop();
                }
                (ItemData::Card { holder, .. }, DataField::Holder) => {
                    holder.pop();
                }
                (ItemData::Card { number, .. }, DataField::Number) => {
                    number.pop();
                }
                (ItemData::Card { expiry, .. }, DataField::Expiry) => {
                    expiry.pop();
                }
                (ItemData::Card { cvv, .. }, DataField::Cvv) => {
                    cvv.pop();
                }
                (ItemData::Card { bank, .. }, DataField::Bank) => {
                    bank.pop();
                }
                (ItemData::Card { notes, .. }, DataField::Notes) => {
                    notes.pop();
                }
                _ => {}
            },
        }
    }

    /// 当前类型的可循环字段序列(Title 在前)。
    fn fields_for(ty: ItemType) -> Vec<Field> {
        let mut v = vec![Field::Title];
        match ty {
            ItemType::Password => {
                v.extend([
                    Field::Data(DataField::Username),
                    Field::Data(DataField::Password),
                    Field::Data(DataField::Url),
                    Field::Data(DataField::TotpSecret),
                    Field::Data(DataField::Notes),
                ]);
            }
            ItemType::Note => {
                v.extend([
                    Field::Data(DataField::Format),
                    Field::Data(DataField::Content),
                ]);
            }
            ItemType::Card => {
                v.extend([
                    Field::Data(DataField::Holder),
                    Field::Data(DataField::Number),
                    Field::Data(DataField::Expiry),
                    Field::Data(DataField::Cvv),
                    Field::Data(DataField::Bank),
                    Field::Data(DataField::Notes),
                ]);
            }
        }
        v
    }

    /// 下一个字段(循环)。
    fn next_field(ty: &ItemType, cur: &Field) -> Field {
        let seq = Self::fields_for(*ty);
        let idx = seq.iter().position(|f| f == cur).unwrap_or(0);
        let next = (idx + 1) % seq.len();
        seq[next].clone()
    }

    /// 上一个字段(循环)。
    fn prev_field(ty: &ItemType, cur: &Field) -> Field {
        let seq = Self::fields_for(*ty);
        let idx = seq.iter().position(|f| f == cur).unwrap_or(0);
        let prev = if idx == 0 {
            seq.len().saturating_sub(1)
        } else {
            idx - 1
        };
        seq[prev].clone()
    }
}

/// 给定类型生成默认(空)的 ItemData。
fn default_data(ty: ItemType) -> ItemData {
    match ty {
        ItemType::Password => ItemData::Password {
            username: String::new(),
            password: String::new(),
            url: String::new(),
            totp_secret: String::new(),
            notes: String::new(),
        },
        ItemType::Note => ItemData::Note {
            format: "text".into(),
            content: String::new(),
        },
        ItemType::Card => ItemData::Card {
            holder: String::new(),
            number: String::new(),
            expiry: String::new(),
            cvv: String::new(),
            bank: String::new(),
            notes: String::new(),
        },
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
    use crate::model::{ItemData, ItemType};
    use crate::store;

    /// 构造一个内存库 + 插入若干 password item 的 App(从 from_unlocked 入口)。
    fn app_with_items(n: usize) -> App {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();
        for i in 0..n {
            let mut it = Item {
                id: None,
                item_type: ItemType::Password,
                title: format!("item-{i}"),
                category_id: None,
                data: ItemData::Password {
                    username: format!("user-{i}"),
                    password: format!("pw-{i}"),
                    url: String::new(),
                    totp_secret: String::new(),
                    notes: String::new(),
                },
                favorite: false,
                tags: Vec::new(),
                created_at: 0,
                updated_at: 0,
            };
            store::insert_item(conn, &mut it).unwrap();
        }
        let tmp = std::env::temp_dir().join(format!(
            "zkv_app_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // from_unlocked 用 save() 落盘,需要 path 存在;先用 vault::create_with_params 建一个空壳,
        // 再把内存 db 的内容保存过去。这里简化:用 fast KDF create 一份,然后直接 from_unlocked(内存 db)。
        // 但 save() 会用 KdfParams::default()(慢)。为避免慢 KDF,这些单测**不触发 save**:
        // 只要不调用会 save 的路径(insert/update/delete + 保存)即可。
        let _ = tmp;
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
    fn normal_n_enters_new_item_mode() {
        let mut app = app_with_items(1);
        let act = app.handle_key(key('n')).unwrap();
        assert_eq!(act, Action::Continue);
        assert!(matches!(app.mode, Mode::NewItem(ItemType::Password)));
        assert!(app.editor.is_some());
    }

    #[test]
    fn create_item_increments_count() {
        // 注意:保存路径会调用 save() -> vault::save_with_key,复用 from_unlocked
        // 缓存的 key(此处用 fast KDF 预建文件派生一次),故落盘仍是 AEAD、很快。
        // 这里用临时文件 + vault::create_with_params 预建,
        // 然后 from_unlocked 一个真实可保存的 path。
        let path = tmp_path("create_item");
        cleanup(&path);
        let kdf = KdfParams { m_kib: 4096, t_cost: 1, p_cost: 1 };
        crate::vault::create_with_params(&path, "pw", &kdf).unwrap();

        let db = crate::vault::unlock(&path, "pw").unwrap();
        // 插一条种子
        {
            let conn = db.conn();
            let mut seed = Item {
                id: None,
                item_type: ItemType::Password,
                title: "seed".into(),
                category_id: None,
                data: ItemData::Password {
                    username: "u".into(),
                    password: "p".into(),
                    url: String::new(),
                    totp_secret: String::new(),
                    notes: String::new(),
                },
                favorite: false,
                tags: Vec::new(),
                created_at: 0,
                updated_at: 0,
            };
            store::insert_item(conn, &mut seed).unwrap();
        }
        let mut app = App::from_unlocked(db, path.clone(), "pw".into()).unwrap();
        let before = app.items.len();

        // n -> NewItem
        app.handle_key(key('n')).unwrap();
        assert!(matches!(app.mode, Mode::NewItem(_)));
        // 输入标题 "new"
        for c in "new".chars() {
            app.handle_key(key(c)).unwrap();
        }
        // Tab 到 username,输入 "bob"
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
        assert!(matches!(app.mode, Mode::Normal));
    }

    #[test]
    fn normal_y_does_not_panic_without_clipboard() {
        let mut app = app_with_items(1);
        // 选中第一条(password 类型)
        app.selected = 0;
        app.handle_key(key('y')).unwrap();
        // 剪贴板可能无后端,message 被设置即可。
        assert!(app.message.is_some());
    }

    #[test]
    fn normal_o_handles_no_totp() {
        // app_with_items 生成的 password 条目 totp_secret 为空 → 按 o 应
        // 不 panic 且设置 message。
        let mut app = app_with_items(1);
        app.selected = 0;
        app.handle_key(key('o')).unwrap();
        assert!(app.message.is_some());
        // 空 secret 应提示无 secret。
        assert!(
            app.message.as_deref().unwrap_or("").contains("no totp secret"),
            "expected no-totp hint, got {:?}",
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
        // 末位不再下移
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
            let mut a = Item {
                id: None,
                item_type: ItemType::Password,
                title: "GitHub".into(),
                category_id: None,
                data: ItemData::Password {
                    username: "u".into(),
                    password: "p".into(),
                    url: String::new(),
                    totp_secret: String::new(),
                    notes: String::new(),
                },
                favorite: false,
                tags: Vec::new(),
                created_at: 0,
                updated_at: 0,
            };
            let mut b = a.clone();
            b.title = "GitLab".into();
            store::insert_item(conn, &mut a).unwrap();
            store::insert_item(conn, &mut b).unwrap();
        }
        let mut app =
            App::from_unlocked(db, std::path::PathBuf::from("/tmp/zkv_unused.zkv"), "x".into())
                .unwrap();
        assert_eq!(app.items.len(), 2);

        // / 进入搜索,输入 "github",Enter
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
        // filter 未变(仍为 None),items 仍为 3
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
            let mut it = Item {
                id: None,
                item_type: ItemType::Password,
                title: "to-delete".into(),
                category_id: None,
                data: ItemData::Password {
                    username: "u".into(),
                    password: "p".into(),
                    url: String::new(),
                    totp_secret: String::new(),
                    notes: String::new(),
                },
                favorite: false,
                tags: Vec::new(),
                created_at: 0,
                updated_at: 0,
            };
            store::insert_item(conn, &mut it).unwrap();
        }
        let mut app = App::from_unlocked(db, path.clone(), "pw".into()).unwrap();
        assert_eq!(app.items.len(), 1);

        // x -> ConfirmDelete
        app.handle_key(key('x')).unwrap();
        assert!(matches!(app.mode, Mode::ConfirmDelete));
        // y -> 删除
        app.handle_key(key('y')).unwrap();
        assert!(matches!(app.mode, Mode::Normal));
        assert_eq!(app.items.len(), 0);
        cleanup(&path);
    }

    #[test]
    fn editor_tab_cycles_password_fields() {
        let mut app = app_with_items(0);
        app.start_editor_new(ItemType::Password);
        let ed = app.editor.as_ref().unwrap();
        assert_eq!(ed.field, Field::Title);
        // Tab -> Username
        let next = App::next_field(&ItemType::Password, &Field::Title);
        assert_eq!(next, Field::Data(DataField::Username));
        // 循环到末位 Notes 再 Tab 回 Title
        let last = Field::Data(DataField::Notes);
        let wrap = App::next_field(&ItemType::Password, &last);
        assert_eq!(wrap, Field::Title);
    }

    #[test]
    fn passphrase_wrong_stays_in_prompt() {
        let path = tmp_path("wrong_pass");
        cleanup(&path);
        let kdf = KdfParams { m_kib: 4096, t_cost: 1, p_cost: 1 };
        crate::vault::create_with_params(&path, "correct", &kdf).unwrap();

        let mut app = App::for_open(path.clone());
        // 输入错误口令 "wrong"
        for c in "wrong".chars() {
            app.handle_key(key(c)).unwrap();
        }
        let act = app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert_eq!(act, Action::Continue);
        // 失败:停留口令态,db 仍 None
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
        // 成功:进入 Normal,db=Some
        assert!(matches!(app.mode, Mode::Normal));
        assert!(app.db.is_some());
        cleanup(&path);
    }

    // ---- 管理模式(CategoryMgr / TagMgr)测试 ----

    /// 构造一个真实可保存的 App(fast KDF 预建文件 + from_unlocked)。
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
        // 预置脏状态。
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
        // c 进入
        app.handle_key(key('c')).unwrap();
        assert!(matches!(app.mode, Mode::CategoryMgr));
        // a 新增
        app.handle_key(key('a')).unwrap();
        assert_eq!(app.mgr_edit, Some(MgrEdit::Add));
        // 输入 "Work"
        for c in "Work".chars() {
            app.handle_key(key(c)).unwrap();
        }
        // Enter 提交
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(app.categories.iter().any(|c| c.name == "Work"));
        assert!(matches!(app.mode, Mode::CategoryMgr));
        assert_eq!(app.mgr_edit, None);
        // 落盘后仍可查到。
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
        // 不输入,直接 Enter → 报错,未新增。
        app.handle_key(key_code(KeyCode::Enter)).unwrap();
        assert!(app.categories.is_empty());
        assert!(app.message.as_deref().unwrap_or("").contains("empty"));
        cleanup(&path);
    }

    #[test]
    fn category_mgr_rename_works() {
        let (mut app, path) = app_with_path("cat_rename");
        // 先插一条分类。
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
        // 但 reload 会刷新 categories;手动进入管理模式后,选中需要再次校验。
        app.handle_key(key('c')).unwrap();
        app.mgr_selected = 0;
        app.handle_key(key('r')).unwrap();
        assert_eq!(app.mgr_edit, Some(MgrEdit::Rename));
        assert_eq!(app.input, "Old");
        // 清空后输入新名。
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
        // 分类新增中途 Esc 取消。
        app.handle_key(key('c')).unwrap();
        app.handle_key(key('a')).unwrap();
        for c in "Z".chars() {
            app.handle_key(key(c)).unwrap();
        }
        app.handle_key(key_code(KeyCode::Esc)).unwrap();
        assert_eq!(app.mgr_edit, None);
        assert!(app.input.is_empty());
        // 仍在管理模式,未提交。
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
        // 末位不再下移。
        app.handle_key(key('j')).unwrap();
        assert_eq!(app.mgr_selected, 2);
        app.handle_key(key('k')).unwrap();
        assert_eq!(app.mgr_selected, 1);
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
