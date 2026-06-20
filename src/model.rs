//! 数据模型(L1)。对应 PRD §5 / §5.1。
//!
//! 类型清单(均 derive `serde::Serialize/Deserialize`):
//! - [`ItemType`]:条目类型,serde 映射到字符串 `password`/`note`/`card`。
//! - [`ItemData`]:三类条目的 JSON 结构(对应 `items.data` 字段)。
//! - [`Item`] / [`Category`] / [`Tag`] / [`Attachment`]:行映射类型。
//!
//! [`ItemData::search_text`] 拼接可搜索明文,供 FTS5 索引(不含标题、不含附件)。

use serde::{Deserialize, Serialize};

/// 条目类型。serde 映射为小写字符串以匹配 `items.type` 列。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemType {
    Password,
    Note,
    Card,
}

/// 条目数据,对应 PRD §5.1 的三类 JSON 结构,序列化后存入 `items.data`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ItemData {
    /// 密码条目。
    Password {
        username: String,
        password: String,
        url: String,
        totp_secret: String,
        notes: String,
    },
    /// 笔记条目。
    Note {
        /// `markdown` | `text`。
        format: String,
        content: String,
    },
    /// 卡片条目。
    Card {
        holder: String,
        number: String,
        expiry: String,
        cvv: String,
        bank: String,
        notes: String,
    },
}

impl ItemData {
    /// 拼接各字段为可搜索明文(供 FTS5 索引)。
    ///
    /// 不含标题(标题由 FTS 单独索引),不含附件正文。各字段以空格分隔。
    pub fn search_text(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        match self {
            ItemData::Password {
                username,
                password,
                url,
                totp_secret,
                notes,
            } => {
                parts.push(username.clone());
                parts.push(password.clone());
                parts.push(url.clone());
                parts.push(totp_secret.clone());
                parts.push(notes.clone());
            }
            ItemData::Note { format, content } => {
                parts.push(format.clone());
                parts.push(content.clone());
            }
            ItemData::Card {
                holder,
                number,
                expiry,
                cvv,
                bank,
                notes,
            } => {
                parts.push(holder.clone());
                parts.push(number.clone());
                parts.push(expiry.clone());
                parts.push(cvv.clone());
                parts.push(bank.clone());
                parts.push(notes.clone());
            }
        }
        // 过滤空字段,用单个空格连接,避免多余空白。
        parts.into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ")
    }
}

/// 条目行,对应 `items` 表。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: Option<i64>,
    pub item_type: ItemType,
    pub title: String,
    pub category_id: Option<i64>,
    pub data: ItemData,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// 分类行,对应 `categories` 表(支持层级)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Category {
    pub id: Option<i64>,
    pub name: String,
    pub parent_id: Option<i64>,
    pub sort_order: i64,
}

/// 标签行,对应 `tags` 表。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    pub id: i64,
    pub name: String,
}

/// 附件行,对应 `attachments` 表(blob 随整库加密)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub id: Option<i64>,
    pub item_id: i64,
    pub filename: String,
    pub mime_type: Option<String>,
    pub size: i64,
    pub blob: Vec<u8>,
}

// ---------------------------------------------------------------------------
// 字段模板重构(A1 阶段:纯新增,不影响现有 ItemType/ItemData/Item 行为)
// ---------------------------------------------------------------------------

/// 字段值类型。serde 映射为小写字符串。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    Text,
    Secret,
    Multiline,
    Totp,
}

/// 字段实例:一个已填值的字段(用于新形状 `items.data = Vec<Field>`)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub value: String,
    pub kind: FieldKind,
    #[serde(default)]
    pub protected: bool,
}

/// 字段规格:模板里描述一个字段该长什么样(无具体值)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldSpec {
    pub name: String,
    pub kind: FieldKind,
    #[serde(default)]
    pub protected: bool,
}

/// 模板:一组字段的命名规格集合。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Template {
    pub id: String,
    pub name: String,
    pub fields: Vec<FieldSpec>,
    #[serde(default)]
    pub built_in: bool,
}

/// 旧版 `ItemData` 的镜像类型,仅用于迁移时反序列化历史数据。
///
/// 与现有 [`ItemData`] 字段完全一致,但只 derive `Deserialize`(迁移方向是单向的:
/// 旧 → 新)。`#[serde(tag = "type", rename_all = "lowercase")]` 保持与历史 JSON 兼容。
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum LegacyItemData {
    Password {
        username: String,
        password: String,
        url: String,
        totp_secret: String,
        notes: String,
    },
    Note {
        format: String,
        content: String,
    },
    Card {
        holder: String,
        number: String,
        expiry: String,
        cvv: String,
        bank: String,
        notes: String,
    },
}

/// 把一组字段拼接为可搜索明文(供迁移重算 `items.search_text`)。
///
/// 规则:`kind != Secret && kind != Totp` 且值非空的字段,以单空格连接。不含标题。
pub fn fields_search_text(fields: &[Field]) -> String {
    fields
        .iter()
        .filter(|f| f.kind != FieldKind::Secret && f.kind != FieldKind::Totp)
        .map(|f| f.value.as_str())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// 把旧版 `LegacyItemData` 映射为 `(template_id, Vec<Field>)`。
///
/// 字段名 / kind 与对应内置模板对齐:
/// - Password → `("password", [username:Text, password:Secret, url:Text, totp:Totp, notes:Multiline])`
///   (注意旧 `totp_secret` 映射到新字段名 `totp`)
/// - Note → `("note", [format:Text, content:Multiline])`
/// - Card → `("card", [holder:Text, number:Secret, expiry:Text, cvv:Secret, bank:Text, notes:Multiline])`
///
/// `protected` 对 Secret/Totp 设 `true`,其余 `false`。
pub fn legacy_to_fields(d: LegacyItemData) -> (String, Vec<Field>) {
    match d {
        LegacyItemData::Password {
            username,
            password,
            url,
            totp_secret,
            notes,
        } => (
            "password".to_string(),
            vec![
                Field { name: "username".into(), value: username, kind: FieldKind::Text, protected: false },
                Field { name: "password".into(), value: password, kind: FieldKind::Secret, protected: true },
                Field { name: "url".into(), value: url, kind: FieldKind::Text, protected: false },
                Field { name: "totp".into(), value: totp_secret, kind: FieldKind::Totp, protected: true },
                Field { name: "notes".into(), value: notes, kind: FieldKind::Multiline, protected: false },
            ],
        ),
        LegacyItemData::Note { format, content } => (
            "note".to_string(),
            vec![
                Field { name: "format".into(), value: format, kind: FieldKind::Text, protected: false },
                Field { name: "content".into(), value: content, kind: FieldKind::Multiline, protected: false },
            ],
        ),
        LegacyItemData::Card {
            holder,
            number,
            expiry,
            cvv,
            bank,
            notes,
        } => (
            "card".to_string(),
            vec![
                Field { name: "holder".into(), value: holder, kind: FieldKind::Text, protected: false },
                Field { name: "number".into(), value: number, kind: FieldKind::Secret, protected: true },
                Field { name: "expiry".into(), value: expiry, kind: FieldKind::Text, protected: false },
                Field { name: "cvv".into(), value: cvv, kind: FieldKind::Secret, protected: true },
                Field { name: "bank".into(), value: bank, kind: FieldKind::Text, protected: false },
                Field { name: "notes".into(), value: notes, kind: FieldKind::Multiline, protected: false },
            ],
        ),
    }
}

/// 构造一个 `FieldSpec`(小工具,避免重复样板)。
fn spec(name: &str, kind: FieldKind) -> FieldSpec {
    let protected = matches!(kind, FieldKind::Secret | FieldKind::Totp);
    FieldSpec {
        name: name.into(),
        kind,
        protected,
    }
}

/// 单个内置模板的静态描述:(id, name, &[(field_name, kind)])。
type BuiltinTemplateRaw = (&'static str, &'static str, &'static [(&'static str, FieldKind)]);

/// 内置 8 个预设模板的静态切片(供 [`get_builtin`] 查找)。
///
/// 每次调用 [`builtin_templates`] 都返回这些静态模板的 clone。
static BUILTIN_TEMPLATES_RAW: &[BuiltinTemplateRaw] = &[
    ("password", "Password", &[
        ("username", FieldKind::Text),
        ("password", FieldKind::Secret),
        ("url", FieldKind::Text),
        ("totp", FieldKind::Totp),
        ("notes", FieldKind::Multiline),
    ]),
    ("note", "Note", &[
        ("format", FieldKind::Text),
        ("content", FieldKind::Multiline),
    ]),
    ("card", "Card", &[
        ("holder", FieldKind::Text),
        ("number", FieldKind::Secret),
        ("expiry", FieldKind::Text),
        ("cvv", FieldKind::Secret),
        ("bank", FieldKind::Text),
        ("notes", FieldKind::Multiline),
    ]),
    ("wifi", "Wi-Fi", &[
        ("ssid", FieldKind::Text),
        ("password", FieldKind::Secret),
        ("security", FieldKind::Text),
        ("hidden", FieldKind::Text),
        ("notes", FieldKind::Multiline),
    ]),
    ("bank", "Bank Account", &[
        ("bank", FieldKind::Text),
        ("account", FieldKind::Text),
        ("iban", FieldKind::Text),
        ("swift", FieldKind::Text),
        ("pin", FieldKind::Secret),
        ("notes", FieldKind::Multiline),
    ]),
    ("ssh", "SSH Key", &[
        ("host", FieldKind::Text),
        ("user", FieldKind::Text),
        ("private_key", FieldKind::Secret),
        ("passphrase", FieldKind::Secret),
        ("public_key", FieldKind::Multiline),
        ("notes", FieldKind::Multiline),
    ]),
    ("identity", "Identity", &[
        ("full_name", FieldKind::Text),
        ("email", FieldKind::Text),
        ("phone", FieldKind::Text),
        ("address", FieldKind::Multiline),
        ("passport", FieldKind::Secret),
        ("notes", FieldKind::Multiline),
    ]),
    ("email", "Email", &[
        ("email", FieldKind::Text),
        ("password", FieldKind::Secret),
        ("imap_server", FieldKind::Text),
        ("smtp_server", FieldKind::Text),
        ("notes", FieldKind::Multiline),
    ]),
];

/// 由 `BUILTIN_TEMPLATES_RAW` 第 `idx` 项构造一个 `Template`。
fn build_template(idx: usize) -> Template {
    let (id, name, fields_raw) = BUILTIN_TEMPLATES_RAW[idx];
    Template {
        id: id.to_string(),
        name: name.to_string(),
        fields: fields_raw
            .iter()
            .map(|(n, k)| spec(n, *k))
            .collect(),
        built_in: true,
    }
}

/// 返回全部 8 个内置预设模板(均为 `built_in: true`)。
pub fn builtin_templates() -> Vec<Template> {
    (0..BUILTIN_TEMPLATES_RAW.len())
        .map(build_template)
        .collect()
}

/// 按 id 查找内置模板,返回静态借用(无需 clone)。
pub fn get_builtin(id: &str) -> Option<&'static Template> {
    // 用一个线程局部懒构造的数组承载静态引用,避免每次构造。
    // 由于 build_template 每次产生新对象,这里改用 leak 一次构造常驻。
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<Template>> = OnceLock::new();
    let table = TABLE.get_or_init(builtin_templates);
    table.iter().find(|t| t.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_type_serde_renames() {
        assert_eq!(
            serde_json::to_string(&ItemType::Password).unwrap(),
            "\"password\""
        );
        assert_eq!(
            serde_json::to_string(&ItemType::Note).unwrap(),
            "\"note\""
        );
        assert_eq!(serde_json::to_string(&ItemType::Card).unwrap(), "\"card\"");

        let t: ItemType = serde_json::from_str("\"card\"").unwrap();
        assert_eq!(t, ItemType::Card);
    }

    #[test]
    fn password_data_roundtrip() {
        let data = ItemData::Password {
            username: "alice".into(),
            password: "s3cret".into(),
            url: "https://example.com".into(),
            totp_secret: "JBSWY3DPEHPK3PXP".into(),
            notes: "main account".into(),
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: ItemData = serde_json::from_str(&json).unwrap();
        assert_eq!(data, back);
        assert!(json.contains("\"username\":\"alice\""));
    }

    #[test]
    fn note_data_roundtrip() {
        let data = ItemData::Note {
            format: "markdown".into(),
            content: "# Title\nsome **bold** text".into(),
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: ItemData = serde_json::from_str(&json).unwrap();
        assert_eq!(data, back);
    }

    #[test]
    fn card_data_roundtrip() {
        let data = ItemData::Card {
            holder: "BOB SMITH".into(),
            number: "4111111111111111".into(),
            expiry: "12/29".into(),
            cvv: "123".into(),
            bank: "Acme Bank".into(),
            notes: "".into(),
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: ItemData = serde_json::from_str(&json).unwrap();
        assert_eq!(data, back);
    }

    #[test]
    fn search_text_nonempty_for_each_variant() {
        let pw = ItemData::Password {
            username: "u".into(),
            password: "p".into(),
            url: "https://x".into(),
            totp_secret: "T".into(),
            notes: "n".into(),
        };
        assert!(!pw.search_text().is_empty());
        assert!(pw.search_text().contains("u"));
        assert!(pw.search_text().contains("https://x"));

        let note = ItemData::Note {
            format: "text".into(),
            content: "hello world".into(),
        };
        assert!(!note.search_text().is_empty());
        assert!(note.search_text().contains("hello world"));

        let card = ItemData::Card {
            holder: "H".into(),
            number: "1234".into(),
            expiry: "01/30".into(),
            cvv: "9".into(),
            bank: "B".into(),
            notes: "cn".into(),
        };
        assert!(!card.search_text().is_empty());
        assert!(card.search_text().contains("1234"));
    }

    #[test]
    fn search_text_skips_empty_fields() {
        let pw = ItemData::Password {
            username: "alice".into(),
            password: "".into(),
            url: "".into(),
            totp_secret: "".into(),
            notes: "".into(),
        };
        // 仅 username 非空,不应出现多余空格。
        assert_eq!(pw.search_text(), "alice");
    }

    #[test]
    fn item_struct_roundtrip() {
        let item = Item {
            id: Some(42),
            item_type: ItemType::Note,
            title: "My Note".into(),
            category_id: Some(7),
            data: ItemData::Note {
                format: "markdown".into(),
                content: "body".into(),
            },
            favorite: true,
            tags: vec!["work".into(), "todo".into()],
            created_at: 1_700_000_000,
            updated_at: 1_700_000_100,
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: Item = serde_json::from_str(&json).unwrap();
        assert_eq!(item, back);
    }

    #[test]
    fn category_tag_attachment_roundtrip() {
        let cat = Category {
            id: Some(1),
            name: "Personal".into(),
            parent_id: None,
            sort_order: 0,
        };
        let cat_back: Category = serde_json::from_str(&serde_json::to_string(&cat).unwrap()).unwrap();
        assert_eq!(cat, cat_back);

        let tag = Tag { id: 3, name: "vip".into() };
        let tag_back: Tag = serde_json::from_str(&serde_json::to_string(&tag).unwrap()).unwrap();
        assert_eq!(tag, tag_back);

        let att = Attachment {
            id: None,
            item_id: 5,
            filename: "a.png".into(),
            mime_type: Some("image/png".into()),
            size: 1024,
            blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let att_back: Attachment =
            serde_json::from_str(&serde_json::to_string(&att).unwrap()).unwrap();
        assert_eq!(att, att_back);
    }

    // -----------------------------------------------------------------------
    // 字段模板重构(A1)测试
    // -----------------------------------------------------------------------

    #[test]
    fn field_kind_serde_renames() {
        assert_eq!(serde_json::to_string(&FieldKind::Text).unwrap(), "\"text\"");
        assert_eq!(
            serde_json::to_string(&FieldKind::Secret).unwrap(),
            "\"secret\""
        );
        assert_eq!(
            serde_json::to_string(&FieldKind::Multiline).unwrap(),
            "\"multiline\""
        );
        assert_eq!(serde_json::to_string(&FieldKind::Totp).unwrap(), "\"totp\"");
        let k: FieldKind = serde_json::from_str("\"multiline\"").unwrap();
        assert_eq!(k, FieldKind::Multiline);
    }

    #[test]
    fn field_serde_roundtrip() {
        let f = Field {
            name: "password".into(),
            value: "hunter2".into(),
            kind: FieldKind::Secret,
            protected: true,
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: Field = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
        // protected 默认 false
        let no_prot: Field =
            serde_json::from_str(r#"{"name":"x","value":"y","kind":"text"}"#).unwrap();
        assert!(!no_prot.protected);
    }

    #[test]
    fn template_serde_roundtrip() {
        let t = Template {
            id: "password".into(),
            name: "Password".into(),
            fields: vec![FieldSpec {
                name: "username".into(),
                kind: FieldKind::Text,
                protected: false,
            }],
            built_in: true,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: Template = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
        // built_in 默认 false
        let no_bi: Template =
            serde_json::from_str(r#"{"id":"x","name":"y","fields":[]}"#).unwrap();
        assert!(!no_bi.built_in);
    }

    #[test]
    fn builtin_templates_has_eight_unique() {
        let tpls = builtin_templates();
        assert_eq!(tpls.len(), 8, "应有 8 个内置模板");
        // id 唯一
        let mut ids: Vec<&str> = tpls.iter().map(|t| t.id.as_str()).collect();
        ids.sort();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "内置模板 id 不应重复");
        // fields 非空 + 全部 built_in
        for t in &tpls {
            assert!(!t.fields.is_empty(), "模板 {} 字段不应为空", t.id);
            assert!(t.built_in, "模板 {} 应为 built_in", t.id);
        }
        // 抽查关键 id 存在
        for expected in [
            "password", "note", "card", "wifi", "bank", "ssh", "identity", "email",
        ] {
            assert!(tpls.iter().any(|t| t.id == expected), "缺少模板 {expected}");
        }
    }

    #[test]
    fn builtin_template_field_alignment() {
        let pw = get_builtin("password").expect("password 模板应存在");
        let names: Vec<&str> = pw.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["username", "password", "url", "totp", "notes"]);
        // totp 字段 protected = true
        let totp = pw.fields.iter().find(|f| f.name == "totp").unwrap();
        assert_eq!(totp.kind, FieldKind::Totp);
        assert!(totp.protected);
    }

    #[test]
    fn get_builtin_returns_some_and_none() {
        assert!(get_builtin("card").is_some());
        assert!(get_builtin("nonexistent").is_none());
    }

    #[test]
    fn fields_search_text_excludes_secret_and_totp() {
        let fields = vec![
            Field { name: "username".into(), value: "alice".into(), kind: FieldKind::Text, protected: false },
            Field { name: "password".into(), value: "s3cret".into(), kind: FieldKind::Secret, protected: true },
            Field { name: "totp".into(), value: "TTT".into(), kind: FieldKind::Totp, protected: true },
            Field { name: "notes".into(), value: "hello".into(), kind: FieldKind::Multiline, protected: false },
        ];
        let st = fields_search_text(&fields);
        assert!(st.contains("alice"));
        assert!(st.contains("hello"));
        assert!(!st.contains("s3cret"), "Secret 不应进入 search_text");
        assert!(!st.contains("TTT"), "Totp 不应进入 search_text");
    }

    #[test]
    fn fields_search_text_skips_empty() {
        let fields = vec![
            Field { name: "a".into(), value: "x".into(), kind: FieldKind::Text, protected: false },
            Field { name: "b".into(), value: "".into(), kind: FieldKind::Text, protected: false },
            Field { name: "c".into(), value: "y".into(), kind: FieldKind::Text, protected: false },
        ];
        assert_eq!(fields_search_text(&fields), "x y");
    }

    fn field_eq(name: &str, kind: FieldKind, protected: bool, f: &Field) {
        assert_eq!(f.name, name);
        assert_eq!(f.kind, kind);
        assert_eq!(f.protected, protected);
    }

    #[test]
    fn legacy_to_fields_password() {
        let d = LegacyItemData::Password {
            username: "u".into(),
            password: "s3cret".into(),
            url: "x".into(),
            totp_secret: "T".into(),
            notes: "n".into(),
        };
        let (tpl, fields) = legacy_to_fields(d);
        assert_eq!(tpl, "password");
        assert_eq!(fields.len(), 5);
        // 关键:旧 totp_secret → 新字段名 "totp":Totp:protected
        field_eq("username", FieldKind::Text, false, &fields[0]);
        field_eq("password", FieldKind::Secret, true, &fields[1]);
        field_eq("url", FieldKind::Text, false, &fields[2]);
        field_eq("totp", FieldKind::Totp, true, &fields[3]);
        field_eq("notes", FieldKind::Multiline, false, &fields[4]);
    }

    #[test]
    fn legacy_to_fields_note() {
        let d = LegacyItemData::Note {
            format: "text".into(),
            content: "body".into(),
        };
        let (tpl, fields) = legacy_to_fields(d);
        assert_eq!(tpl, "note");
        assert_eq!(fields.len(), 2);
        field_eq("format", FieldKind::Text, false, &fields[0]);
        field_eq("content", FieldKind::Multiline, false, &fields[1]);
    }

    #[test]
    fn legacy_to_fields_card() {
        let d = LegacyItemData::Card {
            holder: "h".into(),
            number: "1234".into(),
            expiry: "01/30".into(),
            cvv: "9".into(),
            bank: "b".into(),
            notes: "cn".into(),
        };
        let (tpl, fields) = legacy_to_fields(d);
        assert_eq!(tpl, "card");
        assert_eq!(fields.len(), 6);
        field_eq("holder", FieldKind::Text, false, &fields[0]);
        field_eq("number", FieldKind::Secret, true, &fields[1]);
        field_eq("expiry", FieldKind::Text, false, &fields[2]);
        field_eq("cvv", FieldKind::Secret, true, &fields[3]);
        field_eq("bank", FieldKind::Text, false, &fields[4]);
        field_eq("notes", FieldKind::Multiline, false, &fields[5]);
    }

    #[test]
    fn legacy_item_data_deserializes_historical_json() {
        let json = r#"{"type":"password","username":"u","password":"s","url":"x","totp_secret":"T","notes":"n"}"#;
        let d: LegacyItemData = serde_json::from_str(json).unwrap();
        match d {
            LegacyItemData::Password { username, .. } => assert_eq!(username, "u"),
            _ => panic!("应为 Password 变体"),
        }
    }
}
