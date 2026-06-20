//! 数据模型(L1)。对应 PRD §5 / §5.1。
//!
//! 通用字段/模板模型(字段模板重构):
//! - [`FieldKind`][]:字段值类型(Text/Secret/Multiline/Totp)。
//! - [`Field`][]:一个已填值的字段(`items.data = Vec<Field>`)。
//! - [`FieldSpec`][] / [`Template`][]:字段规格 / 命名模板集合。
//! - [`Item`][] / [`Category`][] / [`Tag`][] / [`Attachment`][]:行映射类型。
//! - [`fields_search_text`][]:拼接可搜索明文(仅 Text/Multiline,Secret/Totp 不入)。
//! - [`LegacyItemData`] / [`legacy_to_fields`]:旧 `ItemData` → 新 `Vec<Field>` 迁移。

use serde::{Deserialize, Serialize};

/// 字段值类型。serde 映射为小写字符串。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    Text,
    Secret,
    Multiline,
    Totp,
}

/// 字段实例:一个已填值的字段(用于 `items.data = Vec<Field>`)。
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

/// 条目行,对应 `items` 表。`template_id` 取代旧 `item_type`;`fields` 取代旧 `data`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: Option<i64>,
    pub template_id: String,
    pub title: String,
    pub category_id: Option<i64>,
    pub fields: Vec<Field>,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Item {
    /// 按 name 查首个字段的可变引用。
    pub fn field_mut(&mut self, name: &str) -> Option<&mut Field> {
        self.fields.iter_mut().find(|f| f.name == name)
    }

    /// 按 name 查首个字段的值。
    pub fn field_value(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.value.as_str())
    }

    /// 首个 kind=Totp 的字段值。
    pub fn totp_value(&self) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.kind == FieldKind::Totp)
            .map(|f| f.value.as_str())
    }
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
// 字段模板:迁移支持 + 内置预设
// ---------------------------------------------------------------------------

/// 旧版 `ItemData` 的镜像类型,仅用于迁移时反序列化历史数据。
///
/// 与历史 `ItemData` 字段完全一致,但只 derive `Deserialize`(迁移方向单向:旧 → 新)。
/// `#[serde(tag = "type", rename_all = "lowercase")]` 保持与历史 JSON 兼容。
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

/// 把一组字段拼接为可搜索明文(供 FTS5 索引 / 迁移重算 `items.search_text`)。
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
///   (旧 `totp_secret` 映射到新字段名 `totp`)
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
    use std::sync::OnceLock;
    static TABLE: OnceLock<Vec<Template>> = OnceLock::new();
    let table = TABLE.get_or_init(builtin_templates);
    table.iter().find(|t| t.id == id)
}

/// 模板展示名:内置模板取 `name`,未知 id 回退为 id 本身。
pub fn template_display_name(template_id: &str) -> String {
    get_builtin(template_id)
        .map(|t| t.name.clone())
        .unwrap_or_else(|| template_id.to_string())
}

/// 用某内置模板实例化一组**空值**字段(供新建条目编辑器初始化)。
///
/// note 模板的 `format` 字段默认填 `"text"`(其余字段空串)。未知 id 返回 `None`。
pub fn instantiate_template(id: &str) -> Option<Vec<Field>> {
    let tpl = get_builtin(id)?;
    Some(
        tpl.fields
            .iter()
            .map(|s| Field {
                name: s.name.clone(),
                value: if id == "note" && s.name == "format" {
                    "text".to_string()
                } else {
                    String::new()
                },
                kind: s.kind,
                protected: s.protected,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut ids: Vec<&str> = tpls.iter().map(|t| t.id.as_str()).collect();
        ids.sort();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "内置模板 id 不应重复");
        for t in &tpls {
            assert!(!t.fields.is_empty(), "模板 {} 字段不应为空", t.id);
            assert!(t.built_in, "模板 {} 应为 built_in", t.id);
        }
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

    #[test]
    fn item_struct_roundtrip() {
        let item = Item {
            id: Some(42),
            template_id: "note".into(),
            title: "My Note".into(),
            category_id: Some(7),
            fields: vec![
                Field { name: "format".into(), value: "markdown".into(), kind: FieldKind::Text, protected: false },
                Field { name: "content".into(), value: "body".into(), kind: FieldKind::Multiline, protected: false },
            ],
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

    #[test]
    fn instantiate_template_produces_empty_fields() {
        let fields = instantiate_template("password").unwrap();
        assert_eq!(fields.len(), 5);
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["username", "password", "url", "totp", "notes"]);
        // 全空。
        assert!(fields.iter().all(|f| f.value.is_empty()));
        // protected 对 Secret/Totp 为 true。
        assert!(fields.iter().find(|f| f.name == "password").unwrap().protected);
    }

    #[test]
    fn instantiate_template_note_format_defaults_text() {
        let fields = instantiate_template("note").unwrap();
        let format = fields.iter().find(|f| f.name == "format").unwrap();
        assert_eq!(format.value, "text");
        let content = fields.iter().find(|f| f.name == "content").unwrap();
        assert_eq!(content.value, "");
    }

    #[test]
    fn instantiate_template_unknown_returns_none() {
        assert!(instantiate_template("nope").is_none());
    }

    #[test]
    fn template_display_name_known_and_unknown() {
        assert_eq!(template_display_name("wifi"), "Wi-Fi");
        assert_eq!(template_display_name("custom-x"), "custom-x");
    }

    #[test]
    fn item_field_helpers() {
        let item = Item {
            id: None,
            template_id: "password".into(),
            title: "T".into(),
            category_id: None,
            fields: vec![
                Field { name: "username".into(), value: "alice".into(), kind: FieldKind::Text, protected: false },
                Field { name: "password".into(), value: "s3cret".into(), kind: FieldKind::Secret, protected: true },
                Field { name: "totp".into(), value: "TTT".into(), kind: FieldKind::Totp, protected: true },
            ],
            favorite: false,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        };
        assert_eq!(item.field_value("username"), Some("alice"));
        assert_eq!(item.field_value("missing"), None);
        assert_eq!(item.totp_value(), Some("TTT"));
        let mut m = item.clone();
        m.field_mut("username").unwrap().value = "bob".into();
        assert_eq!(m.field_value("username"), Some("bob"));
    }
}
