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
}
