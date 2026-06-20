//! 测试支持:构造 `Field` / `Item` 的便捷 helper,供各模块 `#[cfg(test)]` 复用。
//!
//! 本模块仅 `pub use` 在测试中使用;非测试构建下不被任何生产代码引用。

use crate::model::{Field, FieldKind, Item};

/// 构造一个 `Field`。
pub fn mk_field(name: &str, value: &str, kind: FieldKind) -> Field {
    let protected = matches!(kind, FieldKind::Secret | FieldKind::Totp);
    Field {
        name: name.into(),
        value: value.into(),
        kind,
        protected,
    }
}

/// 构造一个 `Item`:`template_id` + `title` + 一组 `(name,value,kind)` 字段。
/// tags/favorite/时间戳取默认空值。
pub fn mk_item(template_id: &str, title: &str, fields: &[(&str, &str, FieldKind)]) -> Item {
    Item {
        id: None,
        template_id: template_id.into(),
        title: title.into(),
        category_id: None,
        fields: fields
            .iter()
            .map(|(n, v, k)| mk_field(n, v, *k))
            .collect(),
        favorite: false,
        tags: Vec::new(),
        created_at: 0,
        updated_at: 0,
    }
}

/// 构造一个 password 模板条目(含 username/password)。
pub fn mk_password_item(username: &str, password: &str) -> Item {
    mk_item(
        "password",
        "",
        &[
            ("username", username, FieldKind::Text),
            ("password", password, FieldKind::Secret),
            ("url", "", FieldKind::Text),
            ("totp", "", FieldKind::Totp),
            ("notes", "", FieldKind::Multiline),
        ],
    )
}
