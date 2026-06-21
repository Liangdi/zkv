//! 数据操作 CRUD。基于 `rusqlite::Connection`(由 [`crate::db::Database::conn`] 提供)与
//! [`crate::model`]。对应 PRD §5/§6。
//!
//! 对外接口(均返回 `Result<...>`):
//! - 条目:`list_items` / `get_item` / `insert_item` / `update_item` / `delete_item`
//!   —— insert/update 时同步刷新 `items.search_text`(由 [`fields_search_text`] 生成)与标签挂载。
//! - 分类:`list_categories` / `insert_category` / `update_category` / `delete_category`
//! - 标签:`list_tags` / `ensure_tag(conn, name) -> id`
//! - 附件:`list_attachments` / `insert_attachment` / `get_attachment` / `delete_attachment`
//!
//! 时间戳:由本模块用 `SystemTime::now()` 填充秒级 Unix。
//!
//! `items.type` 列承载 `template_id`;`items.data` 承载 `Vec<Field>` JSON 数组。
//! 读取层 [`row_to_item`] 始终双解析兜底(先新数组、后 legacy),兼容混合/旧库。
//!
//! 分层(L3):依赖 `crate::error`/`crate::model`/`crate::db` 与外部 crate,不引用 vault/app/ui。

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, Row};

use crate::error::{Error, Result};
use crate::model::{
    fields_search_text, legacy_to_fields, Attachment, Category, Field, Item, LegacyItemData, Tag,
};

/// 当前秒级 Unix 时间戳。
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 行 → Item 复用辅助(供 search.rs 复用)
// ---------------------------------------------------------------------------

/// 把一行(items 表的标准列顺序)解析为 `Item`(不含 tags,tags 由 [`load_tags`] 单独聚合)。
///
/// 列顺序:`id, type, title, category_id, data, favorite, search_text, created_at, updated_at`。
///
/// 返回 `rusqlite::Result` 以符合 `query_map` 的签名要求;`data` JSON 解析错误会被包装为
/// `rusqlite::Error::FromSqlConversionFailure`。
pub(crate) fn row_to_item(row: &Row<'_>) -> rusqlite::Result<Item> {
    let id: i64 = row.get(0)?;
    let type_str: String = row.get(1)?;
    let title: String = row.get(2)?;
    let category_id: Option<i64> = row.get(3)?;
    let data_json: String = row.get(4)?;
    let favorite: i64 = row.get(5)?;
    // search_text 在第 6 列,Item 不直接持有,跳过。
    let created_at: i64 = row.get(7)?;
    let updated_at: i64 = row.get(8)?;

    // 双解析:先试新形状 Vec<Field>(template_id 取 type 列);
    // 失败再试 legacy LegacyItemData → (tpl, fields)。
    // 两者都失败 → 损坏行降级:template_id="(corrupt)",fields 空(不 panic)。
    let (template_id, fields) = if let Ok(fs) = serde_json::from_str::<Vec<Field>>(&data_json) {
        (type_str, fs)
    } else if let Ok(legacy) = serde_json::from_str::<LegacyItemData>(&data_json) {
        let (tpl, fs) = legacy_to_fields(legacy);
        (tpl, fs)
    } else {
        ("(corrupt)".to_string(), Vec::new())
    };

    Ok(Item {
        id: Some(id),
        template_id,
        title,
        category_id,
        fields,
        favorite: favorite != 0,
        tags: Vec::new(),
        created_at,
        updated_at,
    })
}

/// 把一行(标准 9 列 + 第 10 列聚合标签串)解析为 `Item`(含 tags)。
///
/// 前 9 列与 [`row_to_item`] 完全一致;第 10 列(索引 9)为相关子查询用
/// `GROUP_CONCAT(t.name, char(31))` 聚合出的标签串(按 `t.name` 升序),可能为 `NULL`。
/// 用 ASCII Unit Separator(`char(31)` / `\u{1f}`)分词,避免标签名含逗号被误切。
pub(crate) fn row_to_item_with_tags(row: &Row<'_>) -> rusqlite::Result<Item> {
    let mut item = row_to_item(row)?;
    let tags_blob: Option<String> = row.get(9)?;
    item.tags = match tags_blob {
        Some(s) => s.split('\u{1f}').filter(|x| !x.is_empty()).map(String::from).collect(),
        None => Vec::new(),
    };
    Ok(item)
}

/// 加载某个 item 的所有标签名(按 name 升序)。
pub(crate) fn load_tags(conn: &Connection, item_id: i64) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT t.name FROM item_tags it
         JOIN tags t ON t.id = it.tag_id
         WHERE it.item_id = ?1
         ORDER BY t.name ASC",
    )?;
    let tags: Vec<String> = stmt
        .query_map(params![item_id], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(tags)
}

/// 把单个 item 的 tags 字段填充进去(原地修改)。
pub(crate) fn fill_tags(conn: &Connection, item: &mut Item) -> Result<()> {
    if let Some(id) = item.id {
        item.tags = load_tags(conn, id)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 条目 CRUD
// ---------------------------------------------------------------------------

/// 插入条目。序列化 `data` 为 JSON,刷新 `search_text`,同步标签挂载;回填 `item.id`。
pub fn insert_item(conn: &Connection, item: &mut Item) -> Result<i64> {
    let now = now_secs();
    let data_json = serde_json::to_string(&item.fields)?;
    let search_text = fields_search_text(&item.fields);
    let type_str = item.template_id.as_str();
    let favorite_i = if item.favorite { 1 } else { 0 };

    // 若调用方未设时间戳(为 0),用 now 填充;否则保留(便于测试/导入)。
    let created_at = if item.created_at == 0 { now } else { item.created_at };
    let updated_at = if item.updated_at == 0 { now } else { item.updated_at };

    conn.execute(
        "INSERT INTO items(type, title, category_id, data, favorite, search_text, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            type_str,
            item.title,
            item.category_id,
            data_json,
            favorite_i,
            search_text,
            created_at,
            updated_at,
        ],
    )?;

    let id = conn.last_insert_rowid();
    item.id = Some(id);
    item.created_at = created_at;
    item.updated_at = updated_at;

    sync_item_tags(conn, id, &item.tags)?;

    Ok(id)
}

/// 同步某个 item 的标签挂载(先删后插)。`tags` 为标签名列表。
fn sync_item_tags(conn: &Connection, item_id: i64, tags: &[String]) -> Result<()> {
    conn.execute("DELETE FROM item_tags WHERE item_id = ?1", params![item_id])?;
    for t in tags {
        let tag_id = ensure_tag(conn, t)?;
        conn.execute(
            "INSERT OR IGNORE INTO item_tags(item_id, tag_id) VALUES (?1, ?2)",
            params![item_id, tag_id],
        )?;
    }
    Ok(())
}

/// 更新条目。刷新 `updated_at`、`search_text`,重建该 item 的标签挂载。
pub fn update_item(conn: &Connection, item: &Item) -> Result<()> {
    let id = item.id.ok_or_else(|| Error::Other("update_item: item.id is None".into()))?;
    let data_json = serde_json::to_string(&item.fields)?;
    let search_text = fields_search_text(&item.fields);
    let type_str = item.template_id.as_str();
    let favorite_i = if item.favorite { 1 } else { 0 };
    let now = now_secs();

    let affected = conn.execute(
        "UPDATE items SET
            type = ?1,
            title = ?2,
            category_id = ?3,
            data = ?4,
            favorite = ?5,
            search_text = ?6,
            updated_at = ?7
         WHERE id = ?8",
        params![
            type_str,
            item.title,
            item.category_id,
            data_json,
            favorite_i,
            search_text,
            now,
            id,
        ],
    )?;
    if affected == 0 {
        return Err(Error::Other(format!("update_item: item {id} not found")));
    }

    sync_item_tags(conn, id, &item.tags)?;
    Ok(())
}

/// 读取单个条目(含标签聚合)。不存在返回 `Ok(None)`。
pub fn get_item(conn: &Connection, id: i64) -> Result<Option<Item>> {
    let mut stmt = conn.prepare(
        "SELECT id, type, title, category_id, data, favorite, search_text, created_at, updated_at
         FROM items WHERE id = ?1",
    )?;
    let res = stmt.query_row(params![id], row_to_item);
    let mut item = match res {
        Ok(it) => Some(it),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };
    if let Some(it) = item.as_mut() {
        fill_tags(conn, it)?;
    }
    Ok(item)
}

/// 列出全部条目(按 `updated_at` 倒序),含标签聚合。
///
/// 用相关子查询 + `GROUP_CONCAT` 一次性聚合每个 item 的标签(按 `t.name` 升序),
/// 避免对 N 个 item 各发一条查询的 N+1 问题。
pub fn list_items(conn: &Connection) -> Result<Vec<Item>> {
    let mut stmt = conn.prepare(
        "SELECT i.id, i.type, i.title, i.category_id, i.data, i.favorite, i.search_text, i.created_at, i.updated_at,
                (SELECT GROUP_CONCAT(tn, char(31))
                 FROM (SELECT t.name AS tn FROM item_tags it JOIN tags t ON t.id = it.tag_id
                       WHERE it.item_id = i.id ORDER BY t.name ASC)) AS tags
         FROM items i
         ORDER BY i.updated_at DESC",
    )?;
    let items: Vec<Item> = stmt
        .query_map([], row_to_item_with_tags)?
        .filter_map(|r| r.ok())
        .collect();
    Ok(items)
}

/// 删除条目(`item_tags`/`attachments` 由外键级联)。
pub fn delete_item(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM items WHERE id = ?1", params![id])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 分类 CRUD
// ---------------------------------------------------------------------------

/// 列出全部分类(按 `sort_order`, `id` 升序)。
pub fn list_categories(conn: &Connection) -> Result<Vec<Category>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, parent_id, sort_order FROM categories
         ORDER BY sort_order ASC, id ASC",
    )?;
    let cats: Vec<Category> = stmt
        .query_map([], |r| {
            Ok(Category {
                id: Some(r.get::<_, i64>(0)?),
                name: r.get::<_, String>(1)?,
                parent_id: r.get::<_, Option<i64>>(2)?,
                sort_order: r.get::<_, i64>(3)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(cats)
}

/// 插入分类,回填 `category.id`。
pub fn insert_category(conn: &Connection, category: &mut Category) -> Result<i64> {
    let now = now_secs();
    conn.execute(
        "INSERT INTO categories(name, parent_id, sort_order, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            category.name,
            category.parent_id,
            category.sort_order,
            now,
        ],
    )?;
    let id = conn.last_insert_rowid();
    category.id = Some(id);
    Ok(id)
}

/// 更新分类。
pub fn update_category(conn: &Connection, category: &Category) -> Result<()> {
    let id = category
        .id
        .ok_or_else(|| Error::Other("update_category: id is None".into()))?;
    let affected = conn.execute(
        "UPDATE categories SET name = ?1, parent_id = ?2, sort_order = ?3 WHERE id = ?4",
        params![category.name, category.parent_id, category.sort_order, id],
    )?;
    if affected == 0 {
        return Err(Error::Other(format!("update_category: category {id} not found")));
    }
    Ok(())
}

/// 删除分类。子条目的 `category_id` 由外键 `ON DELETE SET NULL` 置空。
pub fn delete_category(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM categories WHERE id = ?1", params![id])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 标签
// ---------------------------------------------------------------------------

/// 列出全部标签(按 name 升序)。
pub fn list_tags(conn: &Connection) -> Result<Vec<Tag>> {
    let mut stmt = conn.prepare("SELECT id, name FROM tags ORDER BY name ASC")?;
    let tags: Vec<Tag> = stmt
        .query_map([], |r| {
            Ok(Tag {
                id: r.get::<_, i64>(0)?,
                name: r.get::<_, String>(1)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(tags)
}

/// 确保标签存在(不存在则插入),返回其 id。
pub fn ensure_tag(conn: &Connection, name: &str) -> Result<i64> {
    let existing: Option<i64> = conn
        .query_row("SELECT id FROM tags WHERE name = ?1", params![name], |r| {
            r.get::<_, i64>(0)
        })
        .ok();
    if let Some(id) = existing {
        return Ok(id);
    }
    conn.execute("INSERT INTO tags(name) VALUES (?1)", params![name])?;
    Ok(conn.last_insert_rowid())
}

/// 删除标签(id)。`item_tags` 由外键 `ON DELETE CASCADE` 自动清理。
pub fn delete_tag(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM tags WHERE id = ?1", params![id])?;
    Ok(())
}

/// 改标签名。标签不存在(affected == 0)时返回 [`Error::Other`]。
pub fn update_tag(conn: &Connection, id: i64, new_name: &str) -> Result<()> {
    let affected = conn.execute(
        "UPDATE tags SET name = ?1 WHERE id = ?2",
        params![new_name, id],
    )?;
    if affected == 0 {
        return Err(Error::Other(format!("update_tag: tag {id} not found")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 附件 CRUD
// ---------------------------------------------------------------------------

/// 列出某 item 的全部附件(不含 blob,按 id 升序)。
pub fn list_attachments(conn: &Connection, item_id: i64) -> Result<Vec<Attachment>> {
    let mut stmt = conn.prepare(
        "SELECT id, item_id, filename, mime_type, size, blob FROM attachments
         WHERE item_id = ?1 ORDER BY id ASC",
    )?;
    let atts: Vec<Attachment> = stmt
        .query_map(params![item_id], |r| {
            Ok(Attachment {
                id: Some(r.get::<_, i64>(0)?),
                item_id: r.get::<_, i64>(1)?,
                filename: r.get::<_, String>(2)?,
                mime_type: r.get::<_, Option<String>>(3)?,
                size: r.get::<_, i64>(4)?,
                blob: r.get::<_, Vec<u8>>(5)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(atts)
}

/// 插入附件,`size` 由 `blob.len()` 填充,回填 `attachment.id`。
pub fn insert_attachment(conn: &Connection, attachment: &mut Attachment) -> Result<i64> {
    let now = now_secs();
    let size = attachment.blob.len() as i64;
    conn.execute(
        "INSERT INTO attachments(item_id, filename, mime_type, size, blob, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            attachment.item_id,
            attachment.filename,
            attachment.mime_type,
            size,
            attachment.blob,
            now,
        ],
    )?;
    let id = conn.last_insert_rowid();
    attachment.id = Some(id);
    attachment.size = size;
    Ok(id)
}

/// 列出全库全部附件(含 blob),按 id 升序。用于完整导出/备份。
pub fn list_all_attachments(conn: &Connection) -> Result<Vec<Attachment>> {
    let mut stmt = conn.prepare(
        "SELECT id, item_id, filename, mime_type, size, blob FROM attachments
         ORDER BY id ASC",
    )?;
    let atts: Vec<Attachment> = stmt
        .query_map([], |r| {
            Ok(Attachment {
                id: Some(r.get::<_, i64>(0)?),
                item_id: r.get::<_, i64>(1)?,
                filename: r.get::<_, String>(2)?,
                mime_type: r.get::<_, Option<String>>(3)?,
                size: r.get::<_, i64>(4)?,
                blob: r.get::<_, Vec<u8>>(5)?,
            })
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(atts)
}

/// 读取单个附件(含 blob)。不存在返回 `Ok(None)`。
pub fn get_attachment(conn: &Connection, id: i64) -> Result<Option<Attachment>> {
    let att = conn
        .query_row(
            "SELECT id, item_id, filename, mime_type, size, blob FROM attachments WHERE id = ?1",
            params![id],
            |r| {
                Ok(Attachment {
                    id: Some(r.get::<_, i64>(0)?),
                    item_id: r.get::<_, i64>(1)?,
                    filename: r.get::<_, String>(2)?,
                    mime_type: r.get::<_, Option<String>>(3)?,
                    size: r.get::<_, i64>(4)?,
                    blob: r.get::<_, Vec<u8>>(5)?,
                })
            },
        )
        .ok();
    Ok(att)
}

/// 删除附件。
pub fn delete_attachment(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM attachments WHERE id = ?1", params![id])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 单元测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::model::FieldKind;
    use crate::test_support::{mk_field, mk_password_item};

    fn sample_password_item(title: &str, tags: Vec<&str>) -> Item {
        let mut it = mk_password_item("alice", "s3cret");
        it.title = title.into();
        it.tags = tags.into_iter().map(String::from).collect();
        it
    }

    #[test]
    fn insert_get_item_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let mut item = sample_password_item("GitHub Login", vec!["work", "vip"]);
        let id = insert_item(conn, &mut item).unwrap();
        assert_eq!(item.id, Some(id));
        assert!(item.created_at > 0);
        assert!(item.updated_at > 0);

        let got = get_item(conn, id).unwrap().expect("item should exist");
        assert_eq!(got.id, Some(id));
        assert_eq!(got.title, "GitHub Login");
        assert_eq!(got.template_id, "password");
        assert_eq!(got.fields, item.fields);
        // tags 往返
        assert_eq!(got.tags, vec!["vip".to_string(), "work".to_string()]);
    }

    #[test]
    fn data_json_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let mut item = crate::test_support::mk_item(
            "note",
            "My Note",
            &[
                ("format", "markdown", FieldKind::Text),
                ("content", "# Hi\nbody", FieldKind::Multiline),
            ],
        );
        item.favorite = true;
        let id = insert_item(conn, &mut item).unwrap();

        let got = get_item(conn, id).unwrap().unwrap();
        assert_eq!(got.fields, item.fields);
        assert!(got.favorite);

        // 验证存入的 data 是 Vec<Field> JSON 数组
        let raw: String = conn
            .query_row(
                "SELECT data FROM items WHERE id = ?1",
                params![id],
                |r| r.get::<_, String>(0),
            )
            .unwrap();
        assert!(raw.starts_with('['), "data 应为 JSON 数组: {raw}");
        assert!(raw.contains("\"name\":\"content\""));
    }

    #[test]
    fn update_item_refreshes_search_text_and_updated_at() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let mut item = sample_password_item("Title", vec![]);
        let id = insert_item(conn, &mut item).unwrap();
        let orig_updated = item.updated_at;

        // 等一秒确保 updated_at 变化(秒级粒度)
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let mut updated = item.clone();
        updated.id = Some(id);
        updated.fields = vec![
            mk_field("username", "bob", FieldKind::Text),
            mk_field("password", "", FieldKind::Secret),
            mk_field("url", "", FieldKind::Text),
            mk_field("totp", "", FieldKind::Totp),
            mk_field("notes", "changed", FieldKind::Multiline),
        ];
        updated.tags = vec!["newtag".into()];
        update_item(conn, &updated).unwrap();

        let got = get_item(conn, id).unwrap().unwrap();
        assert!(got.updated_at > orig_updated, "updated_at should advance");
        assert_eq!(got.fields, updated.fields);
        assert_eq!(got.tags, vec!["newtag".to_string()]);

        // search_text 列刷新(含 username/notes,不含 password Secret)
        let st: String = conn
            .query_row(
                "SELECT search_text FROM items WHERE id = ?1",
                params![id],
                |r| r.get::<_, String>(0),
            )
            .unwrap();
        assert!(st.contains("bob"));
        assert!(st.contains("changed"));
    }

    #[test]
    fn delete_item_removes_row_and_cascades_tags() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let mut item = sample_password_item("To Delete", vec!["t1"]);
        let id = insert_item(conn, &mut item).unwrap();
        assert!(get_item(conn, id).unwrap().is_some());

        delete_item(conn, id).unwrap();
        assert!(get_item(conn, id).unwrap().is_none());

        // item_tags 级联删除
        let cnt: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM item_tags WHERE item_id = ?1",
                params![id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap();
        assert_eq!(cnt, 0);

        // tag 本身保留
        let tags = list_tags(conn).unwrap();
        assert!(tags.iter().any(|t| t.name == "t1"));
    }

    #[test]
    fn list_items_ordered_by_updated_at_desc() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let mut a = sample_password_item("A", vec![]);
        a.created_at = 1000;
        a.updated_at = 1000;
        let _ = insert_item(conn, &mut a).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(1100));

        let mut b = sample_password_item("B", vec![]);
        b.created_at = 1000;
        b.updated_at = 1000;
        let _ = insert_item(conn, &mut b).unwrap();

        let items = list_items(conn).unwrap();
        assert_eq!(items.len(), 2);
        assert!(items[0].updated_at >= items[1].updated_at);
    }

    #[test]
    fn category_crud() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let mut cat = Category {
            id: None,
            name: "Personal".into(),
            parent_id: None,
            sort_order: 0,
        };
        let cid = insert_category(conn, &mut cat).unwrap();
        assert_eq!(cat.id, Some(cid));

        let got = list_categories(conn).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "Personal");

        let mut updated = cat.clone();
        updated.name = "Work".into();
        update_category(conn, &updated).unwrap();
        let got2 = list_categories(conn).unwrap();
        assert_eq!(got2[0].name, "Work");

        delete_category(conn, cid).unwrap();
        assert!(list_categories(conn).unwrap().is_empty());
    }

    #[test]
    fn tag_ensure_idempotent() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let id1 = ensure_tag(conn, "vip").unwrap();
        let id2 = ensure_tag(conn, "vip").unwrap();
        assert_eq!(id1, id2, "ensure_tag should be idempotent");

        let id3 = ensure_tag(conn, "work").unwrap();
        assert_ne!(id1, id3);

        let tags = list_tags(conn).unwrap();
        assert_eq!(tags.len(), 2);
    }

    #[test]
    fn tag_delete_removes_row() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let id = ensure_tag(conn, "vip").unwrap();
        assert!(list_tags(conn).unwrap().iter().any(|t| t.id == id));

        delete_tag(conn, id).unwrap();
        let tags = list_tags(conn).unwrap();
        assert!(tags.is_empty(), "tag should be removed");
    }

    #[test]
    fn tag_update_renames() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let id = ensure_tag(conn, "old").unwrap();
        update_tag(conn, id, "new").unwrap();

        let tags = list_tags(conn).unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].id, id);
        assert_eq!(tags[0].name, "new");

        // 改不存在的 tag → 报错。
        assert!(update_tag(conn, 99999, "x").is_err());
    }

    #[test]
    fn attachment_crud_and_blob_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        // 附件需挂在 item 上
        let mut item = sample_password_item("Has Attachment", vec![]);
        let item_id = insert_item(conn, &mut item).unwrap();

        let blob = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
        let mut att = Attachment {
            id: None,
            item_id,
            filename: "key.bin".into(),
            mime_type: Some("application/octet-stream".into()),
            size: 0, // 应被 insert 填充
            blob: blob.clone(),
        };
        let aid = insert_attachment(conn, &mut att).unwrap();
        assert_eq!(att.id, Some(aid));
        assert_eq!(att.size, blob.len() as i64);

        let got = get_attachment(conn, aid).unwrap().expect("attachment should exist");
        assert_eq!(got.blob, blob);
        assert_eq!(got.size, blob.len() as i64);
        assert_eq!(got.filename, "key.bin");

        let listed = list_attachments(conn, item_id).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].blob, blob);

        delete_attachment(conn, aid).unwrap();
        assert!(get_attachment(conn, aid).unwrap().is_none());
    }

    #[test]
    fn search_text_column_excludes_title() {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        let mut item = crate::test_support::mk_password_item("u", "p");
        item.title = "UniqueTitleWord".into();
        let id = insert_item(conn, &mut item).unwrap();

        // search_text 列不应包含标题
        let st: String = conn
            .query_row(
                "SELECT search_text FROM items WHERE id = ?1",
                params![id],
                |r| r.get::<_, String>(0),
            )
            .unwrap();
        assert!(!st.contains("UniqueTitleWord"));
        // 但标题由 FTS 单独索引
        let title_hit: bool = conn
            .prepare("SELECT 1 FROM items_fts WHERE items_fts MATCH ?1 LIMIT 1")
            .unwrap()
            .query_map(["UniqueTitleWord"], |r| r.get::<_, i64>(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .next()
            .is_some();
        assert!(title_hit);
    }
}
