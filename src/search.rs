//! 搜索与过滤。对应 PRD §6。
//!
//! 对外接口:
//! - [`Filter`]:搜索过滤条件(query/category/tags/item_type/favorite_only 的任意组合)。
//! - [`search`]:根据 `Filter` 执行查询,query 走 FTS5 `MATCH`,其余走 WHERE 组合,
//!   返回 `Vec<Item>`(含标签聚合),按 `updated_at` 倒序。
//!
//! 行 → Item 解析(含标签聚合)复用 [`crate::store`] 的 `row_to_item_with_tags`(单查询)。
//!
//! 分层(L3):依赖 `crate::error`/`crate::model`/`crate::db`/`crate::store` 与外部 crate,
//! 不引用 vault/app/ui。

use rusqlite::{types::Value, Connection};

use crate::error::Result;
use crate::model::{Item, ItemType};
use crate::store::row_to_item_with_tags;

/// 搜索过滤条件。全部字段可组合;`Default` 表示「无任何过滤」。
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// FTS5 查询串(命中标题与 search_text)。`None` 或空串表示不做全文检索。
    pub query: Option<String>,
    /// 仅返回该分类下的条目。
    pub category: Option<i64>,
    /// 仅返回挂有这些标签中任意一个的条目。
    pub tags: Vec<String>,
    /// 仅返回该类型的条目。
    pub item_type: Option<ItemType>,
    /// 仅返回收藏条目。
    pub favorite_only: bool,
}

/// 把 FTS5 原始用户输入转成相对安全的 MATCH 串:按空白分词,每个 token 加引号后 AND 拼接。
/// 避免 `*`/`:` 等 FTS 语法把用户输入当查询指令误解析。
fn sanitize_fts(raw: &str) -> String {
    raw.split_whitespace()
        .map(|tok| {
            // 用双引号包裹,内部双引号翻倍转义。
            let escaped = tok.replace('"', "\"\"");
            format!("\"{escaped}\"")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// 执行搜索。返回按 `updated_at` 倒序的条目列表(含标签聚合)。
///
/// - `query` 非空 → FTS5 `MATCH`(标题 + search_text)。
/// - 其余条件叠加为 WHERE 子句;`tags` 用 `EXISTS` 子查询。
/// - 所有过滤为空且无 query 时返回全部条目。
pub fn search(conn: &Connection, f: &Filter) -> Result<Vec<Item>> {
    let mut sql = String::new();
    let mut where_clauses: Vec<String> = Vec::new();
    // 绑定参数:按 push 顺序。query/category/item_type/favorite/tags。
    let mut bind_params: Vec<Value> = Vec::new();

    let query_trimmed = f
        .query
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    if let Some(q) = query_trimmed {
        sql.push_str(
            "SELECT i.id, i.type, i.title, i.category_id, i.data, i.favorite, i.search_text, i.created_at, i.updated_at,
                    (SELECT GROUP_CONCAT(tn, char(31))
                     FROM (SELECT t.name AS tn FROM item_tags it JOIN tags t ON t.id = it.tag_id
                           WHERE it.item_id = i.id ORDER BY t.name ASC)) AS tags
             FROM items_fts f JOIN items i ON i.id = f.rowid",
        );
        where_clauses.push("f.items_fts MATCH ?1".to_string());
        bind_params.push(Value::from(sanitize_fts(q)));
    } else {
        sql.push_str(
            "SELECT i.id, i.type, i.title, i.category_id, i.data, i.favorite, i.search_text, i.created_at, i.updated_at,
                    (SELECT GROUP_CONCAT(tn, char(31))
                     FROM (SELECT t.name AS tn FROM item_tags it JOIN tags t ON t.id = it.tag_id
                           WHERE it.item_id = i.id ORDER BY t.name ASC)) AS tags
             FROM items i",
        );
    }

    if let Some(cat) = f.category {
        where_clauses.push("i.category_id = ?".to_string());
        bind_params.push(Value::from(cat));
    }

    if let Some(ty) = f.item_type {
        where_clauses.push("i.type = ?".to_string());
        bind_params.push(Value::from(ty.as_str().to_string()));
    }

    if f.favorite_only {
        where_clauses.push("i.favorite = 1".to_string());
    }

    if !f.tags.is_empty() {
        // 用 EXISTS 子查询:item 至少挂有 tags 中任意一个标签。
        let placeholders: Vec<String> = (0..f.tags.len())
            .map(|_| "?".to_string())
            .collect();
        let sub = format!(
            "EXISTS(SELECT 1 FROM item_tags it JOIN tags t ON t.id = it.tag_id
                    WHERE it.item_id = i.id AND t.name IN ({}))",
            placeholders.join(", ")
        );
        where_clauses.push(sub);
        for t in &f.tags {
            bind_params.push(Value::from(t.clone()));
        }
    }

    if !where_clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&where_clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY i.updated_at DESC");

    let mut stmt = conn.prepare(&sql)?;
    // rusqlite 需要 &[&dyn ToSql];从 Value 构造引用列表。
    let binds: Vec<&dyn rusqlite::ToSql> = bind_params
        .iter()
        .map(|v| v as &dyn rusqlite::ToSql)
        .collect();
    let items: Vec<Item> = stmt
        .query_map(binds.as_slice(), row_to_item_with_tags)?
        .filter_map(|r| r.ok())
        .collect();
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use crate::model::{Item, ItemData, ItemType};
    use crate::store;

    fn make_password(title: &str, body: &str, tags: Vec<&str>, favorite: bool) -> Item {
        Item {
            id: None,
            item_type: ItemType::Password,
            title: title.into(),
            category_id: None,
            data: ItemData::Password {
                username: "u".into(),
                password: "p".into(),
                url: "https://x".into(),
                totp_secret: body.into(),
                notes: body.into(),
            },
            favorite,
            tags: tags.into_iter().map(String::from).collect(),
            created_at: 0,
            updated_at: 0,
        }
    }

    fn seed() -> Database {
        let db = Database::open_in_memory().unwrap();
        let conn = db.conn();

        // 分类
        let mut cat = crate::model::Category {
            id: None,
            name: "Work".into(),
            parent_id: None,
            sort_order: 0,
        };
        let cid = store::insert_category(conn, &mut cat).unwrap();

        let mut a = make_password("GitHub Login", "github myuser", vec!["work", "vip"], true);
        a.category_id = Some(cid);
        store::insert_item(conn, &mut a).unwrap();

        let mut b = make_password("GitLab Notes", "gitlab secret", vec!["work"], false);
        b.category_id = Some(cid);
        store::insert_item(conn, &mut b).unwrap();

        let mut c = Item {
            id: None,
            item_type: ItemType::Note,
            title: "Personal Diary".into(),
            category_id: None,
            data: ItemData::Note {
                format: "markdown".into(),
                content: "today was a good day".into(),
            },
            favorite: false,
            tags: vec!["personal".into()],
            created_at: 0,
            updated_at: 0,
        };
        store::insert_item(conn, &mut c).unwrap();

        db
    }

    #[test]
    fn query_hit_and_miss() {
        let db = seed();
        let conn = db.conn();

        // 'github' 命中标题与 search_text
        let hits = search(
            conn,
            &Filter {
                query: Some("github".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(hits.len(), 1, "should match only GitHub item");
        assert_eq!(hits[0].title, "GitHub Login");

        // 不命中
        let miss = search(
            conn,
            &Filter {
                query: Some("zzznomatch".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(miss.is_empty());
    }

    #[test]
    fn query_empty_returns_all() {
        let db = seed();
        let conn = db.conn();
        let all = search(conn, &Filter::default()).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn filter_by_category() {
        let db = seed();
        let conn = db.conn();
        let cats = store::list_categories(conn).unwrap();
        let cid = cats[0].id.unwrap();

        let res = search(
            conn,
            &Filter {
                category: Some(cid),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(res.len(), 2);
        for it in &res {
            assert_eq!(it.category_id, Some(cid));
        }
    }

    #[test]
    fn filter_by_tags() {
        let db = seed();
        let conn = db.conn();

        // 只挂 vip 的是 GitHub
        let vip = search(
            conn,
            &Filter {
                tags: vec!["vip".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(vip.len(), 1);
        assert_eq!(vip[0].title, "GitHub Login");

        // work 命中两条
        let work = search(
            conn,
            &Filter {
                tags: vec!["work".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(work.len(), 2);
    }

    #[test]
    fn filter_by_item_type() {
        let db = seed();
        let conn = db.conn();
        let notes = search(
            conn,
            &Filter {
                item_type: Some(ItemType::Note),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].item_type, ItemType::Note);
    }

    #[test]
    fn filter_favorite_only() {
        let db = seed();
        let conn = db.conn();
        let fav = search(
            conn,
            &Filter {
                favorite_only: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(fav.len(), 1);
        assert!(fav[0].favorite);
    }

    #[test]
    fn combined_filter() {
        let db = seed();
        let conn = db.conn();
        let cats = store::list_categories(conn).unwrap();
        let cid = cats[0].id.unwrap();

        // category=Work + tags=[vip] → 只剩 GitHub
        let res = search(
            conn,
            &Filter {
                category: Some(cid),
                tags: vec!["vip".into()],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].title, "GitHub Login");
    }

    #[test]
    fn sanitize_fts_quotes_tokens() {
        assert_eq!(sanitize_fts("hello world"), "\"hello\" \"world\"");
        // 含双引号的 token 会被转义
        assert_eq!(sanitize_fts("a\"b"), "\"a\"\"b\"");
    }
}
