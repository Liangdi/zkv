//! 列表视图:左栏(分类树 + 标签云)+ 中栏(条目列表 + 搜索框)。对应 PRD §8。

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use super::theme;
use crate::app::App;
use crate::model::Category;

/// 渲染左栏:分类树(按 parent_id 缩进)+ 标签云。
pub fn render_sidebar(frame: &mut Frame, area: Rect, app: &App) {
    let block = theme::block(" Categories / Tags ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // 分类区与标签区分两块。
    let chunks = Layout::vertical([Constraint::Length(3 + app.categories.len() as u16), Constraint::Min(1)])
        .split(inner);
    let cat_area = chunks[0];
    let tag_area = chunks[1];

    // 分类:按 parent_id 标识层级,无 parent 的为顶层,有 parent 的缩进两格。
    // 这里做一个简单的两级渲染。
    let cats = &app.categories;
    let lines: Vec<ratatui::text::Line> = if cats.is_empty() {
        vec![ratatui::text::Line::from("(no categories)").style(theme::muted())]
    } else {
        tree_lines(cats)
    };
    let cat_para = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(cat_para, cat_area);

    // 标签云
    let tag_title = ratatui::text::Line::from("Tags").style(theme::title_style());
    let tag_body = if app.tags.is_empty() {
        ratatui::text::Line::from("(no tags)").style(theme::muted())
    } else {
        ratatui::text::Line::from(app.tags.join("  ")).style(theme::accent2())
    };
    let tag_para = Paragraph::new(vec![tag_title, ratatui::text::Line::from(""), tag_body])
        .wrap(Wrap { trim: false });
    frame.render_widget(tag_para, tag_area);
}

/// 把扁平分类列表渲染成(两级)树形文本行。
fn tree_lines(cats: &[Category]) -> Vec<ratatui::text::Line<'static>> {
    use std::collections::HashMap;
    let mut by_parent: HashMap<Option<i64>, Vec<&Category>> = HashMap::new();
    for c in cats {
        by_parent.entry(c.parent_id).or_default().push(c);
    }
    // 排序保证稳定顺序
    for v in by_parent.values_mut() {
        v.sort_by_key(|c| (c.sort_order, c.id.unwrap_or(0)));
    }
    let mut out = Vec::new();
    let roots = by_parent.get(&None).cloned().unwrap_or_default();
    for root in roots {
        let rid = root.id;
        out.push(ratatui::text::Line::from(format!("▸ {}", root.name)).style(theme::fg()));
        if let Some(children) = by_parent.get(&rid) {
            for ch in children {
                out.push(
                    ratatui::text::Line::from(format!("  • {}", ch.name)).style(theme::muted()),
                );
            }
        }
    }
    out
}

/// 渲染中栏:搜索框(Search 模式时置顶) + 条目列表(选中/收藏标记)。
pub fn render_list(frame: &mut Frame, area: Rect, app: &App) {
    // Search 模式:顶部一行搜索输入框。
    let (list_area, search_widget) = if app.mode == crate::app::Mode::Search {
        let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(area);
        let field = super::input::InputField {
            value: app.input.clone(),
            mask: false,
        };
        (chunks[1], Some((chunks[0], field)))
    } else {
        (area, None)
    };

    if let Some((sarea, field)) = search_widget {
        super::input::render_input(frame, sarea, &field, " / search ");
    }

    let block = theme::block(" Items ");
    let inner = block.inner(list_area);
    frame.render_widget(block, list_area);

    if app.items.is_empty() {
        let empty = Paragraph::new("(no items)\npress n to create")
            .style(theme::muted())
            .wrap(Wrap { trim: true });
        frame.render_widget(empty, inner);
        return;
    }

    let items: Vec<ListItem> = app
        .items
        .iter()
        .map(|it| {
            let star = if it.favorite { "★ " } else { "  " };
            let ty = item_type_tag(it.item_type);
            let text = format!("{star}{ty} {}", it.title);
            ListItem::new(text)
        })
        .collect();

    let list = List::new(items)
        .highlight_style(theme::selected_bar())
        .highlight_symbol("▶ ");

    let mut state = ListState::default();
    if app.selected < app.items.len() {
        state.select(Some(app.selected));
    }
    frame.render_stateful_widget(list, inner, &mut state);
}

/// 把 ItemType 映射到短标签(由于 model 未提供 as_str,这里内联)。
fn item_type_tag(ty: crate::model::ItemType) -> &'static str {
    use crate::model::ItemType;
    match ty {
        ItemType::Password => "[PW]",
        ItemType::Note => "[NO]",
        ItemType::Card => "[CD]",
    }
}
