//! 列表视图:条目列表(含搜索框)。对应 PRD §8。
//!
//! 重排后不再有常驻侧边栏;分类/标签计数折进 header,管理走 `c`/`t` 模态。
//! 列表项两行:第 1 行类型标签 + 标题,第 2 行次要信息(用户名/预览/持卡人)。

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::{List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use super::input;
use super::theme;
use crate::app::App;
use crate::model::{Item, ItemData, ItemType};

/// 渲染条目列表(Search 模式时顶部叠搜索框)。
pub fn render_list(frame: &mut Frame, area: Rect, app: &App) {
    // Search 模式:顶部一行搜索输入框。
    let (list_area, search_widget) = if app.mode == crate::app::Mode::Search {
        let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(area);
        let field = input::InputField {
            value: app.input.clone(),
            mask: false,
        };
        (chunks[1], Some((chunks[0], field)))
    } else {
        (area, None)
    };

    if let Some((sarea, field)) = search_widget {
        input::render_input(frame, sarea, &field, " / search ");
    }

    let inner = theme::panel_frame(frame, list_area, Some("Items"));

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
            // 第 1 行:留 2 列给选中标记 "▸ ";类型标签 + 标题。
            let l1 = ratatui::text::Line::from(vec![
                ratatui::text::Span::raw("  "),
                type_span(it.item_type),
                ratatui::text::Span::raw(" "),
                ratatui::text::Span::styled(it.title.clone(), theme::fg()),
            ]);
            // 第 2 行:次要信息,弱化、缩进。
            let l2 = ratatui::text::Line::from(vec![
                ratatui::text::Span::raw("      "),
                ratatui::text::Span::styled(secondary(it), theme::muted()),
            ]);
            ListItem::new(vec![l1, l2])
        })
        .collect();

    let list = List::new(items)
        .highlight_style(theme::selected_bar())
        .highlight_symbol("▸ ");

    let mut state = ListState::default();
    if app.selected < app.items.len() {
        state.select(Some(app.selected));
    }
    frame.render_stateful_widget(list, inner, &mut state);
}

/// 类型 → 配色标签 span(PW=青、NO=绿、CD=品红)。
fn type_span(ty: ItemType) -> ratatui::text::Span<'static> {
    let (label, style) = match ty {
        ItemType::Password => ("[PW]", theme::accent2()),
        ItemType::Note => ("[NO]", theme::accent()),
        ItemType::Card => ("[CD]", theme::title_style()),
    };
    ratatui::text::Span::styled(label, style)
}

/// 条目的次要信息:密码→用户名、笔记→内容预览、卡片→持卡人。
fn secondary(it: &Item) -> String {
    match &it.data {
        ItemData::Password { username, .. } => {
            if username.is_empty() {
                "—".into()
            } else {
                username.clone()
            }
        }
        ItemData::Note { content, .. } => {
            let first = content.lines().next().unwrap_or("");
            if first.is_empty() {
                "(empty)".into()
            } else {
                first.chars().take(24).collect()
            }
        }
        ItemData::Card { holder, .. } => {
            if holder.is_empty() {
                "—".into()
            } else {
                format!("•••• {holder}")
            }
        }
    }
}
