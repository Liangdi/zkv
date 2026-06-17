//! 详情/编辑面板:右栏。对应 PRD §8。
//!
//! - 无编辑器时:只读展示选中条目字段(密码默认掩码)。
//! - 有编辑器(NewItem/EditItem)时:渲染为表单,高亮当前 `editor.field`。

use ratatui::layout::Rect;
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use super::theme;
use crate::app::{App, DataField, Field};
use crate::model::{Item, ItemData, ItemType};

/// 渲染右栏。
pub fn render_detail(frame: &mut Frame, area: Rect, app: &App) {
    // 编辑器优先:NewItem / EditItem。
    if let Some(ed) = &app.editor {
        render_editor(frame, area, &ed.draft, &ed.field);
        return;
    }

    let block = theme::block(" Detail ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(item) = app.selected_item() else {
        let p = Paragraph::new("(no item selected)\n\nselect with j/k or press n to create")
            .style(theme::muted())
            .wrap(Wrap { trim: true });
        frame.render_widget(p, inner);
        return;
    };

    let lines = view_lines(item);
    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(p, inner);
}

/// 只读视图的字段行。
fn view_lines(item: &Item) -> Vec<ratatui::text::Line<'static>> {
    let mut lines: Vec<ratatui::text::Line> = Vec::new();

    lines.push(label_value("Title", &item.title, false));
    lines.push(label_value("Type", type_str(item.item_type), false));

    let star = if item.favorite { "★ favorite" } else { "" };
    lines.push(ratatui::text::Line::from(star.to_string()).style(theme::accent()));
    lines.push(ratatui::text::Line::from(""));

    match &item.data {
        ItemData::Password {
            username,
            password,
            url,
            totp_secret,
            notes,
        } => {
            lines.push(label_value("Username", username, false));
            lines.push(label_value("Password", &mask(password), true));
            lines.push(label_value("URL", url, false));
            lines.push(label_value("TOTP", &mask(totp_secret), true));
            lines.push(ratatui::text::Line::from(""));
            lines.push(label_value("Notes", notes, false));
        }
        ItemData::Note { format, content } => {
            lines.push(label_value("Format", format, false));
            lines.push(ratatui::text::Line::from(""));
            for ln in content.lines() {
                lines.push(ratatui::text::Line::from(ln.to_string()).style(theme::fg()));
            }
        }
        ItemData::Card {
            holder,
            number,
            expiry,
            cvv,
            bank,
            notes,
        } => {
            lines.push(label_value("Holder", holder, false));
            lines.push(label_value("Number", &mask(number), true));
            lines.push(label_value("Expiry", expiry, false));
            lines.push(label_value("CVV", &mask(cvv), true));
            lines.push(label_value("Bank", bank, false));
            lines.push(ratatui::text::Line::from(""));
            lines.push(label_value("Notes", notes, false));
        }
    }

    if !item.tags.is_empty() {
        lines.push(ratatui::text::Line::from(""));
        lines.push(ratatui::text::Line::from(format!("Tags: {}", item.tags.join(", "))).style(theme::accent2()));
    }

    lines
}

/// 编辑器视图:把 draft 渲染为表单,当前字段用高亮 + `▍` 光标标记。
fn render_editor(frame: &mut Frame, area: Rect, draft: &Item, field: &Field) {
    let block = theme::block(" Editor (Tab/↑↓ next · Enter save · Esc cancel) ");
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rows = editor_rows(draft, field);
    let p = Paragraph::new(rows).wrap(Wrap { trim: false });
    frame.render_widget(p, inner);
}

fn editor_rows(draft: &Item, field: &Field) -> Vec<ratatui::text::Line<'static>> {
    let mut rows = Vec::new();
    rows.push(field_line("Title", &draft.title, field, &Field::Title));

    match (&draft.data, draft.item_type) {
        (ItemData::Password { username, password, url, totp_secret, notes }, ItemType::Password) => {
            rows.push(field_line("Username", username, field, &Field::Data(DataField::Username)));
            rows.push(field_line_mask("Password", password, field, &Field::Data(DataField::Password)));
            rows.push(field_line("URL", url, field, &Field::Data(DataField::Url)));
            rows.push(field_line_mask("TOTP", totp_secret, field, &Field::Data(DataField::TotpSecret)));
            rows.push(field_line("Notes", notes, field, &Field::Data(DataField::Notes)));
        }
        (ItemData::Note { format, content }, ItemType::Note) => {
            rows.push(field_line("Format", format, field, &Field::Data(DataField::Format)));
            rows.push(field_line("Content", content, field, &Field::Data(DataField::Content)));
        }
        (ItemData::Card { holder, number, expiry, cvv, bank, notes }, ItemType::Card) => {
            rows.push(field_line("Holder", holder, field, &Field::Data(DataField::Holder)));
            rows.push(field_line_mask("Number", number, field, &Field::Data(DataField::Number)));
            rows.push(field_line("Expiry", expiry, field, &Field::Data(DataField::Expiry)));
            rows.push(field_line_mask("CVV", cvv, field, &Field::Data(DataField::Cvv)));
            rows.push(field_line("Bank", bank, field, &Field::Data(DataField::Bank)));
            rows.push(field_line("Notes", notes, field, &Field::Data(DataField::Notes)));
        }
        _ => {
            rows.push(ratatui::text::Line::from("(type/data mismatch)").style(theme::error()));
        }
    }
    rows
}

/// 构造一行:label + 明文 value;若当前字段 == cur 则高亮并加光标标记。
fn field_line(label: &str, value: &str, cur: &Field, this: &Field) -> ratatui::text::Line<'static> {
    let active = cur == this;
    let body = if active {
        format!("▍{value}")
    } else {
        value.to_string()
    };
    let style = if active {
        theme::selected()
    } else {
        theme::fg()
    };
    ratatui::text::Line::from(format!("{label:<10}: {body}")).style(style)
}

/// 同上,但 value 以掩码展示(密码类字段)。
fn field_line_mask(label: &str, value: &str, cur: &Field, this: &Field) -> ratatui::text::Line<'static> {
    let masked = mask(value);
    field_line(label, &masked, cur, this)
}

// ---- 小工具 ----

fn label_value(label: &str, value: &str, secret: bool) -> ratatui::text::Line<'static> {
    let style = if secret { theme::accent2() } else { theme::fg() };
    ratatui::text::Line::from(format!("{label:<10}: {value}")).style(style)
}

fn mask(s: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        "•".repeat(s.chars().count())
    }
}

fn type_str(t: ItemType) -> &'static str {
    match t {
        ItemType::Password => "Password",
        ItemType::Note => "Note",
        ItemType::Card => "Card",
    }
}
