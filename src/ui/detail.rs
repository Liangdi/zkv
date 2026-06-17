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

    // 标题随选中条目变化;无选中时回落到通用 "Detail"。
    let title = app
        .selected_item()
        .map(|i| i.title.clone())
        .unwrap_or_else(|| "Detail".into());
    let inner = theme::panel_frame(frame, area, Some(&title));

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
    let mut lines: Vec<ratatui::text::Line<'static>> = Vec::new();
    lines.push(field_view("Type", type_str(item.item_type)));
    lines.push(blank());
    match &item.data {
        ItemData::Password {
            username,
            password,
            url,
            totp_secret,
            notes,
        } => {
            lines.push(field_view("Username", username));
            lines.push(password_view(password));
            lines.push(field_view("URL", url));
            lines.push(secret_view("TOTP", totp_secret));
            lines.push(blank());
            lines.push(field_view("Notes", notes));
        }
        ItemData::Note { format, content } => {
            lines.push(field_view("Format", format));
            lines.push(blank());
            if content.is_empty() {
                lines.push(ratatui::text::Line::from("(empty)").style(theme::muted()));
            } else {
                for ln in content.lines() {
                    lines.push(ratatui::text::Line::from(ln.to_string()).style(theme::fg()));
                }
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
            lines.push(field_view("Holder", holder));
            lines.push(secret_view("Number", number));
            lines.push(field_view("Expiry", expiry));
            lines.push(secret_view("CVV", cvv));
            lines.push(field_view("Bank", bank));
            lines.push(blank());
            lines.push(field_view("Notes", notes));
        }
    }
    lines
}

/// 编辑器视图:把 draft 渲染为表单,当前字段用高亮 + `▍` 光标标记。
fn render_editor(frame: &mut Frame, area: Rect, draft: &Item, field: &Field) {
    let inner = theme::panel_frame(frame, area, Some("Editor · Tab/Enter/Esc"));

    let rows = editor_rows(draft, field);
    let p = Paragraph::new(rows).wrap(Wrap { trim: false });
    frame.render_widget(p, inner);
}

fn editor_rows(draft: &Item, field: &Field) -> Vec<ratatui::text::Line<'static>> {
    let mut rows = Vec::new();
    rows.push(field_line("Title", &draft.title, field, &Field::Title));

    match (&draft.data, draft.item_type) {
        (
            ItemData::Password {
                username,
                password,
                url,
                totp_secret,
                notes,
            },
            ItemType::Password,
        ) => {
            rows.push(field_line(
                "Username",
                username,
                field,
                &Field::Data(DataField::Username),
            ));
            rows.push(field_line_mask(
                "Password",
                password,
                field,
                &Field::Data(DataField::Password),
            ));
            rows.push(field_line("URL", url, field, &Field::Data(DataField::Url)));
            rows.push(field_line_mask(
                "TOTP",
                totp_secret,
                field,
                &Field::Data(DataField::TotpSecret),
            ));
            rows.push(field_line("Notes", notes, field, &Field::Data(DataField::Notes)));
        }
        (ItemData::Note { format, content }, ItemType::Note) => {
            rows.push(field_line(
                "Format",
                format,
                field,
                &Field::Data(DataField::Format),
            ));
            rows.push(field_line(
                "Content",
                content,
                field,
                &Field::Data(DataField::Content),
            ));
        }
        (
            ItemData::Card {
                holder,
                number,
                expiry,
                cvv,
                bank,
                notes,
            },
            ItemType::Card,
        ) => {
            rows.push(field_line(
                "Holder",
                holder,
                field,
                &Field::Data(DataField::Holder),
            ));
            rows.push(field_line_mask(
                "Number",
                number,
                field,
                &Field::Data(DataField::Number),
            ));
            rows.push(field_line(
                "Expiry",
                expiry,
                field,
                &Field::Data(DataField::Expiry),
            ));
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

/// 构造一行:label(青、定宽 10) + value;当前字段 == this 则高亮并加光标标记。
fn field_line(label: &str, value: &str, cur: &Field, this: &Field) -> ratatui::text::Line<'static> {
    let active = cur == this;
    let body = if active {
        format!("▍{value}")
    } else if value.is_empty() {
        "—".into()
    } else {
        value.to_string()
    };
    let vstyle = if active {
        theme::selected()
    } else if value.is_empty() {
        theme::muted()
    } else {
        theme::fg()
    };
    ratatui::text::Line::from(vec![
        ratatui::text::Span::styled(format!("{label:<10}"), theme::accent2()),
        ratatui::text::Span::raw(": "),
        ratatui::text::Span::styled(body, vstyle),
    ])
}

/// 同上,但 value 以掩码展示(密码类字段)。
fn field_line_mask(label: &str, value: &str, cur: &Field, this: &Field) -> ratatui::text::Line<'static> {
    let masked = mask(value);
    field_line(label, &masked, cur, this)
}

// ---- 只读视图字段行辅助 ----

fn blank() -> ratatui::text::Line<'static> {
    ratatui::text::Line::from("")
}

/// 普通字段:空值显示 `—`(弱化)。
fn field_view(label: &str, value: &str) -> ratatui::text::Line<'static> {
    let (text, style) = if value.is_empty() {
        ("—".to_string(), theme::muted())
    } else {
        (value.to_string(), theme::fg())
    };
    ratatui::text::Line::from(vec![
        ratatui::text::Span::styled(format!("{label:<10}"), theme::accent2()),
        ratatui::text::Span::raw(": "),
        ratatui::text::Span::styled(text, style),
    ])
}

/// 敏感字段:非空显示掩码圆点(强调色),空显示 `—`。
fn secret_view(label: &str, value: &str) -> ratatui::text::Line<'static> {
    let (text, style) = if value.is_empty() {
        ("—".to_string(), theme::muted())
    } else {
        (mask(value), theme::accent())
    };
    ratatui::text::Line::from(vec![
        ratatui::text::Span::styled(format!("{label:<10}"), theme::accent2()),
        ratatui::text::Span::raw(": "),
        ratatui::text::Span::styled(text, style),
    ])
}

/// 密码字段:掩码圆点 + `[y] copy` 提示。
fn password_view(password: &str) -> ratatui::text::Line<'static> {
    let mut spans = vec![
        ratatui::text::Span::styled(format!("{:<10}", "Password"), theme::accent2()),
        ratatui::text::Span::raw(": "),
    ];
    if password.is_empty() {
        spans.push(ratatui::text::Span::styled("—", theme::muted()));
    } else {
        spans.push(ratatui::text::Span::styled(mask(password), theme::accent()));
        spans.push(ratatui::text::Span::styled("   [y] copy", theme::accent2()));
    }
    ratatui::text::Line::from(spans)
}

// ---- 小工具 ----

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
