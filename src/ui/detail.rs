//! 详情/编辑面板:右栏。对应 PRD §8。
//!
//! - 无编辑器时:只读展示选中条目字段(密码默认掩码)。
//! - 有编辑器(NewItem/EditItem)时:渲染为表单,高亮当前 `editor.field`。

use ratatui::layout::Rect;
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

use super::theme;
use crate::app::{App, Cursor};
use crate::model::{template_display_name, FieldKind, Item};

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

    let mut lines = view_lines(item);

    // 附件区:在字段末尾追加(只读视图)。仅渲染元数据,不读 blob。
    let item_id = item.id;
    if let Some(id) = item_id {
        let mut att_lines = attachment_lines(app, id, matches!(app.mode, crate::app::Mode::Normal));
        lines.append(&mut att_lines);
    }

    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    frame.render_widget(p, inner);
}

/// 渲染附件清单行(不含 blob)。
///
/// 有附件:逐行 `📎 <filename> (<size>)`;无附件:`📎 (none)`。
/// `in_normal` 为真时末尾追加弱化提示 `press a to manage`。
fn attachment_lines(app: &App, item_id: i64, in_normal: bool) -> Vec<ratatui::text::Line<'static>> {
    let mut lines = Vec::new();
    lines.push(blank());
    let metas = attachment_summary(app, item_id);
    if metas.is_empty() {
        lines.push(ratatui::text::Line::from(vec![
            ratatui::text::Span::styled("📎 ", theme::accent2()),
            ratatui::text::Span::styled("(none)", theme::muted()),
        ]));
    } else {
        for (name, size) in metas {
            lines.push(ratatui::text::Line::from(vec![
                ratatui::text::Span::styled("📎 ", theme::accent2()),
                ratatui::text::Span::styled(name, theme::fg()),
                ratatui::text::Span::styled(format!(" ({})", size), theme::muted()),
            ]));
        }
    }
    if in_normal {
        lines.push(
            ratatui::text::Line::from("press a to manage").style(theme::muted()),
        );
    }
    lines
}

/// 查某 item 的附件元数据(不含 blob),返回 (filename, size) 列表。
fn attachment_summary(app: &App, item_id: i64) -> Vec<(String, i64)> {
    let Some(db) = app.db.as_ref() else {
        return Vec::new();
    };
    let conn = db.conn();
    let mut stmt = match conn.prepare(
        "SELECT filename, size FROM attachments WHERE item_id = ?1 ORDER BY id ASC",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt
        .query_map([item_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        });
    match rows {
        Ok(it) => it.filter_map(|r| r.ok()).collect(),
        Err(_) => Vec::new(),
    }
}

/// 只读视图的字段行。按 `kind` 渲染每个字段:Text/Multiline→普通,Secret→掩码,Totp→验证码。
fn view_lines(item: &Item) -> Vec<ratatui::text::Line<'static>> {
    let mut lines: Vec<ratatui::text::Line<'static>> = Vec::new();
    lines.push(field_view("Type", &template_display_name(&item.template_id)));
    lines.push(blank());
    for f in &item.fields {
        match f.kind {
            FieldKind::Totp => lines.push(totp_code_line_labeled(&f.name, &f.value)),
            FieldKind::Secret => lines.push(secret_view(&f.name, &f.value)),
            FieldKind::Multiline => {
                lines.push(blank());
                if f.value.is_empty() {
                    lines.push(ratatui::text::Line::from("(empty)").style(theme::muted()));
                } else {
                    for ln in f.value.lines() {
                        lines.push(ratatui::text::Line::from(ln.to_string()).style(theme::fg()));
                    }
                }
            }
            FieldKind::Text => lines.push(field_view(&f.name, &f.value)),
        }
    }
    lines
}

/// 编辑器视图:把 draft 渲染为表单,当前字段用高亮 + `▍` 光标标记。
fn render_editor(frame: &mut Frame, area: Rect, draft: &Item, field: &Cursor) {
    let inner = theme::panel_frame(frame, area, Some("Editor · Tab/^T totp/Enter/Esc"));

    let rows = editor_rows(draft, field);
    let p = Paragraph::new(rows).wrap(Wrap { trim: false });
    frame.render_widget(p, inner);
}

fn editor_rows(draft: &Item, field: &Cursor) -> Vec<ratatui::text::Line<'static>> {
    let mut rows = Vec::new();
    rows.push(field_line("Title", &draft.title, field, &Cursor::Title));
    for (i, f) in draft.fields.iter().enumerate() {
        let cur = Cursor::Field(i);
        match f.kind {
            FieldKind::Secret | FieldKind::Totp => {
                rows.push(field_line_mask(&f.name, &f.value, field, &cur));
            }
            _ => rows.push(field_line(&f.name, &f.value, field, &cur)),
        }
    }
    rows
}

/// 构造一行:label(青、定宽 10) + value;当前字段 == this 则高亮并加光标标记。
fn field_line(label: &str, value: &str, cur: &Cursor, this: &Cursor) -> ratatui::text::Line<'static> {
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
fn field_line_mask(label: &str, value: &str, cur: &Cursor, this: &Cursor) -> ratatui::text::Line<'static> {
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

/// 给定 totp secret(可能为空/非法),返回详情页 TOTP 行的渲染文本与样式。
///
/// - 空 secret → `<label> : —`(弱化)。
/// - 合法 secret → `<label> : <code>  (~Ns)`,code 用强调色,剩余秒用弱化色。
/// - 非法 secret → `<label> : (invalid)`,错误色。
///
/// label 用次强调(accent2),定宽 10 + `: ` 拼接风格。
#[cfg(test)]
fn totp_code_line(secret: &str) -> ratatui::text::Line<'static> {
    totp_code_line_labeled("TOTP", secret)
}

/// 同 [`totp_code_line`],但用自定义 label(字段名)。
fn totp_code_line_labeled(label: &str, secret: &str) -> ratatui::text::Line<'static> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let label = ratatui::text::Span::styled(format!("{:<10}", label), theme::accent2());
    let sep = ratatui::text::Span::raw(": ");

    // 空 secret:弱化破折号。
    if secret.is_empty() {
        return ratatui::text::Line::from(vec![
            label,
            sep,
            ratatui::text::Span::styled("—", theme::muted()),
        ]);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    match crate::totp::totp_at(secret, now) {
        Ok(code) => {
            let remaining = 30 - (now % 30);
            ratatui::text::Line::from(vec![
                label,
                sep,
                ratatui::text::Span::styled(code, theme::accent()),
                ratatui::text::Span::styled(format!("  (~{remaining}s)"), theme::muted()),
            ])
        }
        Err(_) => ratatui::text::Line::from(vec![
            label,
            sep,
            ratatui::text::Span::styled("(invalid)", theme::error()),
        ]),
    }
}

// ---- 小工具 ----

fn mask(s: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        "•".repeat(s.chars().count())
    }
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 把一行的 spans 文本拼接成纯字符串,便于断言。
    fn line_text(line: &ratatui::text::Line<'_>) -> String {
        line.spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<Vec<_>>()
            .join("")
    }

    #[test]
    fn totp_code_line_valid_secret_has_six_digits() {
        let line = totp_code_line("JBSWY3DPEHPK3PXP");
        let text = line_text(&line);
        assert!(text.contains("TOTP"), "line should contain TOTP label: {text}");
        // 抽取 6 位数字码:在 ": " 之后、空格之前。
        let code_part = text.split(": ").nth(1).unwrap_or("");
        let code = code_part.split_whitespace().next().unwrap_or("");
        assert_eq!(code.len(), 6, "code should be 6 digits: {text}");
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        // 剩余秒数提示存在。
        assert!(text.contains("(~") && text.contains("s)"), "missing countdown: {text}");
    }

    #[test]
    fn totp_code_line_empty_secret_shows_dash() {
        let line = totp_code_line("");
        let text = line_text(&line);
        assert!(text.contains("—"), "empty secret should show dash: {text}");
        // 不应出现数字码或 invalid。
        assert!(!text.contains("invalid"));
    }

    #[test]
    fn totp_code_line_invalid_secret_shows_invalid() {
        let line = totp_code_line("!!!");
        let text = line_text(&line);
        assert!(text.contains("invalid"), "illegal secret should show invalid: {text}");
    }
}
