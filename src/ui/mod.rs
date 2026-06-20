//! TUI 主循环:终端初始化、事件循环、渲染分发、终端恢复。对应 PRD §8。
//!
//! - [`run`] 启动:启用 raw mode + AlternateScreen,构建 `Terminal`,循环
//!   `draw → poll → read → app.handle_key`,按 `Action::Quit` / `app.quit` 退出。
//! - 终端恢复使用 [`TerminalGuard`](`Drop`):即使中途 panic/返回错误,也会
//!   离开 AlternateScreen 并关闭 raw mode,避免卡在 raw mode。

pub mod detail;
pub mod input;
pub mod list;
pub mod theme;

use std::io::{self, Stdout};

use crossterm::event::{self, Event};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::execute;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::widgets::Clear;
use ratatui::{Frame, Terminal};

use crate::app::{Action, App, Mode, PassKind};
use crate::error::Result;

type Tui = Terminal<CrosstermBackend<Stdout>>;

/// 运行 TUI 主循环。返回前确保终端已恢复。
pub fn run(mut app: App) -> Result<()> {
    // 终端设置:任何失败都要回落。
    enable_raw_mode().map_err(map_io)?;
    let mut stdout = io::stdout();
    if execute!(stdout, EnterAlternateScreen).is_err() {
        // 进入备用屏失败也要关 raw mode。
        let _ = disable_raw_mode();
        return Err(crate::error::Error::Other("tui: enter alternate screen failed".into()));
    }

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(e) => {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            return Err(map_io(e));
        }
    };

    // 用 guard 包裹,确保任何退出路径(含?)都会恢复终端。
    let _guard = TerminalGuard;

    let result = main_loop(&mut terminal, &mut app);

    // 显式恢复(guard 的 Drop 也会再做一次,作为兜底)。
    let _ = terminal.draw(|f| {
        // 最后一帧不强制;直接进 Drop。
        let _ = f;
    });
    result
}

fn main_loop(terminal: &mut Tui, app: &mut App) -> Result<()> {
    loop {
        if terminal.draw(|f| draw(f, app)).is_err() {
            // draw 失败(终端消失等):直接退出循环,由 guard 恢复。
            break;
        }

        // 阻塞等待事件;poll 返回 false(超时)时重绘即可。
        let Ok(true) = event::poll(std::time::Duration::from_millis(250)) else {
            continue;
        };
        let ev = match event::read() {
            Ok(ev) => ev,
            Err(_) => break,
        };

        if let Event::Key(key) = ev {
            let action = app.handle_key(key)?;
            if matches!(action, Action::Quit) || app.quit {
                break;
            }
        }
    }
    Ok(())
}

/// 单帧渲染:按 `app.mode` 分发。
fn draw(frame: &mut Frame, app: &App) {
    if let Mode::PromptPassphrase(kind) = &app.mode {
        draw_passphrase(frame, app, *kind);
        return;
    }

    // 纵向三段:header / body / footer。
    let whole = frame.area();
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(whole);
    let header_area = vert[0];
    let body_area = vert[1];
    let footer_area = vert[2];

    render_header(frame, header_area, app);

    // 先给 body 填底,保证列间 spacing 缝隙干净(无 diff 残影)。
    frame.render_widget(
        ratatui::widgets::Block::default().style(theme::bg()),
        body_area,
    );

    // 两栏:list / detail,中间留 1 列缝。
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .spacing(1)
        .split(body_area);
    list::render_list(frame, cols[0], app);
    detail::render_detail(frame, cols[1], app);

    render_footer(frame, footer_area, app);

    // 叠加模态
    match app.mode {
        Mode::ConfirmDelete => draw_confirm_delete(frame, app),
        Mode::CategoryMgr => draw_category_mgr(frame, app),
        Mode::TagMgr => draw_tag_mgr(frame, app),
        _ => {}
    }
}

/// 口令输入:全屏模态(mask)。
fn draw_passphrase(frame: &mut Frame, app: &App, kind: PassKind) {
    // sci-fi Panel 自带 1 内边距 + 1 边框,故上下各占 2 行;内容需 7 行 → 至少 11 行。
    // 50% 在 80×24 下得 12 行,内层 8 行,info(3)+input(3)+msg(1) 宽裕。
    let area = centered_rect(60, 50, frame.area());
    frame.render_widget(Clear, area);

    let title = match kind {
        PassKind::Open => "Unlock Vault",
        PassKind::Create => "Create New Vault",
    };
    let path = app
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(no path)".into());

    let inner = theme::panel_frame(frame, area, Some(title));

    let field = input::InputField {
        value: app.input.clone(),
        mask: app.input_mask,
    };

    let msg = app.message.as_deref().unwrap_or("");
    let lines = vec![
        ratatui::text::Line::from(format!("file: {path}")).style(theme::muted()),
        ratatui::text::Line::from(""),
        ratatui::text::Line::from("passphrase:").style(theme::title_style()),
    ];
    let info = ratatui::widgets::Paragraph::new(lines);
    // 先把标题信息渲染到 inner 上半部分。
    let sub = Layout::vertical([Constraint::Length(3), Constraint::Length(3), Constraint::Min(1)])
        .split(inner);
    frame.render_widget(info, sub[0]);
    input::render_input(frame, sub[1], &field, " passphrase ");
    let msg_p = ratatui::widgets::Paragraph::new(msg).style(theme::accent2());
    frame.render_widget(msg_p, sub[2]);
}

/// 确认删除模态。
fn draw_confirm_delete(frame: &mut Frame, app: &App) {
    let area = centered_rect(50, 30, frame.area());
    let title = app.selected_item().map(|i| i.title.clone()).unwrap_or_default();
    let l1: std::borrow::Cow<str> = std::borrow::Cow::Owned(format!("Delete \"{}\"?", title));
    let l2: std::borrow::Cow<str> = std::borrow::Cow::Borrowed("");
    let l3: std::borrow::Cow<str> = std::borrow::Cow::Borrowed("press y to confirm · n/Esc to cancel");
    let lines: [&str; 3] = [l1.as_ref(), l2.as_ref(), l3.as_ref()];
    input::render_modal(frame, area, " Confirm Delete ", &lines);
}

/// 分类管理面板。
fn draw_category_mgr(frame: &mut Frame, app: &App) {
    let entries: Vec<String> = app
        .categories
        .iter()
        .map(|c| {
            if let Some(pid) = c.parent_id {
                // 尽量把 parent 名标出;找不到则只标 id。
                let pname = app
                    .categories
                    .iter()
                    .find(|p| p.id == Some(pid))
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| format!("#{pid}"));
                format!("{} (parent: {})", c.name, pname)
            } else {
                c.name.clone()
            }
        })
        .collect();
    draw_mgr(
        frame,
        app,
        "Categories",
        &entries,
        app.mgr_selected,
        "a:add  r:rename  x:del  Esc:back",
        "(none, press a to add)",
    );
}

/// 标签管理面板。
fn draw_tag_mgr(frame: &mut Frame, app: &App) {
    let entries: Vec<String> = app.tags.to_vec();
    draw_mgr(
        frame,
        app,
        "Tags",
        &entries,
        app.mgr_selected,
        "a:add  r:rename  x:del  Esc:back",
        "(none, press a to add)",
    );
}

/// 管理面板通用渲染:列表 + (编辑态)输入框 + 提示行。
fn draw_mgr(
    frame: &mut Frame,
    app: &App,
    title: &str,
    entries: &[String],
    selected: usize,
    browse_hint: &str,
    empty_hint: &str,
) {
    let area = centered_rect(56, 56, frame.area());
    frame.render_widget(Clear, area);

    let editing = app.mgr_edit.is_some();
    let inner = theme::panel_frame(frame, area, Some(title));

    // inner 内部:列表 / [输入框] / 提示行。
    let constraints = if editing {
        vec![
            Constraint::Min(1),
            Constraint::Length(3),
            Constraint::Length(1),
        ]
    } else {
        vec![Constraint::Min(1), Constraint::Length(1)]
    };
    let chunks = Layout::vertical(constraints).split(inner);
    let list_area = chunks[0];

    // 输入框(编辑态)。
    if editing {
        let field = input::InputField {
            value: app.input.clone(),
            mask: false,
        };
        let label = match app.mgr_edit {
            Some(crate::app::MgrEdit::Add) => " add ",
            Some(crate::app::MgrEdit::Rename) => " rename ",
            None => " ",
        };
        input::render_input(frame, chunks[1], &field, label);
    }

    // 列表区。
    if entries.is_empty() {
        let empty = ratatui::widgets::Paragraph::new(empty_hint).style(theme::muted());
        frame.render_widget(empty, list_area);
    } else {
        let items: Vec<ratatui::widgets::ListItem> = entries
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let style = if i == selected {
                    theme::selected_bar()
                } else {
                    theme::fg()
                };
                let mark = if i == selected { "▸ " } else { "  " };
                ratatui::widgets::ListItem::new(ratatui::text::Line::from(vec![
                    ratatui::text::Span::raw(mark),
                    ratatui::text::Span::styled(name.clone(), style),
                ]))
            })
            .collect();
        let list = ratatui::widgets::List::new(items);
        frame.render_widget(list, list_area);
    }

    // 提示行。
    let hint = if editing {
        "Enter:confirm  Esc:cancel"
    } else {
        browse_hint
    };
    let hint_idx = if editing { 2 } else { 1 };
    let hint_p = ratatui::widgets::Paragraph::new(hint).style(theme::muted());
    frame.render_widget(hint_p, chunks[hint_idx]);
}

/// 顶部状态栏:品牌 · 消息(或库路径) · 条目/锁定状态。
fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(1),
            Constraint::Length(34),
        ])
        .split(area);

    // 左:品牌。
    let brand = ratatui::widgets::Paragraph::new(
        ratatui::text::Line::from(" zkv ").style(theme::title_style()),
    )
    .style(theme::bar());
    frame.render_widget(brand, chunks[0]);

    // 中:瞬态消息(强调),否则库路径(弱化)。
    let (center_text, center_style) = match app.message.as_deref() {
        Some(m) if !m.is_empty() => (m.to_string(), theme::accent2()),
        _ => (
            app.path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            theme::muted(),
        ),
    };
    let center = ratatui::widgets::Paragraph::new(
        ratatui::text::Line::from(center_text).style(center_style),
    )
    .style(theme::bar());
    frame.render_widget(center, chunks[1]);

    // 右:计数 + 锁定态。
    let unlocked = app.db.is_some();
    let state_label = if unlocked { "unlocked" } else { "locked" };
    let state_style = if unlocked { theme::accent() } else { theme::error() };
    let right = ratatui::widgets::Paragraph::new(ratatui::text::Line::from(vec![
        ratatui::text::Span::styled(
            format!(
                " {} items · {}c · {}t · ",
                app.items.len(),
                app.categories.len(),
                app.tags.len()
            ),
            theme::muted(),
        ),
        ratatui::text::Span::styled("● ", state_style),
        ratatui::text::Span::styled(state_label.to_string(), state_style),
    ]))
    .style(theme::bar())
    .alignment(ratatui::layout::Alignment::Right);
    frame.render_widget(right, chunks[2]);
}

/// 底部键位栏:键名(青) + 说明(弱化)。
fn render_footer(frame: &mut Frame, area: Rect, _app: &App) {
    let hints: &[(&str, &str)] = &[
        ("n", "new"),
        ("e", "edit"),
        ("x", "del"),
        ("/", "search"),
        ("y", "copy"),
        ("o", "otp"),
        ("l", "lock"),
        ("c", "cat"),
        ("t", "tag"),
        ("q", "quit"),
    ];
    let mut spans: Vec<ratatui::text::Span<'_>> = vec![ratatui::text::Span::raw(" ")];
    for (i, (k, label)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(ratatui::text::Span::raw("   "));
        }
        spans.push(ratatui::text::Span::styled(*k, theme::accent2()));
        spans.push(ratatui::text::Span::styled(format!(":{label}"), theme::muted()));
    }
    frame.render_widget(
        ratatui::widgets::Paragraph::new(ratatui::text::Line::from(spans)).style(theme::bar()),
        area,
    );
}

// ---- helpers ----

/// 居中矩形(宽、高为百分比)。
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let pop_h = area.height * percent_y / 100;
    let pop_w = area.width * percent_x / 100;
    let y = area.y + (area.height.saturating_sub(pop_h)) / 2;
    let x = area.x + (area.width.saturating_sub(pop_w)) / 2;
    Rect::new(x, y, pop_w, pop_h)
}

fn map_io(e: io::Error) -> crate::error::Error {
    crate::error::Error::Other(format!("tui io: {e}"))
}

/// 终端恢复守卫:`Drop` 时离开 AlternateScreen 并关闭 raw mode。
/// 即便主循环因 panic 提前展开栈,Drop 仍会执行(unwind 路径)。
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let mut out = io::stdout();
        let _ = execute!(out, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}
