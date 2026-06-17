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
            let action = app.handle_key(key).map_err(|e| e)?;
            if matches!(action, Action::Quit) || app.quit {
                break;
            }
        }
    }
    Ok(())
}

/// 单帧渲染:按 `app.mode` 分发。
fn draw(frame: &mut Frame, app: &App) {
    match &app.mode {
        Mode::PromptPassphrase(kind) => {
            draw_passphrase(frame, app, *kind);
            return;
        }
        _ => {}
    }

    // 三栏 + 顶部 message。
    let whole = frame.area();
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(1)])
        .split(whole);
    let msg_area = vert[0];
    let body_area = vert[1];

    // 顶部 message / 模式提示
    let msg_text = top_message(app);
    let msg_line = ratatui::widgets::Paragraph::new(msg_text)
        .style(theme::accent2());
    frame.render_widget(msg_line, msg_area);

    // 三栏:sidebar / list / detail
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(24),
            Constraint::Percentage(40),
            Constraint::Min(20),
        ])
        .split(body_area);
    list::render_sidebar(frame, cols[0], app);
    list::render_list(frame, cols[1], app);
    detail::render_detail(frame, cols[2], app);

    // 叠加模态
    match app.mode {
        Mode::ConfirmDelete => draw_confirm_delete(frame, app),
        Mode::CategoryMgr => draw_simple_modal(frame, "Category Manager", "Esc to return"),
        Mode::TagMgr => draw_simple_modal(frame, "Tag Manager", "Esc to return"),
        _ => {}
    }
}

/// 口令输入:全屏模态(mask)。
fn draw_passphrase(frame: &mut Frame, app: &App, kind: PassKind) {
    let area = centered_rect(60, 20, frame.area());
    frame.render_widget(Clear, area);

    let title = match kind {
        PassKind::Open => " Unlock Vault ",
        PassKind::Create => " Create New Vault ",
    };
    let path = app
        .path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(no path)".into());

    let block = theme::block(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);

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

/// 通用简单模态(分类/标签管理最小实现)。
fn draw_simple_modal(frame: &mut Frame, title: &str, body: &str) {
    let area = centered_rect(50, 25, frame.area());
    input::render_modal(frame, area, title, &[body]);
}

/// 顶部消息行。
fn top_message(app: &App) -> String {
    let mode_tag = match &app.mode {
        Mode::Normal => "NORMAL",
        Mode::Search => "SEARCH",
        Mode::NewItem(t) => match t {
            crate::model::ItemType::Password => "NEW·PASSWORD",
            crate::model::ItemType::Note => "NEW·NOTE",
            crate::model::ItemType::Card => "NEW·CARD",
        },
        Mode::EditItem => "EDIT",
        Mode::ConfirmDelete => "CONFIRM-DELETE",
        Mode::CategoryMgr => "CATEGORY-MGR",
        Mode::TagMgr => "TAG-MGR",
        Mode::PromptPassphrase(_) => "LOCKED",
    };
    let msg = app.message.as_deref().unwrap_or("");
    format!(" [{mode_tag}]  {msg}  ·  n:new e:edit x:del /:search y:copy l:lock q:quit")
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
