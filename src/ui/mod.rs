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
use std::time::{Duration, Instant};

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
    let lock_secs = lock_timeout_secs();
    let mut last_activity = Instant::now();
    loop {
        // 每轮循环都检查自动锁定(而非只在 poll 超时分支):PTY / 终端下可能
        // 持续到达非按键事件(Resize/Focus/Mouse 等),使 event::poll 总返回
        // true、永不走超时分支;把检查放在循环顶部可保证超时后必触发锁定,
        // 且锁定后随后的 draw 会渲染口令面板。
        maybe_auto_lock(app, lock_secs, &last_activity);

        if terminal.draw(|f| draw(f, app)).is_err() {
            // draw 失败(终端消失等):直接退出循环,由 guard 恢复。
            break;
        }

        // 阻塞等待事件;poll 返回 false(超时)时直接进入下一轮(顶部再检查)。
        let Ok(true) = event::poll(Duration::from_millis(250)) else {
            continue;
        };
        let ev = match event::read() {
            Ok(ev) => ev,
            Err(_) => break,
        };

        if let Event::Key(key) = ev {
            // 任意按键都算用户活动,刷新计时基准。
            last_activity = Instant::now();
            let action = app.handle_key(key)?;
            if matches!(action, Action::Quit) || app.quit {
                break;
            }
        }
    }
    Ok(())
}

/// 自动锁定超时阈值(秒)。读环境变量 `ZKV_LOCK_SECS`:
/// - 缺失 / 解析失败 / 非法 → 默认 **300**(5 分钟);
/// - `0` → **禁用**自动锁定。
///
/// 本函数只**读** env,不写,故无需 unsafe。
fn lock_timeout_secs() -> u64 {
    const DEFAULT: u64 = 300;
    let Some(raw) = std::env::var_os("ZKV_LOCK_SECS") else {
        return DEFAULT;
    };
    // 借助 String 解析:可一并拒绝带 `+`/`-` 之外的非法值与负值(u64 不含负数)。
    match raw.to_string_lossy().parse::<u64>() {
        Ok(v) => v,
        Err(_) => DEFAULT,
    }
}

/// 在主循环里检查是否已超过闲置阈值;若是则调用 `app.lock()`。
/// `lock_secs == 0` 禁用;`app.db.is_none()` 表示已锁/未解锁,不重复锁。
fn maybe_auto_lock(app: &mut App, lock_secs: u64, last_activity: &Instant) {
    if lock_secs == 0 {
        return;
    }
    if app.db.is_none() {
        return;
    }
    if last_activity.elapsed() >= Duration::from_secs(lock_secs) {
        app.lock();
    }
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
        Mode::PickTemplate => draw_pick_template(frame, app),
        Mode::CategoryMgr => draw_category_mgr(frame, app),
        Mode::TagMgr => draw_tag_mgr(frame, app),
        Mode::Attachments => draw_attachments(frame, app),
        _ => {}
    }
}

/// 口令输入:全屏模态(mask)。
fn draw_passphrase(frame: &mut Frame, app: &App, kind: PassKind) {
    // sci-fi Panel 自带 1 内边距 + 1 边框,上下各占 2 行。
    // info(1) + input(3) + msg(≥0):inner ≥ 4 行(面板 ≥ 8 行)即可保证 input 有 1 内容行,
    // 不再把 input 压成无内容的纯边框。passphrase 标注交给 input 的 legend(" passphrase "),
    // 避免与 info 内的标签重复占高。
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
    let info = ratatui::widgets::Paragraph::new(
        ratatui::text::Line::from(format!("file: {path}")).style(theme::muted()),
    );
    // input 固定 3 行(上边框 + 1 内容 + 下边框);info 压到 1 行,msg 用 Min(0) 不与 input
    // 竞争高度——这样 inner ≥ 4 行时 input 必有 1 内容行,短终端不再塌成纯边框。
    let sub = Layout::vertical([Constraint::Length(1), Constraint::Length(3), Constraint::Min(0)])
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
/// 模板选择面板(`n` 新建时挑选预设模板;j/k 选,Enter 进编辑器)。
fn draw_pick_template(frame: &mut Frame, app: &App) {
    let entries: Vec<String> = crate::model::builtin_templates()
        .iter()
        .map(|t| t.name.clone())
        .collect();
    draw_mgr(
        frame,
        app,
        "New Item · Pick Template",
        &entries,
        app.tpl_selected,
        "j/k select  Enter confirm  Esc back",
        "(no templates)",
    );
}

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

/// 附件管理面板:列出元数据(不含 blob),编辑态显示路径输入框。
fn draw_attachments(frame: &mut Frame, app: &App) {
    // 标题:Attachments · <item title>(尽量取锁定的 item 标题,否则 id)。
    let title = app
        .items
        .iter()
        .find(|i| i.id == app.att_item_id)
        .map(|i| i.title.clone())
        .or_else(|| app.att_item_id.map(|id| format!("#{}", id)))
        .unwrap_or_default();
    let panel_title = format!("Attachments · {}", title);

    let area = centered_rect(64, 60, frame.area());
    frame.render_widget(Clear, area);
    let editing = app.att_edit.is_some();
    let inner = theme::panel_frame(frame, area, Some(&panel_title));

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

    if editing {
        let field = input::InputField {
            value: app.input.clone(),
            mask: false,
        };
        let label = match app.att_edit {
            Some(crate::app::AttEdit::Add) => " path: ",
            Some(crate::app::AttEdit::Export) => " out: ",
            None => " ",
        };
        input::render_input(frame, chunks[1], &field, label);
    }

    if app.att_list.is_empty() {
        let empty = ratatui::widgets::Paragraph::new("(no attachments, press a to add)")
            .style(theme::muted());
        frame.render_widget(empty, list_area);
    } else {
        let items: Vec<ratatui::widgets::ListItem> = app
            .att_list
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let style = if i == app.att_selected {
                    theme::selected_bar()
                } else {
                    theme::fg()
                };
                let mark = if i == app.att_selected { "▸ " } else { "  " };
                let mime = a.mime_type.clone().unwrap_or_else(|| "-".into());
                let text = format!("{:<5} {:<24} {:<22} {}", a.id, a.filename, mime, a.size);
                ratatui::widgets::ListItem::new(ratatui::text::Line::from(vec![
                    ratatui::text::Span::raw(mark),
                    ratatui::text::Span::styled(text, style),
                ]))
            })
            .collect();
        let list = ratatui::widgets::List::new(items);
        frame.render_widget(list, list_area);
    }

    let hint = if editing {
        "Enter:confirm  Esc:cancel"
    } else {
        "a:add  e:export  x:del  Esc:back"
    };
    let hint_idx = if editing { 2 } else { 1 };
    let hint_p = ratatui::widgets::Paragraph::new(hint).style(theme::muted());
    frame.render_widget(hint_p, chunks[hint_idx]);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 串行化所有读写 `ZKV_LOCK_SECS` 的测试:env 非线程隔离,
    /// 默认并行测试运行器下多个测试并发 set/remove 同一 env 会产生竞态。
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap()
    }

    #[test]
    fn lock_timeout_secs_reads_env() {
        let _g = env_lock();

        // 0 = 禁用。
        // SAFETY: 持 env_lock,本函数内串行 set/remove,无并发竞态。
        unsafe {
            std::env::set_var("ZKV_LOCK_SECS", "0");
        }
        assert_eq!(lock_timeout_secs(), 0);

        // 正常值。
        // SAFETY: 同上。
        unsafe {
            std::env::set_var("ZKV_LOCK_SECS", "60");
        }
        assert_eq!(lock_timeout_secs(), 60);

        // 非法 / 负值 → 默认 300。
        // SAFETY: 同上。
        unsafe {
            std::env::set_var("ZKV_LOCK_SECS", "not-a-number");
        }
        assert_eq!(lock_timeout_secs(), 300);
        unsafe {
            std::env::set_var("ZKV_LOCK_SECS", "-5");
        }
        assert_eq!(lock_timeout_secs(), 300);

        // 缺失 env → 默认 300。
        // SAFETY: 同上。
        unsafe {
            std::env::remove_var("ZKV_LOCK_SECS");
        }
        assert_eq!(lock_timeout_secs(), 300);
    }

    /// 登录屏的 passphrase 输入框在任何 ≥ 16 行的终端下都必须保留 1 内容行
    /// (不塌成无内容的纯边框)。回归保险:解析 TestBackend 缓冲,断言掩码圆点 `•`
    /// 出现在画面中。
    #[test]
    fn passphrase_input_keeps_content_row_on_short_terminal() {
        use ratatui::backend::TestBackend;
        for h in [16u16, 20, 24] {
            let mut app = App::for_open(std::path::PathBuf::from("/tmp/x.zkv"));
            app.input = "mySecretPass".into();
            app.input_mask = true;
            let backend = TestBackend::new(80, h);
            let mut term = ratatui::Terminal::new(backend).unwrap();
            term.draw(|f| draw_passphrase(f, &app, PassKind::Open)).unwrap();
            let buf = term.backend().buffer();
            let rendered: String = (0..h)
                .flat_map(|y| (0..80u16).map(move |x| buf[(x, y)].symbol().to_string()))
                .collect();
            assert!(
                rendered.contains('•'),
                "passphrase input lost its content row at height {h}"
            );
        }
    }
}
