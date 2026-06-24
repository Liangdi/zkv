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
use ratatui_sci_fi::widgets::{
    AlertPopup, AlertPopupState, Divider, GlitchText, GlitchTextState, PopupShape, Spinner,
    SpinnerState,
};
use ratatui_sci_fi::Theme;

use crate::app::{Action, App, Mode, PassKind};
use crate::error::Result;

type Tui = Terminal<CrosstermBackend<Stdout>>;

/// 每帧推进的「逻辑 tick」步进。主循环 `poll` 为 250ms(~4fps),而 sci-fi 的
/// 光标 blink 周期 `DEFAULT_CURSOR_PERIOD=15` 假设 ~60fps;直接按帧计数会让
/// 光标 ~3.75s 才闪一次。每帧步进 6 → ~0.6s/相位,接近标准 0.5s 闪烁。
const TICKS_PER_FRAME: u64 = 6;

/// 跨帧动画状态(纯 UI 层,不污染 `App` 业务状态 —— 尊重 MVC 边界)。
///
/// - `tick`:动画时钟,驱动 `TextInput` 光标闪烁。
/// - `glitch`:品牌故障字的有状态动画(PRNG/burst,必须持久化)。
/// - `alert`:删除确认弹窗的 flash 倒数。
/// - `spinner`:解锁中 loading 转圈(`Spinner`)的帧计数。
/// - `prev_mode`:模式切换 edge 检测,用于在进入告警模式时 arm flash。
#[derive(Default)]
struct Anim {
    tick: u64,
    glitch: GlitchTextState,
    alert: AlertPopupState,
    spinner: SpinnerState,
    prev_mode: Option<Mode>,
}

impl Anim {
    /// 每帧推进:动画时钟步进 + 各 widget state 自推进。
    fn step(&mut self) {
        self.tick = self.tick.wrapping_add(TICKS_PER_FRAME);
        self.glitch.tick();
        self.alert.tick();
        self.spinner.tick();
    }

    /// 模式切换 edge:切到 `ConfirmDelete` 时 arm 弹窗 flash(~2s 闪烁后稳态)。
    fn arm_alert_on_enter(&mut self, mode: &Mode) {
        if self.prev_mode.as_ref() != Some(mode) && *mode == Mode::ConfirmDelete {
            self.alert.flash(8);
        }
        self.prev_mode = Some(mode.clone());
    }
}

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

    let mut anim = Anim::default();
    let result = main_loop(&mut terminal, &mut app, &mut anim);

    // 显式恢复(guard 的 Drop 也会再做一次,作为兜底)。
    let _ = terminal.draw(|f| {
        // 最后一帧不强制;直接进 Drop。
        let _ = f;
    });
    result
}

fn main_loop(terminal: &mut Tui, app: &mut App, anim: &mut Anim) -> Result<()> {
    let lock_secs = lock_timeout_secs();
    let mut last_activity = Instant::now();
    loop {
        // 推进 UI 动画时钟 + 各 widget state(光标闪烁 / 故障字 / 弹窗 flash);
        // 模式切换 edge 检测:进入告警模式时 arm 弹窗 flash。
        anim.step();
        anim.arm_alert_on_enter(&app.mode);

        // Booting 态:drain 后台解锁结果(派生完成 → Normal,失败 → 口令态)。
        if app.boot_rx.is_some() {
            app.pump_boot()?;
        }

        // 每轮循环都检查自动锁定(而非只在 poll 超时分支):PTY / 终端下可能
        // 持续到达非按键事件(Resize/Focus/Mouse 等),使 event::poll 总返回
        // true、永不走超时分支;把检查放在循环顶部可保证超时后必触发锁定,
        // 且锁定后随后的 draw 会渲染口令面板。
        maybe_auto_lock(app, lock_secs, &last_activity);

        if terminal.draw(|f| draw(f, app, anim)).is_err() {
            // draw 失败(终端消失等):直接退出循环,由 guard 恢复。
            break;
        }

        // 阻塞等待事件;poll 返回 false(超时)时直接进入下一轮(顶部再检查)。
        // Booting 态用更短间隔(~20fps)让 loading 转圈流畅、派生完成后尽快切走;其余 250ms 省电。
        let poll_ms = if matches!(app.mode, Mode::Booting) { 50 } else { 250 };
        let Ok(true) = event::poll(Duration::from_millis(poll_ms)) else {
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
fn draw(frame: &mut Frame, app: &App, anim: &Anim) {
    if let Mode::PromptPassphrase(kind) = &app.mode {
        draw_passphrase(frame, app, *kind, anim);
        return;
    }
    if matches!(app.mode, Mode::Booting) {
        draw_loading(frame, app, anim);
        return;
    }

    // 纵向三段:header / body / footer。
    let whole = frame.area();
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(3),
        ])
        .split(whole);
    let header_area = vert[0];
    let body_area = vert[1];
    let footer_area = vert[2];

    render_header(frame, header_area, app, anim);

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
    list::render_list(frame, cols[0], app, anim.tick);
    detail::render_detail(frame, cols[1], app);

    render_footer(frame, footer_area, app);

    // 叠加模态
    match app.mode {
        Mode::ConfirmDelete => draw_confirm_delete(frame, app, anim),
        Mode::ImportTotp => draw_import_totp(frame, app, anim),
        Mode::PickTemplate => draw_pick_template(frame, app, anim),
        Mode::CategoryMgr => draw_category_mgr(frame, app, anim),
        Mode::TagMgr => draw_tag_mgr(frame, app, anim),
        Mode::Attachments => draw_attachments(frame, app, anim),
        _ => {}
    }
}

/// 口令输入:居中模态。三档自适应布局(完整 / 精简 / 紧凑):
/// - **完整**(inner ≥ 13 行):锁标 + Glitch 品牌 + 副标题 + 分隔线 + 路径 + 输入 + 提示。
/// - **精简**(inner ≥ 7 行):去掉锁标与分隔线,保留品牌/副标题/路径/输入/提示。
/// - **紧凑**(其余):仅路径 + 输入 + 消息 —— 保证极矮终端下输入框仍有 1 内容行
///   (回归保险:`passphrase_input_keeps_content_row_on_short_terminal`)。
fn draw_passphrase(frame: &mut Frame, app: &App, kind: PassKind, anim: &Anim) {
    let area = centered_rect(62, 72, frame.area());
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

    if inner.height >= 13 {
        // 完整版:锁标 / 品牌 / 副标题 / 分隔线 / 路径 / 输入 / 提示;上下各留 Min(0) 呼吸。
        let chunks = Layout::vertical([
            Constraint::Min(0),
            Constraint::Length(5), // 锁标
            Constraint::Length(1), // Glitch 品牌 zkv
            Constraint::Length(1), // 副标题
            Constraint::Length(1), // 分隔线
            Constraint::Length(1), // 路径
            Constraint::Length(3), // 口令输入(固定,优先保证可见)
            Constraint::Length(1), // 按键提示
            Constraint::Min(0),
        ])
        .split(inner);
        render_lock_art(frame, chunks[1]);
        render_brand(frame, chunks[2], anim);
        render_tagline(frame, chunks[3]);
        frame.render_widget(
            Divider::new().label("SECURE ACCESS").theme(Theme::Cyberpunk),
            chunks[4],
        );
        render_path_line(frame, chunks[5], &path);
        input::render_input(frame, chunks[6], &field, " passphrase ", anim.tick);
        render_passphrase_hints(frame, chunks[7], msg);
    } else if inner.height >= 7 {
        // 精简版:品牌 / 副标题 / 路径 / 输入 / 提示;去掉锁标与分隔线。
        let chunks = Layout::vertical([
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(inner);
        render_brand(frame, chunks[1], anim);
        render_tagline(frame, chunks[2]);
        render_path_line(frame, chunks[3], &path);
        input::render_input(frame, chunks[4], &field, " passphrase ", anim.tick);
        render_passphrase_hints(frame, chunks[5], msg);
    } else {
        // 紧凑版:路径 + 输入 + 消息。
        let sub =
            Layout::vertical([Constraint::Length(1), Constraint::Length(3), Constraint::Min(0)])
                .split(inner);
        render_path_line(frame, sub[0], &path);
        input::render_input(frame, sub[1], &field, " passphrase ", anim.tick);
        frame.render_widget(
            ratatui::widgets::Paragraph::new(msg).style(msg_style(msg)),
            sub[2],
        );
    }
}

/// ASCII 锁标(5 行,锁扣 + 锁体 + 圆盘)。每行由 `Paragraph` 居中渲染:
/// 锁扣(3 宽)与锁体(7 宽)各自独立居中,但锁扣的 │ 恰好落在锁体的 ┴ 之上,
/// 故视觉上对齐。
fn render_lock_art(frame: &mut Frame, area: Rect) {
    use ratatui::text::{Line, Span};
    let shackle = theme::accent2();
    let body = theme::accent2();
    let dial = theme::accent();
    let lines = vec![
        Line::styled("╭─╮", shackle),
        Line::styled("│ │", shackle),
        Line::styled("╭─┴─┴─╮", body),
        Line::from(vec![
            Span::styled("│ ", body),
            Span::styled("◉◉◉", dial),
            Span::styled(" │", body),
        ]),
        Line::styled("╰─────╯", body),
    ];
    let p = ratatui::widgets::Paragraph::new(lines)
        .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(p, area);
}

/// Glitch 品牌 "zkv":居中放置(手动算 x 偏移,GlitchText 不支持对齐)。
fn render_brand(frame: &mut Frame, area: Rect, anim: &Anim) {
    let text = "zkv";
    let w = text.chars().count() as u16;
    if area.width < w || area.height == 0 {
        return;
    }
    let x = area.x + (area.width - w) / 2;
    let mut glitch = anim.glitch.clone();
    let brand = GlitchText::new(text).intensity(0.15).theme(Theme::Cyberpunk);
    frame.render_stateful_widget(brand, Rect::new(x, area.y, w, 1), &mut glitch);
}

/// 副标题:弱化的产品定位。
fn render_tagline(frame: &mut Frame, area: Rect) {
    let line = ratatui::text::Line::styled("ZERO·KNOWLEDGE VAULT", theme::muted());
    frame.render_widget(
        ratatui::widgets::Paragraph::new(line).alignment(ratatui::layout::Alignment::Center),
        area,
    );
}

/// 路径行:`◆ <path>` 居中;◆ 用强调绿做点缀。
fn render_path_line(frame: &mut Frame, area: Rect, path: &str) {
    let line = ratatui::text::Line::from(vec![
        ratatui::text::Span::styled("◆ ", theme::accent()),
        ratatui::text::Span::styled(path, theme::muted()),
    ]);
    frame.render_widget(
        ratatui::widgets::Paragraph::new(line).alignment(ratatui::layout::Alignment::Center),
        area,
    );
}

/// 底部按键提示:`[ENTER] unlock   [ESC] quit`(键位青色,与底部键位栏一致)。
/// 有瞬态消息(成功/失败)时优先显示消息,失败类用红色。
fn render_passphrase_hints(frame: &mut Frame, area: Rect, msg: &str) {
    let line = if msg.is_empty() {
        ratatui::text::Line::from(vec![
            ratatui::text::Span::styled("[ENTER]", theme::accent2()),
            ratatui::text::Span::styled(" unlock   ", theme::fg()),
            ratatui::text::Span::styled("[ESC]", theme::muted()),
            ratatui::text::Span::styled(" quit", theme::muted()),
        ])
    } else {
        ratatui::text::Line::styled(msg.to_string(), msg_style(msg))
    };
    frame.render_widget(
        ratatui::widgets::Paragraph::new(line).alignment(ratatui::layout::Alignment::Center),
        area,
    );
}

/// 消息着色:含 fail/locked/panic → 红(错误),否则青(信息)。
fn msg_style(msg: &str) -> ratatui::style::Style {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("fail") || lower.contains("locked") || lower.contains("panic") {
        theme::error()
    } else {
        theme::accent2()
    }
}

/// Booting 态(解锁中):居中小面板渲染 sci-fi `Spinner`(盲文转圈)+ loading 文案,
/// 掩盖 Argon2id 派生 + 解密等待。转圈帧由 `Anim.spinner` 每帧推进,render 用 clone。
/// 一旦后台派生完成(`pump_boot`),立即切走,不额外占用时间。
///
/// 面板用**固定高度**(7 行,保证 inner ≥ 3 行不塌框);屏幕过矮(<7 行)或过窄时
/// 退化为无框单行 spinner,杜绝边框被文字溢出。
fn draw_loading(frame: &mut Frame, _app: &App, anim: &Anim) {
    let whole = frame.area();
    let label = "unlocking vault…";
    let label_w = label.chars().count() as u16;
    // Spinner 自带 glyph(accent)+ space + label(muted);total_w = 整条视觉宽度。
    let total_w = label_w.saturating_add(2);

    let spinner_area = if whole.height >= 7 {
        // 居中小面板:宽 38%(不窄于 total_w+4),高 7 行,整体夹到屏幕内。
        let panel_w = ((whole.width as u32 * 38 / 100) as u16).max(total_w.saturating_add(4));
        let w = panel_w.min(whole.width);
        let h = 7u16.min(whole.height);
        let x = whole.x + (whole.width - w) / 2;
        let y = whole.y + (whole.height - h) / 2;
        let area = Rect::new(x, y, w, h);
        frame.render_widget(Clear, area);
        let inner = theme::panel_frame(frame, area, Some("LOADING"));
        let row_y = inner.y + inner.height / 2;
        let sx = inner.x + inner.width.saturating_sub(total_w) / 2;
        Rect::new(sx, row_y, total_w.min(inner.width), 1)
    } else {
        // 矮屏退化:无框,整行居中 spinner。
        frame.render_widget(Clear, whole);
        let row_y = whole.y + whole.height / 2;
        let sx = whole.x + whole.width.saturating_sub(total_w) / 2;
        Rect::new(sx, row_y, total_w.min(whole.width), 1)
    };

    let mut state = anim.spinner.clone();
    let spinner = Spinner::new().label(label).theme(Theme::Cyberpunk);
    frame.render_stateful_widget(spinner, spinner_area, &mut state);
}

/// 确认删除模态:sci-fi `AlertPopup`(双线红框,进入时由 `Anim` arm 的 flash 闪 ~2s)。
fn draw_confirm_delete(frame: &mut Frame, app: &App, anim: &Anim) {
    let area = centered_rect(56, 20, frame.area());
    frame.render_widget(Clear, area);
    let title = app
        .selected_item()
        .map(|i| i.title.clone())
        .unwrap_or_default();
    // AlertPopup 的 message 是单行,把原来的 3 行(标题/空行/提示)压成一行。
    let msg = format!("Delete \"{title}\"?   ·   y confirm   n/Esc cancel");
    let popup = AlertPopup::new(msg)
        .title(" Confirm Delete ")
        .shape(PopupShape::Thick)
        .theme(Theme::Cyberpunk);
    // flash 倒数由 main_loop 每帧推进 anim.alert;render 用 clone 避免借 anim 可变。
    let mut state = anim.alert.clone();
    frame.render_stateful_widget(popup, area, &mut state);
}

/// TOTP/2FA 配置弹窗:说明 + 单行输入框(otpauth:// URI / 本地图片路径 / http(s)/data: URL)。
fn draw_import_totp(frame: &mut Frame, app: &App, anim: &Anim) {
    let area = centered_rect(64, 60, frame.area());
    frame.render_widget(Clear, area);
    let inner = theme::panel_frame(frame, area, Some(" Set TOTP / 2FA "));

    // info(4 行说明) + input(3 行) + hint/msg(Min)。
    let chunks = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .split(inner);

    let info = ratatui::widgets::Paragraph::new(vec![
        ratatui::text::Line::from("paste one of:").style(theme::muted()),
        ratatui::text::Line::from("  • otpauth://totp/...?secret=...").style(theme::muted()),
        ratatui::text::Line::from("  • local QR image path").style(theme::muted()),
        ratatui::text::Line::from("  • http(s)/data: image url").style(theme::muted()),
    ]);
    frame.render_widget(info, chunks[0]);

    let field = input::InputField {
        value: app.input.clone(),
        mask: false,
    };
    input::render_input(frame, chunks[1], &field, " totp source ", anim.tick);

    // 提示行;有瞬态消息(成功/失败)时优先显示消息。
    let msg = app.message.as_deref().unwrap_or("");
    let bottom = if msg.is_empty() {
        "Enter:confirm  Esc:cancel  (url fetch may pause briefly)".to_string()
    } else {
        msg.to_string()
    };
    let hint_p = ratatui::widgets::Paragraph::new(bottom).style(theme::muted());
    frame.render_widget(hint_p, chunks[2]);
}

/// 分类管理面板。
/// 模板选择面板(`n` 新建时挑选预设模板;j/k 选,Enter 进编辑器)。
fn draw_pick_template(frame: &mut Frame, app: &App, anim: &Anim) {
    let entries: Vec<String> = crate::model::builtin_templates()
        .iter()
        .map(|t| t.name.clone())
        .collect();
    draw_mgr(
        frame,
        app,
        anim,
        "New Item · Pick Template",
        &entries,
        app.tpl_selected,
        "j/k select  Enter confirm  Esc back",
        "(no templates)",
    );
}

fn draw_category_mgr(frame: &mut Frame, app: &App, anim: &Anim) {
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
        anim,
        "Categories",
        &entries,
        app.mgr_selected,
        "a:add  r:rename  x:del  Esc:back",
        "(none, press a to add)",
    );
}

/// 标签管理面板。
fn draw_tag_mgr(frame: &mut Frame, app: &App, anim: &Anim) {
    let entries: Vec<String> = app.tags.to_vec();
    draw_mgr(
        frame,
        app,
        anim,
        "Tags",
        &entries,
        app.mgr_selected,
        "a:add  r:rename  x:del  Esc:back",
        "(none, press a to add)",
    );
}

/// 附件管理面板:列出元数据(不含 blob),编辑态显示路径输入框。
fn draw_attachments(frame: &mut Frame, app: &App, anim: &Anim) {
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
        input::render_input(frame, chunks[1], &field, label, anim.tick);
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
#[allow(clippy::too_many_arguments)]
fn draw_mgr(
    frame: &mut Frame,
    app: &App,
    anim: &Anim,
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
        input::render_input(frame, chunks[1], &field, label, anim.tick);
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
fn render_header(frame: &mut Frame, area: Rect, app: &App, anim: &Anim) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(1),
            Constraint::Length(34),
        ])
        .split(area);

    // 左:品牌(sci-fi 故障字,偶发字符替换;颜色遵循 Cyberpunk 的 Glitch 规则 —
    // clean=fg、corrupt=alert 红,与之前的品红标题不同)。先填 bar 底色再画。
    frame.render_widget(ratatui::widgets::Block::default().style(theme::bar()), chunks[0]);
    let mut glitch = anim.glitch.clone();
    let brand = GlitchText::new(" zkv ").intensity(0.15).theme(Theme::Cyberpunk);
    frame.render_stateful_widget(brand, chunks[0], &mut glitch);

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

    // 右:计数(`▸` 分隔)+ 锁定态(◆ UNLOCKED 绿 / ■ LOCKED 红呼吸闪烁)。
    let unlocked = app.db.is_some();
    let (state_sym, state_label) = if unlocked { ("◆", "UNLOCKED") } else { ("■", "LOCKED") };
    let state_style = if unlocked {
        theme::accent()
    } else if (anim.tick / 8) % 2 == 0 {
        theme::error()
    } else {
        theme::muted()
    };
    let right = ratatui::widgets::Paragraph::new(ratatui::text::Line::from(vec![
        ratatui::text::Span::styled(
            format!(
                " {} items ▸ {}c ▸ {}t ▸ ",
                app.items.len(),
                app.categories.len(),
                app.tags.len()
            ),
            theme::muted(),
        ),
        ratatui::text::Span::styled(format!("{state_sym} "), state_style),
        ratatui::text::Span::styled(state_label, state_style),
    ]))
    .style(theme::bar())
    .alignment(ratatui::layout::Alignment::Right);
    frame.render_widget(right, chunks[2]);
}

/// 底部键位栏:sci-fi 圆角边框包裹 + HUD 按键(`[N]` 强调 / 动作弱化,` ▸ ` 分隔)。
fn render_footer(frame: &mut Frame, area: Rect, _app: &App) {
    let hints: &[(&str, &str)] = &[
        ("N", "NEW"),
        ("E", "EDIT"),
        ("X", "DEL"),
        ("/", "SEARCH"),
        ("Y", "COPY"),
        ("O", "OTP"),
        ("L", "LOCK"),
        ("C", "CAT"),
        ("T", "TAG"),
        ("Q", "QUIT"),
    ];
    let mut spans: Vec<ratatui::text::Span<'_>> = vec![ratatui::text::Span::raw(" ")];
    for (i, (k, label)) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(ratatui::text::Span::styled(" ▸ ", theme::muted()));
        }
        spans.push(ratatui::text::Span::styled(format!("[{k}]"), theme::accent2()));
        spans.push(ratatui::text::Span::styled(*label, theme::muted()));
    }
    let block = ratatui::widgets::Block::default()
        .borders(ratatui::widgets::Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(theme::border())
        .style(theme::bar());
    frame.render_widget(
        ratatui::widgets::Paragraph::new(ratatui::text::Line::from(spans)).block(block),
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
            let anim = Anim::default();
            term.draw(|f| draw_passphrase(f, &app, PassKind::Open, &anim)).unwrap();
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
