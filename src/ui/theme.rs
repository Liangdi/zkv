//! 科幻风主题:封装 [`ratatui_sci_fi`] 0.2.0 的调色板,提供 zkv 统一样式入口。
//!
//! 样式的**唯一来源**是 [`crate::style`] 里那份编译期 CSS(`ratatui_style` 解析):
//! `:root` token 的 RGB 与 Cyberpunk 调色板逐字节一致,故 TUI 视觉与之前完全相同,
//! 但 TUI 与 CLI 现在共享同一套配色(改一处即整体换肤)。每个公开样式函数用
//! `OnceLock` 缓存首次 `style::compute` 的结果(调色板编译期固定,样式恒定),
//! 每帧零计算成本。
//!
//! `panel_frame` 仍直接用 `ratatui_sci_fi::widgets::Panel`(霓虹边框效果好),
//! 仅颜色同源。`colors::*` 是裸 `Color` 直取(当前无调用点),保留 `PALETTE` 常量。

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::Frame;
use ratatui_sci_fi::themes::{Palette, Theme};
use ratatui_sci_fi::widgets::{Panel, PanelShape};

use std::sync::OnceLock;

use crate::style;

/// 面板边框形态(全局可调):Rounded=现代 AI 感,Double=复古终端,Thick=厚重。
/// 改这一处即可整体换肤。
pub const PANEL_SHAPE: PanelShape = PanelShape::Rounded;

/// 当前生效的调色板(编译期固定为 Cyberpunk)。仅供 `colors::*` 裸色直取。
const PALETTE: Palette = Theme::Cyberpunk.palette();

/// 取(并缓存)某个语义 class 对应的 `Style`。调色板恒定,首帧后直接命中缓存。
fn cached(slot: &'static OnceLock<Style>, classes: &'static [&'static str]) -> Style {
    *slot.get_or_init(|| style::compute(classes))
}

/// 背景色。
pub fn bg() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["bg"])
}

/// 面板/边框底色。
pub fn panel() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["panel"])
}

/// 普通文本样式。
pub fn fg() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["fg"])
}

/// 边框样式:霓虹青细边。
pub fn border() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["border"])
}

/// 标题样式:品红加粗。
pub fn title_style() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["title"])
}

/// 选中项高亮:品红前景 + 加粗。
pub fn selected() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["selected"])
}

/// 弱化文本(标签、说明、空态)。
pub fn muted() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["muted"])
}

/// 错误/告警文本。
pub fn error() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["err"])
}

/// 强调色(正向状态、收藏星标)。
pub fn accent() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["accent"])
}

/// 次强调(青)。
pub fn accent2() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["accent2"])
}

/// 裸 Color 访问(供需要直接颜色的场景)。
pub mod colors {
    use super::*;

    pub fn accent() -> Color {
        PALETTE.accent.color()
    }
    pub fn accent2() -> Color {
        PALETTE.accent2.color()
    }
    pub fn ok() -> Color {
        PALETTE.ok.color()
    }
    pub fn fg() -> Color {
        PALETTE.fg.color()
    }
    pub fn muted() -> Color {
        PALETTE.muted.color()
    }
    pub fn alert() -> Color {
        PALETTE.alert.color()
    }
    pub fn panel() -> Color {
        PALETTE.panel.color()
    }
}

/// 选中行背景填充色(用 panel 色做底,文字用 accent)。
pub fn selected_bar() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["selected_bar"])
}

/// header/footer 状态栏底色:panel 底 + 前景文字。
pub fn bar() -> Style {
    static C: OnceLock<Style> = OnceLock::new();
    cached(&C, &["bar"])
}

/// 带边框 + 标题的区块构造辅助(圆角,用于输入框等紧凑小盒)。
pub fn block(t: &str) -> ratatui::widgets::Block<'_> {
    use ratatui::widgets::{Block, BorderType, Borders};
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border())
        .title(t)
        .title_style(title_style())
        .style(Style::default().fg(PALETTE.fg.color()))
}

/// 渲染一个 sci-fi 面板(ratatui-sci-fi `Panel`:主题级霓虹边框 + 1 内边距 + 标题),
/// 返回内容区 Rect。取代手搓 `Block`,边框颜色/内边距来自 Cyberpunk 的 Frame 级联。
pub fn panel_frame(frame: &mut Frame, area: Rect, title: Option<&str>) -> Rect {
    let mut panel = Panel::new().theme(Theme::Cyberpunk).shape(PANEL_SHAPE);
    if let Some(t) = title {
        panel = panel.title(format!(" {t} "));
    }
    let inner = panel.inner(area);
    frame.render_widget(panel, area);
    inner
}

// 注:`PALETTE` 仍被 `colors::*` 与 `block()` 引用(裸色直取);语义样式则全部经
// `style::compute` 由 CSS 派生,二者 RGB 逐字节一致。

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::{Color, Modifier};

    /// 委托 + OnceLock 缓存路径必须返回与 Cyberpunk 调色板逐字节一致的样式。
    /// 这是「TUI 视觉零变化」的回归保险。
    #[test]
    fn theme_styles_match_cyberpunk_palette() {
        let title = title_style();
        assert_eq!(title.fg, Some(Color::Rgb(0xff, 0x00, 0x7f)));
        assert!(title.add_modifier.contains(Modifier::BOLD));

        assert_eq!(fg().fg, Some(Color::Rgb(0xf0, 0xe6, 0xff)));
        assert_eq!(border().fg, Some(Color::Rgb(0x00, 0xf0, 0xff))); // accent2 青
        assert_eq!(error().fg, Some(Color::Rgb(0xff, 0x20, 0x60))); // alert 红
        assert_eq!(accent().fg, Some(Color::Rgb(0x39, 0xff, 0x14))); // ok 绿
        assert_eq!(bg().bg, Some(Color::Rgb(0x08, 0x04, 0x14)));
        assert_eq!(panel().bg, Some(Color::Rgb(0x14, 0x0a, 0x22)));

        // selected_bar: bg=panel, fg=accent(粉), bold。
        let sb = selected_bar();
        assert_eq!(sb.bg, Some(Color::Rgb(0x14, 0x0a, 0x22)));
        assert_eq!(sb.fg, Some(Color::Rgb(0xff, 0x00, 0x7f)));
        assert!(sb.add_modifier.contains(Modifier::BOLD));
    }

    /// 重复调用命中 OnceLock 缓存,返回相同(且等于首次)的值——不 panic、不漂移。
    #[test]
    fn theme_caching_is_stable() {
        let a = title_style();
        let b = title_style();
        assert_eq!(a.fg, b.fg);
        assert_eq!(a.add_modifier, b.add_modifier);
    }
}

