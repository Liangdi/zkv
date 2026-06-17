//! 科幻风主题:封装 [`ratatui_sci_fi`] 0.2.0 的调色板,提供 zkv 统一样式入口。
//!
//! `ratatui_sci_fi` 0.2.0 提供的核心能力是 **`Theme` 枚举 + `Palette`**(语义化 RGB
//! 调色板:`accent`/`accent2`/`bg`/`panel`/`fg`/`muted`/`ok`/`warn`/`alert`)以及一套
//! CSS 级联 stylesheet(主要供其自带 widget 使用)。zkv 的 TUI 直接使用 `Palette` 的
//! `Color` 来构建 ratatui `Style`,无需触碰 stylesheet 引擎。
//!
//! 选用默认的 **Cyberpunk** 主题(荧光粉 / 霓虹青 / 亮绿),契合“保险箱/终端”科技感:
//! 深底 + 霓虹青描边,品红/绿高亮。

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::Frame;
use ratatui_sci_fi::themes::{Palette, Theme};
use ratatui_sci_fi::widgets::{Panel, PanelShape};

/// 面板边框形态(全局可调):Rounded=现代 AI 感,Double=复古终端,Thick=厚重。
/// 改这一处即可整体换肤。
pub const PANEL_SHAPE: PanelShape = PanelShape::Rounded;

/// 当前生效的调色板(编译期固定为 Cyberpunk)。
const PALETTE: Palette = Theme::Cyberpunk.palette();

/// 背景色。
pub fn bg() -> Style {
    Style::default().bg(PALETTE.bg.color())
}

/// 面板/边框底色。
pub fn panel() -> Style {
    Style::default().bg(PALETTE.panel.color())
}

/// 普通文本样式。
pub fn fg() -> Style {
    Style::default().fg(PALETTE.fg.color())
}

/// 边框样式:霓虹青细边。
pub fn border() -> Style {
    Style::default().fg(PALETTE.accent2.color())
}

/// 标题样式:品红加粗。
pub fn title_style() -> Style {
    Style::default()
        .fg(PALETTE.accent.color())
        .add_modifier(Modifier::BOLD)
}

/// 选中项高亮:品红前景 + 加粗。
pub fn selected() -> Style {
    Style::default()
        .fg(PALETTE.accent.color())
        .add_modifier(Modifier::BOLD)
}

/// 弱化文本(标签、说明、空态)。
pub fn muted() -> Style {
    Style::default().fg(PALETTE.muted.color())
}

/// 错误/告警文本。
pub fn error() -> Style {
    Style::default().fg(PALETTE.alert.color())
}

/// 强调色(正向状态、收藏星标)。
pub fn accent() -> Style {
    Style::default().fg(PALETTE.ok.color())
}

/// 次强调(青)。
pub fn accent2() -> Style {
    Style::default().fg(PALETTE.accent2.color())
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
    Style::default()
        .bg(PALETTE.panel.color())
        .fg(PALETTE.accent.color())
        .add_modifier(Modifier::BOLD)
}

/// header/footer 状态栏底色:panel 底 + 前景文字。
pub fn bar() -> Style {
    Style::default()
        .bg(PALETTE.panel.color())
        .fg(PALETTE.fg.color())
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
