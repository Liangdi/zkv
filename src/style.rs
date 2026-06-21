//! 统一主题源:`ratatui_style` 解析一份编译期 CSS,同时供给 **TUI**(`ratatui::Style`)
//! 与 **CLI**(ANSI 字符串)。TUI 与 CLI 同源,改这一处即可整体换肤。
//!
//! ## 命名 footgun(务必注意)
//! 这里的 class 名**对齐 `ui/theme.rs` 的语义**,而非字面颜色:
//! - `.accent` = **绿**(`ok`)——对应 `theme::accent()` 用的是 `PALETTE.ok`;
//! - `.err`    = **红**(`alert`);`.warn` = 琥珀;`.ok` = 绿。
//!
//! 不要按 CSS 常识把 `.accent` 当作品红。
//!
//! ## 配色
//! `:root` token 的 RGB 与 `ratatui_sci_fi::themes::palette::CYBERPUNK` 逐字节一致,
//! 因此 TUI 视觉与改动前完全相同。

use std::io::IsTerminal;
use std::sync::OnceLock;

use ratatui::style::{Color as RColor, Modifier, Style as RStyle};
use ratatui_style::{ComputeScratch, NodeRef, Stylesheet};

/// 唯一主题表。RGB = Cyberpunk 调色板;class 名对齐 `ui/theme.rs` 语义。
const THEME_CSS: &str = r#"
:root {
  --accent:  #ff007f;
  --accent2: #00f0ff;
  --bg:      #080414;
  --panel:   #140a22;
  --fg:      #f0e6ff;
  --muted:   #6a3a7a;
  --ok:      #39ff14;
  --warn:    #ffb000;
  --alert:   #ff2060;
}
/* —— TUI 语义(对齐 ui/theme.rs)—— */
.title,.selected     { color: var(--accent); font-weight: bold; }
.border              { color: var(--accent2); }
.fg                  { color: var(--fg); }
.muted               { color: var(--muted); }
.accent              { color: var(--ok); }      /* theme::accent() = 绿 */
.accent2             { color: var(--accent2); }
.bg                  { background: var(--bg); }
.panel               { background: var(--panel); }
.bar                 { background: var(--panel); color: var(--fg); }
.selected_bar        { background: var(--panel); color: var(--accent); font-weight: bold; }
/* —— CLI 语义 —— */
.ok                  { color: var(--ok); }
.warn                { color: var(--warn); }
.err                 { color: var(--alert); }
.id                  { color: var(--accent2); }
.key                 { color: var(--accent2); }
.val                 { color: var(--fg); }
"#;

/// 解析一次的全局样式表。CSS 是编译期常量,解析失败 = authoring bug,fail-fast。
pub fn sheet() -> &'static Stylesheet {
    static SHEET: OnceLock<Stylesheet> = OnceLock::new();
    SHEET.get_or_init(|| {
        Stylesheet::parse(THEME_CSS).expect("zkv: theme CSS must parse (authoring bug)")
    })
}

// 绘制循环用的 per-thread 计算暂存区(`compute_with` 需要可变借用)。
thread_local! {
    static SCRATCH: std::cell::RefCell<ComputeScratch> =
        std::cell::RefCell::new(ComputeScratch::new());
}

/// 把一组 class 计算成 `ratatui::Style`。zkv 的查询都是扁平单元素(仅 class 选择器,
/// 无后代组合),无 parent 继承。首次调用后零分配。
pub fn compute(classes: &[&str]) -> RStyle {
    SCRATCH.with(|cell| {
        let mut g = cell.borrow_mut();
        let node = NodeRef::new("Div").classes(classes);
        sheet().compute_with(&node, None, &mut g).to_style()
    })
}

// ===========================================================================
// CLI 着色能力检测 + ANSI 渲染
// ===========================================================================

/// 全局环境覆盖:`NO_COLOR`(任意值,含空)→ 关;`CLICOLOR_FORCE != "0"`→ 开;否则 None。
fn env_override() -> Option<bool> {
    if std::env::var_os("NO_COLOR").is_some() {
        return Some(false);
    }
    if let Ok(v) = std::env::var("CLICOLOR_FORCE") {
        if v != "0" {
            return Some(true);
        }
    }
    None
}

fn stream_enabled(is_tty: bool) -> bool {
    if let Some(v) = env_override() {
        return v;
    }
    // available_color_count 读 COLORTERM/TERM(真彩色=65535、256、默认 8),本身不判 tty。
    is_tty && crossterm::style::available_color_count() > 0
}

/// stdout 是否应着色。优先级:NO_COLOR > CLICOLOR_FORCE > (stdout 是 tty 且支持彩色)。
pub fn stdout_enabled() -> bool {
    stream_enabled(std::io::stdout().is_terminal())
}

/// stderr 是否应着色。同上,判 stderr 是否 tty。
pub fn stderr_enabled() -> bool {
    stream_enabled(std::io::stderr().is_terminal())
}

/// 用给定 class 的前景/背景/修饰位把 `text` 包成真彩色 SGR 字符串。
/// `enabled = false` 或空串时原样返回。**仅包裹单行片段**——多行文本请只着色前缀。
pub fn paint(enabled: bool, classes: &[&str], text: &str) -> String {
    if !enabled || text.is_empty() {
        return text.to_string();
    }
    let open = sgr_open(&compute(classes));
    if open.is_empty() {
        return text.to_string();
    }
    format!("{open}{text}\x1b[0m")
}

/// 把 `ratatui::Style` 展开成 SGR 开序列(如 `\x1b[1;38;2;0;240;255m`);无属性则空串。
fn sgr_open(st: &RStyle) -> String {
    let mut params: Vec<String> = Vec::new();

    let m = st.add_modifier;
    if m.contains(Modifier::BOLD) {
        params.push("1".into());
    }
    if m.contains(Modifier::DIM) {
        params.push("2".into());
    }
    if m.contains(Modifier::ITALIC) {
        params.push("3".into());
    }
    if m.contains(Modifier::UNDERLINED) {
        params.push("4".into());
    }
    if m.contains(Modifier::SLOW_BLINK) {
        params.push("5".into());
    }
    if m.contains(Modifier::RAPID_BLINK) {
        params.push("6".into());
    }
    if m.contains(Modifier::REVERSED) {
        params.push("7".into());
    }
    if m.contains(Modifier::HIDDEN) {
        params.push("8".into());
    }
    if m.contains(Modifier::CROSSED_OUT) {
        params.push("9".into());
    }

    if let Some(fg) = st.fg {
        push_color(&mut params, fg, false);
    }
    if let Some(bg) = st.bg {
        push_color(&mut params, bg, true);
    }

    if params.is_empty() {
        String::new()
    } else {
        format!("\x1b[{}m", params.join(";"))
    }
}

/// 16 色命名 → 标准索引(0..16),其余返回 None。
fn named_index(c: RColor) -> Option<u8> {
    Some(match c {
        RColor::Black => 0,
        RColor::Red => 1,
        RColor::Green => 2,
        RColor::Yellow => 3,
        RColor::Blue => 4,
        RColor::Magenta => 5,
        RColor::Cyan => 6,
        RColor::Gray => 7,
        RColor::DarkGray => 8,
        RColor::LightRed => 9,
        RColor::LightGreen => 10,
        RColor::LightYellow => 11,
        RColor::LightBlue => 12,
        RColor::LightMagenta => 13,
        RColor::LightCyan => 14,
        RColor::White => 15,
        _ => return None,
    })
}

/// 把一个颜色追加为 SGR 参数。`is_bg` 区分前景(38/30 系)与背景(48/40 系)。
fn push_color(params: &mut Vec<String>, c: RColor, is_bg: bool) {
    let (extended, base_lo, base_hi): (&str, u32, u32) = if is_bg {
        ("48", 40, 100)
    } else {
        ("38", 30, 90)
    };
    match c {
        RColor::Reset => {}
        RColor::Indexed(i) => params.push(format!("{extended};5;{i}")),
        RColor::Rgb(r, g, b) => params.push(format!("{extended};2;{r};{g};{b}")),
        other => {
            if let Some(idx) = named_index(other) {
                let code = if idx < 8 {
                    base_lo + idx as u32
                } else {
                    base_hi + (idx - 8) as u32
                };
                params.push(code.to_string());
            }
        }
    }
}

// ===========================================================================
// CLI 便捷封装(按语义默认选 stdout/stderr 口)
// ===========================================================================
// 约定:`ok/muted/title/id/kv` 默认 stdout;`err/warn` 默认 stderr。
// 少数跨流场景(如 export 成功消息走 stderr)请直接用 `paint(stderr_enabled(), …)`。

/// 成功消息(绿)。走 stdout。
pub fn ok(text: &str) -> String {
    paint(stdout_enabled(), &["ok"], text)
}

/// 弱化文本(暗紫)。走 stdout。
pub fn muted(text: &str) -> String {
    paint(stdout_enabled(), &["muted"], text)
}

/// 标题/品牌(品红加粗)。走 stdout。
pub fn title(text: &str) -> String {
    paint(stdout_enabled(), &["title"], text)
}

/// id 高亮(青)。走 stdout。
pub fn id_text(text: &str) -> String {
    paint(stdout_enabled(), &["id"], text)
}

/// 错误(红)。走 stderr。
pub fn err(text: &str) -> String {
    paint(stderr_enabled(), &["err"], text)
}

/// 告警/敏感提示(琥珀)。走 stderr。
pub fn warn(text: &str) -> String {
    paint(stderr_enabled(), &["warn"], text)
}

/// 一行键值:`label` 着色为 key(青),`val` 保持终端默认色(不在浅色背景下掉色)。
pub fn kv(label: &str, val: &str) -> String {
    format!("{} {}", paint(stdout_enabled(), &["key"], label), val)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 主题 CSS 必须可解析(否则 `sheet()` 会在首帧 panic)。CI 兜底。
    #[test]
    fn theme_css_parses() {
        Stylesheet::parse(THEME_CSS).expect("theme CSS must parse");
    }

    /// compute 返回的 fg 必须等于 CSS 里声明的 Cyberpunk 原色。
    #[test]
    fn compute_accent_is_pink() {
        let st = compute(&["title"]);
        assert_eq!(st.fg, Some(RColor::Rgb(0xff, 0x00, 0x7f)));
        assert!(st.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn compute_ok_is_green() {
        let st = compute(&["ok"]);
        assert_eq!(st.fg, Some(RColor::Rgb(0x39, 0xff, 0x14)));
    }

    /// paint 关闭时原样返回,绝不掺入 ANSI。
    #[test]
    fn paint_disabled_is_plain() {
        assert_eq!(paint(false, &["ok"], "hi"), "hi");
        assert_eq!(paint(false, &["ok"], ""), "");
    }

    /// paint 开启时产出真彩色 SGR + reset。
    #[test]
    fn paint_enabled_wraps_truecolor() {
        let s = paint(true, &["ok"], "hi");
        assert!(s.starts_with("\x1b[38;2;57;255;20m"), "got: {s:?}");
        assert!(s.ends_with("\x1b[0m"));
        assert!(s.contains("hi"));
    }

    /// 多 class 合并:bold + 青色 = `1;38;2;0;240;255`。
    #[test]
    fn paint_merges_modifier_and_color() {
        let s = paint(true, &["title"], "x");
        // title = accent(#ff007f) + bold(1)
        assert!(s.starts_with("\x1b[1;38;2;255;0;127m"), "got: {s:?}");
    }
}
