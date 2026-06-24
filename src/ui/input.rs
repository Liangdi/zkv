//! 输入组件:文本输入框、口令模态、通用确认模态。对应 PRD §8。

use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders};
use ratatui::Frame;
use ratatui_sci_fi::widgets::{TextInput, TextInputState};

use super::theme;

/// 单行输入字段(带可选掩码,用于口令)。
#[derive(Debug, Clone)]
pub struct InputField {
    pub value: String,
    pub mask: bool,
}

impl InputField {
    pub fn new(mask: bool) -> Self {
        Self {
            value: String::new(),
            mask,
        }
    }

    /// 追加一个字符。
    pub fn push_char(&mut self, c: char) {
        self.value.push(c);
    }

    /// 退格删除末尾字符。
    pub fn backspace(&mut self) {
        self.value.pop();
    }

    /// 清空。
    pub fn clear(&mut self) {
        self.value.clear();
    }

    /// 用于渲染的文本:掩码时返回与长度等量的 `•`,否则返回原值。
    pub fn rendered(&self) -> String {
        if self.mask {
            "•".repeat(self.value.chars().count())
        } else {
            self.value.clone()
        }
    }
}

/// 渲染单行输入框:外层圆角边框(legend label) + sci-fi `TextInput`(闪烁 `█`
/// 光标,口令自动 `•` 掩码)。`tick` 是 UI 层动画时钟,驱动光标闪烁节奏。
///
/// 输入是 `App` 集中持有的 append-only 缓冲(`app.input`),这里每帧临时构造
/// `TextInputState`:光标恒在末尾(无左右移动),`blink_tick` 取动画时钟。
/// 不持久化 state,避免与 `app.input` 双状态漂移。
pub fn render_input(frame: &mut Frame, area: Rect, field: &InputField, label: &str, tick: u64) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border())
        .title(label)
        .title_style(theme::title_style());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut state = TextInputState {
        value: field.value.clone(),
        cursor: field.value.chars().count(),
        blink_tick: tick,
    };
    let mut input = TextInput::new().theme(ratatui_sci_fi::Theme::Cyberpunk);
    if field.mask {
        input = input.password(true);
    }
    frame.render_stateful_widget(input, inner, &mut state);
}

#[cfg(test)]
mod tests {
    use super::InputField;

    #[test]
    fn push_and_backspace() {
        let mut f = InputField::new(false);
        for c in "abc".chars() {
            f.push_char(c);
        }
        assert_eq!(f.value, "abc");
        f.backspace();
        assert_eq!(f.value, "ab");
    }

    #[test]
    fn mask_renders_bullets() {
        let mut f = InputField::new(true);
        for c in "secret".chars() {
            f.push_char(c);
        }
        assert_eq!(f.rendered(), "•".repeat(6));
        f.clear();
        assert_eq!(f.rendered(), "");
    }
}
