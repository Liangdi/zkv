//! 输入组件:文本输入框、口令模态、通用确认模态。对应 PRD §8。

use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

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

/// 渲染单行输入框(label + 值)。
pub fn render_input(frame: &mut Frame, area: Rect, field: &InputField, label: &str) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::border())
        .title(label)
        .title_style(theme::title_style());
    let text = if field.value.is_empty() {
        // 占位提示
        Paragraph::new("")
            .style(theme::muted())
            .block(block)
    } else {
        Paragraph::new(field.rendered()).style(theme::fg()).block(block)
    };
    frame.render_widget(text, area);
}

/// 渲染一个居中模态:用 `Clear` 清底,带标题与多行正文。
pub fn render_modal(frame: &mut Frame, area: Rect, title: &str, body_lines: &[&str]) {
    // 清底
    frame.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::accent2())
        .title(format!(" {title} "))
        .title_style(theme::title_style())
        .style(theme::fg());

    let inner = {
        let chunks = Layout::vertical([Constraint::Min(1)]).split(area);
        block.inner(chunks[0])
    };
    frame.render_widget(block, area);

    let lines: Vec<ratatui::text::Line> = body_lines
        .iter()
        .map(|s| ratatui::text::Line::from(*s).style(theme::fg()))
        .collect();
    let para = Paragraph::new(lines)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true });
    frame.render_widget(para, inner);
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
