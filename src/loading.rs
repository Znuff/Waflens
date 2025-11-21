use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};

pub struct LoadingScreen;

impl LoadingScreen {
    pub fn new() -> Self {
        Self
    }

    pub fn draw(&self, f: &mut Frame, step: usize, step_name: &str, progress: f64, message: &str) {
            // Center the dialog - 50% width, centered horizontally and vertically
            let area = f.area();
            let vertical_center = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(25),
                    Constraint::Percentage(50),
                    Constraint::Percentage(25),
                ])
                .split(area);

            let horizontal_center = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(25),
                    Constraint::Percentage(50),
                    Constraint::Percentage(25),
                ])
                .split(vertical_center[1]);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints([
                    Constraint::Length(3),  // Title
                    Constraint::Length(3),  // Step indicator
                    Constraint::Length(3),  // Progress bar
                    Constraint::Length(3),  // Message
                    Constraint::Min(0),     // Spacer
                ])
                .split(horizontal_center[1]);

            // Title
            let title = Paragraph::new("ModSecurity Audit Log Parser")
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(title, chunks[0]);

            // Step indicator
            let step_text = format!("Step {}/5: {}", step, step_name);
            let step_para = Paragraph::new(step_text)
                .style(Style::default().fg(Color::Yellow))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(step_para, chunks[1]);

            // Progress bar
            let gauge = Gauge::default()
                .block(Block::default().borders(Borders::ALL).title("Progress"))
                .gauge_style(Style::default().fg(Color::Cyan).bg(Color::Black))
                .percent((progress * 100.0) as u16)
                .label(format!("{:.1}%", progress * 100.0));
            f.render_widget(gauge, chunks[2]);

            // Message
            let msg = Paragraph::new(message)
                .style(Style::default().fg(Color::Gray))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(msg, chunks[3]);
    }

    pub fn draw_summary(&self, f: &mut Frame, total_entries: usize, total_groups: usize, file_size_mb: f64) {
            // Center the dialog - 50% width, centered
            let area = f.area();
            let vertical_center = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(25),
                    Constraint::Percentage(50),
                    Constraint::Percentage(25),
                ])
                .split(area);

            let horizontal_center = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(25),
                    Constraint::Percentage(50),
                    Constraint::Percentage(25),
                ])
                .split(vertical_center[1]);

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(2)
                .constraints([
                    Constraint::Length(3),   // Title
                    Constraint::Length(7),   // Summary box
                    Constraint::Min(0),      // Spacer
                ])
                .split(horizontal_center[1]);

            // Title
            let title = Paragraph::new("✅ Loading Complete!")
                .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL));
            f.render_widget(title, chunks[0]);

            // Summary
            let summary_lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::raw("  📁 File size: "),
                    Span::styled(format!("{:.2} MB", file_size_mb), Style::default().fg(Color::Cyan)),
                ]),
                Line::from(vec![
                    Span::raw("  📊 Total entries: "),
                    Span::styled(format!("{}", total_entries), Style::default().fg(Color::Yellow)),
                ]),
                Line::from(vec![
                    Span::raw("  🔗 Audit groups: "),
                    Span::styled(format!("{}", total_groups), Style::default().fg(Color::Green)),
                ]),
                Line::from(""),
            ];

            let summary = Paragraph::new(summary_lines)
                .block(Block::default().borders(Borders::ALL).title(" Summary "))
                .alignment(Alignment::Left);
            f.render_widget(summary, chunks[1]);
    }
}
