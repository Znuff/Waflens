use crate::app::{App, AppView};
use crate::colors::ColorScheme;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
    Frame,
};
use std::sync::OnceLock;

// Detect color scheme once at startup
static COLOR_SCHEME: OnceLock<ColorScheme> = OnceLock::new();

fn colors() -> &'static ColorScheme {
    COLOR_SCHEME.get_or_init(|| ColorScheme::detect())
}

/// Calculate dynamic column widths based on available terminal width
/// Ensures all columns are visible even on narrow terminals
fn calculate_column_widths(table_width: u16) -> [Constraint; 6] {
    // Account for borders (2 chars) and column separators (5 chars for 6 columns)
    let available_width = table_width.saturating_sub(7) as usize;

    // Minimum widths to keep columns readable
    const MIN_AUDIT_ID: usize = 12;
    const MIN_TIMESTAMP: usize = 16;
    const MIN_DOMAIN: usize = 15;
    const MIN_CLIENT_IP: usize = 15;  // IPv4: 15 chars, IPv6: up to 39 chars
    const MIN_STATUS: usize = 6;      // "Status" header or "429"
    const MIN_RULE_IDS: usize = 10;

    let total_min = MIN_AUDIT_ID + MIN_TIMESTAMP + MIN_DOMAIN + MIN_CLIENT_IP + MIN_STATUS + MIN_RULE_IDS;

    // If terminal is very narrow, use minimum widths with proportional allocation
    if available_width <= total_min {
        return [
            Constraint::Length(MIN_AUDIT_ID as u16),
            Constraint::Length(MIN_TIMESTAMP as u16),
            Constraint::Length(MIN_DOMAIN as u16),
            Constraint::Length(MIN_CLIENT_IP as u16),
            Constraint::Length(MIN_STATUS as u16),
            Constraint::Min(MIN_RULE_IDS as u16),
        ];
    }

    // We have extra space - distribute intelligently
    let extra_space = available_width - total_min;

    // Preferred maximum widths when space allows
    const PREF_AUDIT_ID: usize = 24;
    const PREF_TIMESTAMP: usize = 19;
    const PREF_DOMAIN: usize = 40;
    const PREF_CLIENT_IP: usize = 39;  // Full IPv6 width
    const PREF_STATUS: usize = 6;      // Status codes are always 3 digits
    const PREF_RULE_IDS: usize = 20;

    // Calculate how much we can grow each column
    let audit_id_growth = (PREF_AUDIT_ID - MIN_AUDIT_ID).min(extra_space / 6);
    let timestamp_growth = (PREF_TIMESTAMP - MIN_TIMESTAMP).min(extra_space / 6);
    let domain_growth = (PREF_DOMAIN - MIN_DOMAIN).min(extra_space / 6);
    let client_ip_growth = (PREF_CLIENT_IP - MIN_CLIENT_IP).min(extra_space / 6);
    let status_growth = (PREF_STATUS - MIN_STATUS).min(extra_space / 6);
    let rule_ids_growth = (PREF_RULE_IDS - MIN_RULE_IDS).min(extra_space / 6);

    [
        Constraint::Length((MIN_AUDIT_ID + audit_id_growth) as u16),
        Constraint::Length((MIN_TIMESTAMP + timestamp_growth) as u16),
        Constraint::Length((MIN_DOMAIN + domain_growth) as u16),
        Constraint::Length((MIN_CLIENT_IP + client_ip_growth) as u16),
        Constraint::Length((MIN_STATUS + status_growth) as u16),
        Constraint::Min((MIN_RULE_IDS + rule_ids_growth) as u16),
    ]
}

pub fn draw(f: &mut Frame, app: &mut App) {
    match app.current_view {
        AppView::TableView => draw_table_view(f, app),
        AppView::DetailView => draw_detail_view(f, app),
    }
}

fn draw_table_view(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),  // File/Rule info bar
            Constraint::Length(3),  // Help/keybinds bar
            Constraint::Length(if app.search_mode { 3 } else { 0 }),
        ])
        .split(f.area());

    // Store table area for mouse click handling
    app.table_area = Some(chunks[1]);

    // Title bar
    let c = colors();
    let title = Paragraph::new("ModSecurity Audit Log Examiner")
        .style(Style::default().fg(c.title).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Table
    let headers = Row::new(vec![
        Cell::from("Audit ID").style(Style::default().fg(c.header).add_modifier(Modifier::BOLD)),
        Cell::from("Timestamp").style(Style::default().fg(c.header).add_modifier(Modifier::BOLD)),
        Cell::from("Domain").style(Style::default().fg(c.header).add_modifier(Modifier::BOLD)),
        Cell::from("Client IP").style(Style::default().fg(c.header).add_modifier(Modifier::BOLD)),
        Cell::from("Status").style(Style::default().fg(c.header).add_modifier(Modifier::BOLD)),
        Cell::from("Rule IDs").style(Style::default().fg(c.header).add_modifier(Modifier::BOLD)),
    ]);

    let visible_groups = app.visible_groups();

    // Calculate visible window - only render what fits on screen (performance optimization)
    let available_height = chunks[1].height.saturating_sub(3) as usize; // Subtract borders and header
    let start_idx = app.scroll_offset;

    let rows: Vec<Row> = visible_groups
        .iter()
        .enumerate()
        .skip(start_idx)
        .take(available_height)
        .map(|(idx, group)| {
            let style = if idx == app.selected_index {
                Style::default()
                    .bg(c.selected_bg)
                    .fg(c.selected_fg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let rule_ids = if group.primary_rule_ids.len() > 3 {
                format!("{} (+{})", group.primary_rule_ids[..3].join(", "), group.primary_rule_ids.len() - 3)
            } else {
                group.primary_rule_ids.join(", ")
            };
            let timestamp = group.first_timestamp.format("%Y-%m-%d %H:%M:%S").to_string();

            let status_text = group.http_status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let status_color = c.status_color(group.http_status);

            Row::new(vec![
                Cell::from(group.base_id.clone()).style(Style::default().fg(c.audit_id)),
                Cell::from(timestamp).style(Style::default().fg(c.timestamp)),
                Cell::from(group.domain.clone()).style(Style::default().fg(c.domain)),
                Cell::from(group.client_ip.clone()).style(Style::default().fg(c.client_ip)),
                Cell::from(status_text).style(Style::default().fg(status_color)),
                Cell::from(rule_ids).style(Style::default().fg(c.rule_id)),
            ])
            .style(style)
        })
        .collect();

    // Calculate dynamic column widths based on terminal width
    let constraints = calculate_column_widths(chunks[1].width);

    let table = Table::new(rows, constraints)
        .header(headers)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Entries ({}) ", visible_groups.len())),
        )
        .row_highlight_style(Style::default().bg(c.selected_bg));

    f.render_widget(table, chunks[1]);

    // File/Rule info bar
    let info_text = if let Some(group) = app.selected_group() {
        let rule_id = group.primary_rule_ids.first()
            .map(|r| r.as_str())
            .unwrap_or("N/A");
        let file = group.file_path.as_ref()
            .map(|f| f.as_str())
            .unwrap_or("N/A");
        format!("File: {} | Rule ID: {}", file, rule_id)
    } else {
        "No entry selected".to_string()
    };

    let info_bar = Paragraph::new(info_text)
        .style(Style::default().fg(c.label))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(info_bar, chunks[2]);

    // Help/keybinds bar
    let help_text = if app.search_mode {
        "ESC: Exit search | Enter: Apply search"
    } else {
        "↑/↓: Navigate | Enter: Details | /: Search | r/F5: Refresh | q: Quit"
    };

    let help = Paragraph::new(help_text)
        .style(Style::default().fg(c.help_text))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(help, chunks[3]);

    // Search bar
    if app.search_mode {
        let search_text = format!("Search: {}", app.search_query);
        let search = Paragraph::new(search_text)
            .style(Style::default().fg(c.search_highlight))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Search (domain:, ip:, id:, auditid:, status:) ")
                    .style(Style::default().fg(c.title)),
            );
        f.render_widget(search, chunks[4]);
    }
}

fn draw_detail_view(f: &mut Frame, app: &App) {
    let c = colors();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),  // File/Rule info bar
            Constraint::Length(3),  // Help/keybinds bar
        ])
        .split(f.area());

    if let Some(group) = app.selected_group() {
        // Title
        let title_text = format!(
            "Audit Chain: {} | {} | {}",
            group.base_id, group.domain, group.client_ip
        );
        let title = Paragraph::new(title_text)
            .style(Style::default().fg(c.title).add_modifier(Modifier::BOLD))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(title, chunks[0]);

        // Detail content
        let mut lines = Vec::new();

        for entry in &group.entries {
            // Parse and color-code content
            let content_lines = colorize_content(&entry.raw_content, c);
            lines.extend(content_lines);

            lines.push(Line::from(""));
        }

        // Add IP API information if available
        if let Some(ref ip_info) = app.current_ip_info {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(
                    "IP Geolocation & Network Information",
                    Style::default().fg(c.label).add_modifier(Modifier::BOLD),
                ),
            ]));
            lines.push(Line::from(""));

            // Syntax highlight the JSON
            let json_lines = colorize_json(ip_info, c);
            lines.extend(json_lines);
        }

        let detail_text = Text::from(lines);
        let detail = Paragraph::new(detail_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Chain Details ({} parts) ", group.entries.len())),
            )
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll as u16, 0));

        f.render_widget(detail, chunks[1]);

        // File/Rule info bar
        let rule_id = group.primary_rule_ids.first()
            .map(|r| r.as_str())
            .unwrap_or("N/A");
        let file = group.file_path.as_ref()
            .map(|f| f.as_str())
            .unwrap_or("N/A");
        let info_text = format!("File: {} | Rule ID: {}", file, rule_id);

        let info_bar = Paragraph::new(info_text)
            .style(Style::default().fg(c.label))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(info_bar, chunks[2]);

        // Help bar
        let help = Paragraph::new("↑/↓: Scroll | ←/→: Prev/Next Entry | PgUp/PgDn: Page | ESC/q: Back")
            .style(Style::default().fg(c.help_text))
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(help, chunks[3]);
    }
}

fn colorize_content<'a>(content: &'a str, c: &ColorScheme) -> Vec<Line<'a>> {
    let mut lines = Vec::new();

    for line in content.lines() {
        let line_lower = line.to_lowercase();

        if line.starts_with("GET") || line.starts_with("POST") || line.starts_with("PUT") ||
           line.starts_with("DELETE") || line.starts_with("PATCH") {
            // HTTP request line
            lines.push(Line::from(vec![
                Span::styled(line, Style::default().fg(c.http_method).add_modifier(Modifier::BOLD)),
            ]));
        } else if line_lower.starts_with("host:") {
            // Case-insensitive Host header
            if let Some(colon_pos) = line.find(':') {
                let header_part = &line[..=colon_pos];
                let value_part = &line[colon_pos+1..];
                lines.push(Line::from(vec![
                    Span::styled(header_part, Style::default().fg(c.label).add_modifier(Modifier::BOLD)),
                    Span::styled(value_part, Style::default().fg(c.host_header)),
                ]));
            } else {
                lines.push(Line::from(line));
            }
        } else if line_lower.starts_with("user-agent:") {
            // Case-insensitive User-Agent header
            if let Some(colon_pos) = line.find(':') {
                let header_part = &line[..=colon_pos];
                let value_part = &line[colon_pos+1..];
                lines.push(Line::from(vec![
                    Span::styled(header_part, Style::default().fg(c.label).add_modifier(Modifier::BOLD)),
                    Span::styled(value_part, Style::default().fg(c.user_agent)),
                ]));
            } else {
                lines.push(Line::from(line));
            }
        } else if line.contains("ModSecurity") || line.contains("OWASP") {
            lines.push(Line::from(vec![
                Span::styled(line, Style::default().fg(c.modsec_message).add_modifier(Modifier::BOLD)),
            ]));
        } else if line.contains("[id \"") {
            // Rule ID line
            lines.push(Line::from(vec![
                Span::styled(line, Style::default().fg(c.rule_id_detail).add_modifier(Modifier::BOLD)),
            ]));
        } else if line.contains("--") && line.len() > 20 {
            // Boundary lines
            lines.push(Line::from(vec![
                Span::styled(line, Style::default().fg(c.boundary)),
            ]));
        } else if line.starts_with("HTTP/") {
            lines.push(Line::from(vec![
                Span::styled(line, Style::default().fg(c.http_status).add_modifier(Modifier::BOLD)),
            ]));
        } else if line.ends_with(':') && !line.contains(' ') {
            // Other header names
            lines.push(Line::from(vec![
                Span::styled(line, Style::default().fg(c.header_name)),
            ]));
        } else {
            lines.push(Line::from(line));
        }
    }

    lines
}

fn colorize_json<'a>(json: &'a str, c: &ColorScheme) -> Vec<Line<'a>> {
    let mut lines = Vec::new();

    for line in json.lines() {
        let trimmed = line.trim_start();

        // Detect JSON structure elements
        if trimmed.starts_with('{') || trimmed.starts_with('}') {
            // Braces
            lines.push(Line::from(vec![
                Span::styled(line, Style::default().fg(c.boundary)),
            ]));
        } else if trimmed.starts_with('"') && trimmed.contains(':') {
            // JSON key-value pair
            if let Some(colon_pos) = line.find(':') {
                let key_part = &line[..colon_pos + 1];
                let value_part = &line[colon_pos + 1..];

                // Determine color based on value type (strip trailing comma for comparison)
                let value_trimmed = value_part.trim().trim_end_matches(',');
                let value_color = if value_part.trim().starts_with('"') {
                    // String value
                    c.host_header
                } else if value_trimmed == "true" || value_trimmed == "false" {
                    // Boolean
                    c.http_method
                } else if value_trimmed == "null" {
                    // Null
                    c.boundary
                } else {
                    // Number
                    c.timestamp
                };

                lines.push(Line::from(vec![
                    Span::styled(key_part, Style::default().fg(c.label).add_modifier(Modifier::BOLD)),
                    Span::styled(value_part, Style::default().fg(value_color)),
                ]));
            } else {
                lines.push(Line::from(line));
            }
        } else {
            lines.push(Line::from(line));
        }
    }

    lines
}
