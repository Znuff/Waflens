use crate::ipapi::IpApiCache;
use crate::parser::{AuditGroup, AuditLogParser};
use anyhow::Result;
use std::time::{Duration, Instant};
use std::io;
use ratatui::{backend::CrosstermBackend, Terminal};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppView {
    TableView,
    DetailView,
}

pub struct App {
    pub audit_groups: Vec<AuditGroup>,
    pub filtered_groups: Vec<usize>, // Indices into audit_groups
    pub selected_index: usize,
    pub scroll_offset: usize,
    pub search_query: String,
    pub search_mode: bool,
    pub current_view: AppView,
    pub detail_scroll: usize,
    pub should_quit: bool,
    pub log_path: String,
    pub last_click_time: Option<Instant>,
    pub last_click_row: Option<usize>,
    pub table_area: Option<ratatui::layout::Rect>, // Cached table area for mouse clicks
    pub ip_api_enabled: bool,
    pub ip_api_cache: IpApiCache,
    pub current_ip_info: Option<String>, // Cached IP info for current detail view
}

impl App {
    pub fn new(log_path: &str, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, ip_api_enabled: bool) -> Result<Self> {
        let parser = AuditLogParser::new();
        let audit_groups = parser.parse_log_file(log_path, terminal)?;
        let filtered_groups: Vec<usize> = (0..audit_groups.len()).collect();

        Ok(Self {
            audit_groups,
            filtered_groups,
            selected_index: 0,
            scroll_offset: 0,
            search_query: String::new(),
            search_mode: false,
            current_view: AppView::TableView,
            detail_scroll: 0,
            should_quit: false,
            log_path: log_path.to_string(),
            last_click_time: None,
            last_click_row: None,
            table_area: None,
            ip_api_enabled,
            ip_api_cache: IpApiCache::new(),
            current_ip_info: None,
        })
    }

    pub fn refresh(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        // Save current position
        let saved_selected_index = self.selected_index;
        let saved_scroll_offset = self.scroll_offset;

        let parser = AuditLogParser::new();
        self.audit_groups = parser.parse_log_file(&self.log_path, terminal)?;
        self.filtered_groups = (0..self.audit_groups.len()).collect();
        self.apply_search();

        // Restore position, clamping to valid range
        let max_index = self.filtered_groups.len().saturating_sub(1);
        self.selected_index = saved_selected_index.min(max_index);
        self.scroll_offset = saved_scroll_offset.min(max_index);

        Ok(())
    }

    pub fn selected_group(&self) -> Option<&AuditGroup> {
        self.filtered_groups
            .get(self.selected_index)
            .and_then(|&idx| self.audit_groups.get(idx))
    }

    pub fn visible_groups(&self) -> Vec<&AuditGroup> {
        self.filtered_groups
            .iter()
            .filter_map(|&idx| self.audit_groups.get(idx))
            .collect()
    }

    pub fn move_selection_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
            if self.selected_index < self.scroll_offset {
                self.scroll_offset = self.selected_index;
            }
        }
    }

    pub fn move_selection_down(&mut self, visible_height: usize) {
        if self.selected_index < self.filtered_groups.len().saturating_sub(1) {
            self.selected_index += 1;
            // Auto-scroll when selection moves beyond visible area
            if self.selected_index >= self.scroll_offset + visible_height {
                self.scroll_offset = self.selected_index.saturating_sub(visible_height - 1);
            }
        }
    }

    pub fn page_up(&mut self, page_size: usize) {
        self.selected_index = self.selected_index.saturating_sub(page_size);
        self.scroll_offset = self.scroll_offset.saturating_sub(page_size);
    }

    pub fn page_down(&mut self, page_size: usize) {
        self.selected_index = (self.selected_index + page_size).min(self.filtered_groups.len().saturating_sub(1));
        self.scroll_offset = self.scroll_offset + page_size;
    }

    pub fn scroll_detail_up(&mut self) {
        self.detail_scroll = self.detail_scroll.saturating_sub(1);
    }

    pub fn scroll_detail_down(&mut self) {
        self.detail_scroll += 1;
    }

    pub fn page_detail_up(&mut self, page_size: usize) {
        self.detail_scroll = self.detail_scroll.saturating_sub(page_size);
    }

    pub fn page_detail_down(&mut self, page_size: usize) {
        self.detail_scroll += page_size;
    }

    pub fn scroll_detail_home(&mut self) {
        self.detail_scroll = 0;
    }

    pub fn scroll_detail_end(&mut self) {
        // Set to a very large value - ratatui will clamp it automatically
        self.detail_scroll = usize::MAX;
    }

    pub fn enter_search_mode(&mut self) {
        self.search_mode = true;
    }

    pub fn exit_search_mode(&mut self) {
        self.search_mode = false;
    }

    pub fn add_search_char(&mut self, c: char) {
        self.search_query.push(c);
        self.apply_search();
    }

    pub fn remove_search_char(&mut self) {
        self.search_query.pop();
        self.apply_search();
    }

    pub fn clear_search(&mut self) {
        self.search_query.clear();
        self.filtered_groups = (0..self.audit_groups.len()).collect();
        self.selected_index = 0;
        self.scroll_offset = 0;
    }

    pub fn apply_search(&mut self) {
        if self.search_query.is_empty() {
            self.filtered_groups = (0..self.audit_groups.len()).collect();
        } else {
            self.filtered_groups = self.audit_groups
                .iter()
                .enumerate()
                .filter(|(_, group)| self.matches_search(group))
                .map(|(idx, _)| idx)
                .collect();
        }
        self.selected_index = 0;
        self.scroll_offset = 0;
    }

    fn matches_search(&self, group: &AuditGroup) -> bool {
        let query = self.search_query.to_lowercase();

        // Check for tokenized search
        if let Some((token, value)) = query.split_once(':') {
            match token.trim() {
                "domain" => group.domain.to_lowercase().contains(value.trim()),
                "ip" => group.client_ip.contains(value.trim()),
                "rule" | "ruleid" | "id" => group.primary_rule_ids.iter()
                    .any(|id| id.contains(value.trim())),
                "auditid" => group.base_id.to_lowercase().contains(value.trim()),
                "status" | "http" => {
                    if let Some(status) = group.http_status {
                        status.to_string().contains(value.trim())
                    } else {
                        false
                    }
                },
                _ => self.matches_all_fields(group, &query),
            }
        } else {
            self.matches_all_fields(group, &query)
        }
    }

    fn matches_all_fields(&self, group: &AuditGroup, query: &str) -> bool {
        group.domain.to_lowercase().contains(query) ||
        group.client_ip.contains(query) ||
        group.base_id.to_lowercase().contains(query) ||
        group.primary_rule_ids.iter().any(|id| id.contains(query)) ||
        group.http_status.map(|s| s.to_string().contains(query)).unwrap_or(false)
    }

    pub fn show_detail_view(&mut self) {
        self.current_view = AppView::DetailView;
        self.detail_scroll = 0;

        // Fetch IP info when entering detail view
        if self.ip_api_enabled {
            if let Some(group) = self.selected_group() {
                self.current_ip_info = self.ip_api_cache.get_ip_info(&group.client_ip).ok();
            }
        } else {
            self.current_ip_info = None;
        }
    }

    pub fn show_table_view(&mut self) {
        self.current_view = AppView::TableView;
        // Keep current_ip_info - it's just a copy of what's already cached
    }

    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    pub fn handle_click(&mut self, row: usize, visible_height: usize) -> bool {
        const DOUBLE_CLICK_MS: u64 = 500;
        let now = Instant::now();
        let mut should_open_detail = false;

        // Check for double-click
        if let (Some(last_time), Some(last_row)) = (self.last_click_time, self.last_click_row) {
            if last_row == row && now.duration_since(last_time) < Duration::from_millis(DOUBLE_CLICK_MS) {
                // Double-click detected - open detail view
                should_open_detail = true;
            }
        }

        // Update selection
        self.selected_index = row;

        // Auto-scroll if needed
        if self.selected_index < self.scroll_offset {
            self.scroll_offset = self.selected_index;
        } else if self.selected_index >= self.scroll_offset + visible_height {
            self.scroll_offset = self.selected_index.saturating_sub(visible_height - 1);
        }

        // Update click tracking
        self.last_click_time = Some(now);
        self.last_click_row = Some(row);

        should_open_detail
    }
}
