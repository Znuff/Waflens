use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::io;
use ratatui::{backend::CrosstermBackend, Terminal};
use crate::loading::LoadingScreen;

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub audit_id: String,
    pub timestamp: DateTime<Utc>,
    pub domain: String,
    pub rule_ids: Vec<String>,
    pub client_ip: String,
    pub http_status: Option<u16>,
    pub raw_content: String,
    pub file_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditGroup {
    pub base_id: String,
    pub entries: Vec<AuditEntry>,
    pub first_timestamp: DateTime<Utc>,
    pub domain: String,
    pub client_ip: String,
    pub http_status: Option<u16>,
    pub primary_rule_ids: Vec<String>,
    pub file_path: Option<String>,
}

impl AuditGroup {
    pub fn from_entries(entries: Vec<AuditEntry>) -> Self {
        let base_id = entries[0].audit_id.clone();
        let first_timestamp = entries.iter().map(|e| e.timestamp).min().unwrap();
        let domain = entries[0].domain.clone();
        let client_ip = entries[0].client_ip.clone();

        let mut rule_ids = Vec::new();
        let mut file_path = None;
        let mut http_status = None;

        for entry in &entries {
            for rule_id in &entry.rule_ids {
                if !rule_ids.contains(rule_id) {
                    rule_ids.push(rule_id.clone());
                }
            }
            // Get the first non-None file path
            if file_path.is_none() && entry.file_path.is_some() {
                file_path = entry.file_path.clone();
            }
            // Get the first non-None HTTP status
            if http_status.is_none() && entry.http_status.is_some() {
                http_status = entry.http_status;
            }
        }

        Self {
            base_id,
            entries,
            first_timestamp,
            domain,
            client_ip,
            http_status,
            primary_rule_ids: rule_ids,
            file_path,
        }
    }
}

pub struct AuditLogParser {
    timestamp_re: Regex,
    rule_id_re: Regex,
    host_re: Regex,
    client_ip_re: Regex,
    file_re: Regex,
    http_status_re: Regex,
}

impl AuditLogParser {
    pub fn new() -> Self {
        Self {
            timestamp_re: Regex::new(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]")
                .unwrap(),
            rule_id_re: Regex::new(r#"\[id "(\d+)"\]"#).unwrap(),
            host_re: Regex::new(r"(?i)Host:\s*([^\r\n]+)").unwrap(),
            // Parse the A section line: [timestamp] audit-id source-ip source-port dest-ip dest-port
            // We'll extract this in create_entry by splitting the line
            client_ip_re: Regex::new(r"\[[\d/A-Za-z: +-]+\]\s+\S+\s+(\S+)")
                .unwrap(),
            file_re: Regex::new(r#"\[file "([^"]+)"\]"#).unwrap(),
            // Extract HTTP status code from F section: HTTP/1.1 200 OK
            http_status_re: Regex::new(r"HTTP/\d\.\d\s+(\d{3})").unwrap(),
        }
    }

    pub fn parse_log_file<P: AsRef<Path>>(
        &self,
        path: P,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<Vec<AuditGroup>> {
        let loading = LoadingScreen::new();

        // Step 1: Read file
        terminal.draw(|f| loading.draw(f, 1, "Reading audit log file", 0.0, "Reading file from disk..."))?;
        let bytes = fs::read(path.as_ref())
            .context("Failed to read audit log file")?;
        let file_size_mb = bytes.len() as f64 / 1_000_000.0;
        let file_size_msg = format!("File size: {:.2} MB ({} bytes)", file_size_mb, bytes.len());
        terminal.draw(|f| loading.draw(f, 1, "Reading audit log file", 0.2, &file_size_msg))?;

        // Step 2: Convert to UTF-8
        terminal.draw(|f| loading.draw(f, 2, "Converting to UTF-8 text", 0.2, "Processing file contents..."))?;
        let content = String::from_utf8_lossy(&bytes).to_string();
        let line_count = content.lines().count();
        let lines_msg = format!("Lines processed: {}", line_count);
        terminal.draw(|f| loading.draw(f, 2, "Converting to UTF-8 text", 0.4, &lines_msg))?;

        // Step 3: Parse entries
        terminal.draw(|f| loading.draw(f, 3, "Parsing audit entries", 0.4, "Extracting audit log entries..."))?;
        let entries = self.parse_entries_with_loading(&content, terminal, &loading)?;
        let entries_msg = format!("Entries found: {}", entries.len());
        terminal.draw(|f| loading.draw(f, 3, "Parsing audit entries", 0.6, &entries_msg))?;

        // Step 4: Group entries
        terminal.draw(|f| loading.draw(f, 4, "Grouping entries by audit ID", 0.6, "Creating audit groups..."))?;
        let mut groups: HashMap<String, Vec<AuditEntry>> = HashMap::new();
        let total_entries = entries.len();
        for entry in entries {
            groups.entry(entry.audit_id.clone())
                .or_insert_with(Vec::new)
                .push(entry);
        }
        let group_count = groups.len();
        let groups_msg = format!("Unique audit groups: {}", group_count);
        terminal.draw(|f| loading.draw(f, 4, "Grouping entries by audit ID", 0.8, &groups_msg))?;

        // Step 5: Sort
        terminal.draw(|f| loading.draw(f, 5, "Sorting by timestamp", 0.8, "Sorting groups (most recent first)..."))?;
        let mut audit_groups: Vec<AuditGroup> = groups
            .into_iter()
            .map(|(_, entries)| AuditGroup::from_entries(entries))
            .collect();
        audit_groups.sort_by(|a, b| b.first_timestamp.cmp(&a.first_timestamp));
        terminal.draw(|f| loading.draw(f, 5, "Sorting by timestamp", 1.0, "Complete!"))?;

        // Show summary
        terminal.draw(|f| loading.draw_summary(f, total_entries, group_count, file_size_mb))?;
        std::thread::sleep(std::time::Duration::from_millis(800));

        Ok(audit_groups)
    }

    fn parse_entries_with_loading(
        &self,
        content: &str,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
        loading: &LoadingScreen,
    ) -> Result<Vec<AuditEntry>> {
        let mut entries = Vec::new();
        let boundary_re = Regex::new(r"--([a-zA-Z0-9]+)-([A-Z])--").unwrap();
        let mut current_id: Option<String> = None;
        let mut accumulated_content = String::new();
        let mut line_num = 0;
        let total_lines = content.lines().count() as u64;

        for line in content.lines() {
            line_num += 1;

            // Update progress every 1000 lines
            if line_num % 1000 == 0 {
                let progress = 0.4 + (line_num as f64 / total_lines as f64) * 0.2;
                let msg = if entries.len() > 0 {
                    format!("Found {} entries so far...", entries.len())
                } else {
                    "Scanning log file...".to_string()
                };
                terminal.draw(|f| loading.draw(f, 3, "Parsing audit entries", progress, &msg))?;
            }

            if let Some(caps) = boundary_re.captures(line) {
                let id = caps.get(1).unwrap().as_str().to_string();

                // If this is a different ID than current, save the previous entry
                if let Some(ref prev_id) = current_id {
                    if &id != prev_id {
                        // Save previous entry
                        if !accumulated_content.trim().is_empty() {
                            if let Some(entry) = self.create_entry(prev_id.clone(), accumulated_content.clone()) {
                                entries.push(entry);
                            }
                        }
                        // Reset for new entry
                        accumulated_content.clear();
                    }
                }

                // Track this ID
                current_id = Some(id);
                accumulated_content.push_str(&format!("{}\n", line));
            } else if current_id.is_some() {
                // Accumulate content for current entry
                accumulated_content.push_str(line);
                accumulated_content.push('\n');
            }
        }

        // Save the last entry
        if let Some(id) = current_id {
            if !accumulated_content.trim().is_empty() {
                if let Some(entry) = self.create_entry(id, accumulated_content) {
                    entries.push(entry);
                }
            }
        }

        Ok(entries)
    }


    fn create_entry(&self, audit_id: String, content: String) -> Option<AuditEntry> {
        // Parse timestamp
        let timestamp = self.parse_timestamp(&content)
            .unwrap_or_else(|| Utc::now());

        // Extract domain (trim to remove any \r or whitespace)
        let domain = self.host_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim_end_matches('\r').trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Extract client IP
        let client_ip = self.client_ip_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string());

        // Extract rule IDs
        let rule_ids: Vec<String> = self.rule_id_re
            .captures_iter(&content)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();

        // Extract file path
        let file_path = self.file_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        // Extract HTTP status code from F section
        let http_status = self.http_status_re
            .captures(&content)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().parse::<u16>().ok());

        Some(AuditEntry {
            audit_id,
            timestamp,
            domain,
            rule_ids,
            client_ip,
            http_status,
            raw_content: content,
            file_path,
        })
    }

    fn parse_timestamp(&self, content: &str) -> Option<DateTime<Utc>> {
        self.timestamp_re
            .captures(content)
            .and_then(|c| c.get(1))
            .and_then(|m| {
                DateTime::parse_from_str(m.as_str(), "%d/%b/%Y:%H:%M:%S %z")
                    .ok()
                    .map(|dt| dt.with_timezone(&Utc))
            })
    }
}
