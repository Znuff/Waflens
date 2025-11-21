# Waflens - Technical Documentation

## Project Overview

A terminal-based user interface (TUI) application written in Rust for parsing, analyzing, and browsing ModSecurity audit logs. Built using the Ratatui framework for the UI and Crossterm for terminal control.

Waflens provides an intuitive lens into your Web Application Firewall logs with features like IP geolocation, adaptive colors, dynamic column sizing, advanced search, and live refresh.

## Architecture

### Core Components

1. **main.rs** - Application entry point and event loop
2. **app.rs** - Application state management and business logic
3. **parser.rs** - ModSecurity audit log parsing
4. **ui.rs** - Terminal UI rendering
5. **colors.rs** - Adaptive color scheme (16/256 color support)
6. **loading.rs** - Loading screen during log parsing
7. **ipapi.rs** - IP geolocation with subnet caching

### Dependencies

- **ratatui (0.29)** - Terminal UI framework
- **crossterm (0.28)** - Terminal manipulation and control
- **regex (1.11)** - Pattern matching for log parsing
- **chrono (0.4)** - Timestamp parsing and formatting
- **anyhow (1.0)** - Error handling
- **clap (4.5)** - Command-line argument parsing with derive macros
- **indicatif (0.17)** - Progress bars and indicators
- **num-format (0.4)** - Number formatting
- **reqwest (0.12)** - HTTP client with blocking and JSON features
- **serde (1.0)** - Serialization framework with derive macros
- **serde_json (1.0)** - JSON serialization/deserialization

## ModSecurity Audit Log Format

### Serial Format Structure

ModSecurity audit logs use a boundary-based format with distinct sections:

```
--boundary-A--
[timestamp] unique-id source-ip source-port dest-ip dest-port

--boundary-B--
[HTTP Request Headers]

--boundary-C--
[HTTP Request Body]

--boundary-F--
[HTTP Response Status Line]

--boundary-H--
[ModSecurity Messages]

--boundary-Z--
[End Marker]
```

### Section Details

- **A Section**: Always first, contains transaction metadata in fixed order:
  - Format: `[DD/MMM/YYYY:HH:MM:SS +TZTZ] UNIQUE-ID SOURCE-IP SOURCE-PORT DEST-IP DEST-PORT`
  - Example: `[27/Jul/2016:05:46:16 +0200] V5guiH8AAQEAADTeJ2wAAAAK 192.168.3.1 50084 192.168.3.111 80`

- **B Section**: HTTP request headers
  - Extract Host header for domain identification

- **F Section**: HTTP response status line
  - Extract HTTP status code (200, 404, 503, etc.)

- **H Section**: ModSecurity rule matches and messages
  - Contains rule IDs in format: `[id "123456"]`
  - Contains file references: `[file "/path/to/rule.conf"]`
  - Contains line numbers: `[line "42"]`

### Parsing Strategy

**DO NOT use greedy regex patterns.** The log format has predictable structure and field order.

#### IP Address Extraction (A Section)
```rust
// Regex: \[[\d/A-Za-z: +-]+\]\s+\S+\s+(\S+)
// Matches: [timestamp] audit-id SOURCE-IP
// Captures the third field which can be IPv4 or IPv6
client_ip_re: Regex::new(r"\[[\d/A-Za-z: +-]+\]\s+\S+\s+(\S+)")
```

This approach:
- Relies on fixed field position (3rd field)
- Uses `\S+` (non-whitespace) to match any IP format
- Works for both IPv4 (`192.168.1.1`) and IPv6 (`2001:db8::1`)

#### Domain Extraction (B Section)
```rust
// Case-insensitive Host header extraction
host_re: Regex::new(r"(?i)Host:\s*([^\r\n]+)")
```

#### HTTP Status Extraction (F Section)
```rust
// Extract HTTP status code from response line
http_status_re: Regex::new(r"HTTP/\d\.\d\s+(\d{3})")
```

#### Rule ID Extraction (H Section)
```rust
// Extract numeric rule IDs
rule_id_re: Regex::new(r#"\[id "(\d+)"\]"#)
```

Store all unique rule IDs found in the H section.

## Application State (app.rs)

### Core Data Structure

```rust
pub struct App {
    pub audit_groups: Vec<AuditGroup>,      // All parsed audit entries
    pub filtered_groups: Vec<usize>,        // Indices matching current search
    pub selected_index: usize,              // Currently selected row
    pub scroll_offset: usize,               // Table view scroll position
    pub search_query: String,               // Current search filter
    pub search_mode: bool,                  // Whether search bar is active
    pub current_view: AppView,              // TableView or DetailView
    pub detail_scroll: usize,               // Detail view scroll position
    pub should_quit: bool,                  // Application exit flag
    pub log_path: String,                   // Path to audit log file
    pub last_click_time: Option<Instant>,   // For double-click detection
    pub last_click_row: Option<usize>,      // For double-click detection
    pub table_area: Option<Rect>,           // Cached table area for mouse clicks
    pub ip_api_enabled: bool,               // Whether IP geolocation is enabled
    pub ip_api_cache: IpApiCache,           // IP geolocation cache
    pub current_ip_info: Option<String>,    // Cached IP info for current detail view
}
```

### AuditGroup Structure

```rust
pub struct AuditGroup {
    pub base_id: String,                    // Audit ID (e.g., V5guiH8AAQEAADTeJ2wAAAAK)
    pub first_timestamp: DateTime<Utc>,    // Parsed timestamp
    pub client_ip: String,                  // Source IP (IPv4 or IPv6)
    pub domain: String,                     // Host header value
    pub http_status: Option<u16>,           // HTTP status code (200, 404, etc.)
    pub primary_rule_ids: Vec<String>,      // All unique rule IDs triggered
    pub file_path: Option<String>,          // Rule file path
    pub entries: Vec<AuditEntry>,           // All related audit entries
}
```

## Color Scheme (colors.rs)

### Adaptive Color Detection

Waflens automatically detects terminal capabilities:

```rust
pub fn detect() -> Self {
    if let Ok(colorterm) = std::env::var("COLORTERM") {
        if colorterm.contains("truecolor") || colorterm.contains("24bit") {
            return Self::colors_256();
        }
    }
    if let Ok(term) = std::env::var("TERM") {
        if term.contains("256color") {
            return Self::colors_256();
        }
    }
    Self::colors_16()
}
```

### Color Modes

**16-Color Mode**: Uses bright variants for better visibility
- `LightCyan`, `LightYellow`, `LightMagenta`, etc.
- Better for terminals with custom color themes

**256-Color Mode**: Uses indexed colors for richer palette
- `Color::Indexed(117)` (light cyan)
- `Color::Indexed(221)` (light yellow)
- `Color::Indexed(34)` (dark green for User-Agent)

### HTTP Status Color Coding

```rust
pub fn status_color(&self, status: Option<u16>) -> Color {
    match status {
        Some(code) if code >= 200 && code < 300 => self.status_2xx,  // Green
        Some(code) if code >= 300 && code < 400 => self.status_3xx,  // Cyan
        Some(code) if code >= 400 && code < 500 => self.status_4xx,  // Red
        Some(code) if code >= 500 && code < 600 => self.status_5xx,  // Magenta/Purple
        _ => self.status_unknown,                                     // Default color
    }
}
```

## Loading Screen (loading.rs)

### Frame-Based Rendering

**IMPORTANT**: The loading screen shares the same terminal instance as the main app. Do NOT create separate terminal instances.

```rust
pub struct LoadingScreen;

impl LoadingScreen {
    pub fn draw(&self, f: &mut Frame, step: usize, step_name: &str, progress: f64, message: &str) {
        // Center the dialog at 50% width
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

        // Render centered loading dialog with Unicode indicators
    }
}
```

### Parser Integration

The parser accepts a terminal reference for loading screen updates:

```rust
pub fn parse_log_file<P: AsRef<Path>>(
    &self,
    path: P,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<Vec<AuditGroup>> {
    // Update loading screen during parsing
    terminal.draw(|f| {
        loading_screen.draw(f, step, step_name, progress, message);
    })?;
}
```

## IP Geolocation (ipapi.rs)

### Smart Subnet Caching

Queries are cached by /24 subnet for IPv4 to minimize API requests:

```rust
fn get_subnet_24(ip: &str) -> Option<String> {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        match addr {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                // Cache by .0 address
                Some(format!("{}.{}.{}.0", octets[0], octets[1], octets[2]))
            }
            IpAddr::V6(_) => {
                // IPv6 uses full address
                Some(ip.to_string())
            }
        }
    } else {
        None
    }
}
```

### API Integration

```rust
pub fn get_ip_info(&self, ip: &str) -> Result<String> {
    let cache_key = Self::get_subnet_24(ip)
        .unwrap_or_else(|| ip.to_string());

    // Check cache first
    {
        let cache = self.cache.lock().unwrap();
        if let Some(cached) = cache.get(&cache_key) {
            return Ok(cached.clone());
        }
    }

    // Fetch from API with all fields
    let url = format!(
        "http://ip-api.com/json/{}?fields=query,status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting",
        cache_key
    );

    let response = reqwest::blocking::get(&url)?;
    let api_response: IpApiResponse = response.json()?;
    let pretty_json = serde_json::to_string_pretty(&api_response)?;

    // Cache for future requests
    {
        let mut cache = self.cache.lock().unwrap();
        cache.insert(cache_key, pretty_json.clone());
    }

    Ok(pretty_json)
}
```

### Lazy Loading

IP information is only fetched when entering detail view or navigating between entries:

```rust
pub fn show_detail_view(&mut self) {
    self.current_view = AppView::DetailView;
    self.detail_scroll = 0;

    // Fetch IP info when entering detail view
    if self.ip_api_enabled {
        if let Some(group) = self.selected_group() {
            self.current_ip_info = self.ip_api_cache.get_ip_info(&group.client_ip).ok();
        }
    }
}
```

## User Interface (ui.rs)

### Dynamic Column Sizing

Columns automatically adjust based on terminal width:

```rust
fn calculate_column_widths(table_width: u16) -> [Constraint; 6] {
    let available_width = table_width.saturating_sub(7) as usize;

    // Minimum widths ensure all columns visible on narrow terminals
    const MIN_AUDIT_ID: usize = 12;
    const MIN_TIMESTAMP: usize = 16;
    const MIN_DOMAIN: usize = 15;
    const MIN_CLIENT_IP: usize = 15;
    const MIN_STATUS: usize = 6;
    const MIN_RULE_IDS: usize = 10;

    // Preferred maximums for optimal readability
    const PREF_AUDIT_ID: usize = 24;
    const PREF_TIMESTAMP: usize = 19;
    const PREF_DOMAIN: usize = 40;
    const PREF_CLIENT_IP: usize = 39;  // Full IPv6 width
    const PREF_STATUS: usize = 6;
    const PREF_RULE_IDS: usize = 20;

    // Intelligent growth distribution based on available space
    // ... (see ui.rs for full implementation)
}
```

### Table View Columns

The table view displays 6 columns:
1. **Audit ID** (12-24 chars)
2. **Timestamp** (16-19 chars)
3. **Domain** (15-40 chars)
4. **Client IP** (15-39 chars for IPv6)
5. **HTTP Status** (6 chars, color-coded)
6. **Rule IDs** (10-20 chars)

### JSON Syntax Highlighting

IP geolocation data is displayed with syntax highlighting:

```rust
fn colorize_json<'a>(json: &'a str, c: &ColorScheme) -> Vec<Line<'a>> {
    let mut lines = Vec::new();

    for line in json.lines() {
        let trimmed = line.trim_start();

        if trimmed.starts_with('{') || trimmed.starts_with('}') {
            // Braces in dark gray
            lines.push(Line::from(vec![
                Span::styled(line, Style::default().fg(c.boundary)),
            ]));
        } else if trimmed.starts_with('"') && trimmed.contains(':') {
            if let Some(colon_pos) = line.find(':') {
                let key_part = &line[..colon_pos + 1];
                let value_part = &line[colon_pos + 1..];

                // Strip trailing comma for comparison
                let value_trimmed = value_part.trim().trim_end_matches(',');
                let value_color = if value_part.trim().starts_with('"') {
                    c.host_header  // String values in cyan
                } else if value_trimmed == "true" || value_trimmed == "false" {
                    c.http_method  // Booleans in green
                } else if value_trimmed == "null" {
                    c.boundary  // Null in dark gray
                } else {
                    c.timestamp  // Numbers in blue
                };

                lines.push(Line::from(vec![
                    Span::styled(key_part, Style::default().fg(c.label).add_modifier(Modifier::BOLD)),
                    Span::styled(value_part, Style::default().fg(value_color)),
                ]));
            }
        }
    }

    lines
}
```

### Two-View System

#### 1. Table View (main.rs: handle_table_input)

**Mouse Support**: ENABLED
- Single-click: Select row
- Double-click: Open detail view (500ms window)
- Mouse capture is enabled in this view

**Keyboard Navigation**:
- `↑/k`: Move selection up
- `↓/j`: Move selection down
- `PgUp/PgDn`: Page up/down
- `Home/End`: Jump to first/last entry
- `Enter`: Open detail view for selected entry
- `r` or `F5`: Refresh log file (reload and reparse)
- `/`: Enter search mode
- `ESC`: Clear search
- `q`: Quit application

#### 2. Detail View (main.rs: handle_detail_input)

**Mouse Support**: DISABLED
- Allows native terminal text selection for copying

**Keyboard Navigation**:
- `↑/k`: Scroll up one line
- `↓/j`: Scroll down one line
- `←/h`: Previous entry (resets scroll to top, fetches new IP info)
- `→/l`: Next entry (resets scroll to top, fetches new IP info)
- `PageUp`: Scroll up one page
- `PageDown`: Scroll down one page
- `Home`: Scroll to top
- `End`: Scroll to bottom
- `q/Esc`: Return to table view

**Content Display**:
Shows complete raw audit log entry with syntax highlighting, followed by IP geolocation data (if enabled).

### Search System

Search is tokenized with prefix support:

- **`domain:VALUE`** - Filter by Host header (case-insensitive substring match)
- **`ip:VALUE`** - Filter by source IP address (substring match, works with IPv4/IPv6)
- **`rule:VALUE`** or **`id:VALUE`** - Filter by rule ID (searches all rule IDs in entry)
- **`auditid:VALUE`** - Filter by audit ID (the unique transaction identifier)
- **`status:VALUE`** or **`http:VALUE`** - Filter by HTTP status code
- **No prefix** - Search across all fields (domain, IP, audit ID, rule IDs, HTTP status)

Implementation in `app.rs`:

```rust
fn matches_search(&self, group: &AuditGroup) -> bool {
    let query = self.search_query.to_lowercase();

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
```

### Mouse Event Handling

**CRITICAL**: Use actual widget areas instead of hardcoded offsets.

**Table View Only** - Mouse capture enabled:

```rust
fn handle_mouse_input(app: &mut App, mouse: MouseEvent) {
    if let MouseEventKind::Down(_) = mouse.kind {
        // Use cached table_area from last render
        if let Some(table_area) = app.table_area {
            let content_start_y = table_area.y + 2; // Border + header row
            let content_height = table_area.height.saturating_sub(3);

            if mouse.row >= content_start_y && mouse.row < content_start_y + content_height {
                let clicked_row = (mouse.row - content_start_y) as usize;
                let actual_index = app.scroll_offset + clicked_row;

                if actual_index < app.filtered_groups.len() {
                    let should_open = app.handle_click(actual_index, content_height as usize);
                    if should_open {
                        app.show_detail_view();
                    }
                }
            }
        }
    }
}
```

**Detail View** - Mouse capture disabled for text selection:

```rust
// In run_app event loop
let should_enable_mouse = matches!(app.current_view, AppView::TableView);
if should_enable_mouse != mouse_enabled {
    if should_enable_mouse {
        execute!(io::stdout(), EnableMouseCapture)?;
    } else {
        execute!(io::stdout(), DisableMouseCapture)?;
    }
    mouse_enabled = should_enable_mouse;
}
```

### Double-Click Detection

```rust
pub fn handle_click(&mut self, row: usize, visible_height: usize) -> bool {
    const DOUBLE_CLICK_MS: u64 = 500;
    let now = Instant::now();
    let mut should_open_detail = false;

    // Check for double-click
    if let (Some(last_time), Some(last_row)) = (self.last_click_time, self.last_click_row) {
        if last_row == row && now.duration_since(last_time) < Duration::from_millis(DOUBLE_CLICK_MS) {
            should_open_detail = true;
        }
    }

    self.selected_index = row;

    // Auto-scroll logic
    if self.selected_index < self.scroll_offset {
        self.scroll_offset = self.selected_index;
    } else if self.selected_index >= self.scroll_offset + visible_height {
        self.scroll_offset = self.selected_index.saturating_sub(visible_height - 1);
    }

    self.last_click_time = Some(now);
    self.last_click_row = Some(row);

    should_open_detail
}
```

## Refresh Functionality

Reload and reparse the log file while preserving UI state:

```rust
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
```

## Known Issues & Gotchas

### 1. Carriage Return Handling
Windows-style line endings (`\r\n`) can cause issues with domain extraction. Always strip `\r` from captured values:

```rust
let domain = self.host_re
    .captures(&content)
    .and_then(|c| c.get(1))
    .map(|m| m.as_str().trim().trim_end_matches('\r').to_string())
    .unwrap_or_else(|| "unknown".to_string());
```

### 2. Entry Grouping
Audit log entries are identified by boundaries. The boundary prefix is consistent within a log file but varies between files. Parse it dynamically from the first entry:

```rust
fn extract_boundary_prefix(content: &str) -> Option<String> {
    if let Some(first_line) = content.lines().next() {
        if first_line.starts_with("--") && first_line.ends_with("-A--") {
            let prefix = first_line.strip_prefix("--")?
                .strip_suffix("-A--")?;
            return Some(prefix.to_string());
        }
    }
    None
}
```

### 3. IPv6 vs IPv4
Do NOT try to use complex regex to differentiate IP formats. Use field position in the A section:
- Field 1: `[timestamp]`
- Field 2: `audit-id`
- Field 3: `source-ip` ← This is what we want
- Field 4: `source-port`
- Field 5: `dest-ip`
- Field 6: `dest-port`

### 4. Table Area Tracking
Store the actual table widget area for accurate mouse click calculation:

```rust
// In draw_table_view()
app.table_area = Some(chunks[1]);
```

Use this stored area instead of hardcoded offsets for mouse event handling.

### 5. Detail Scroll Reset
When navigating between entries in detail view (left/right arrows), always reset `detail_scroll` to 0 and fetch new IP info:

```rust
KeyCode::Left | KeyCode::Char('h') => {
    app.move_selection_up();
    app.detail_scroll = 0; // Important!

    // Fetch new IP info
    if app.ip_api_enabled {
        if let Some(group) = app.selected_group() {
            app.current_ip_info = app.ip_api_cache.get_ip_info(&group.client_ip).ok();
        }
    }
},
```

### 6. Terminal State Management
Use a single terminal instance throughout the application lifecycle. The loading screen should render via `&mut Frame`, not own a terminal:

```rust
// WRONG - Creates separate terminal instances
let mut loading_terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

// CORRECT - Shares terminal instance
terminal.draw(|f| {
    loading_screen.draw(f, step, step_name, progress, message);
})?;
```

### 7. Case-Insensitive Header Matching
Always convert to lowercase for comparison, but preserve original case for display:

```rust
let line_lower = line.to_lowercase();
if line_lower.starts_with("host:") {
    // Use original line for display, line_lower for matching
}
```

## Build & Run

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run with custom log file
cargo run --release -- /var/log/apache2/modsec_audit.log

# Disable IP geolocation
cargo run --release -- --ip-api false /var/log/apache2/modsec_audit.log

# Or run the binary directly
./target/release/waflens /var/log/apache2/modsec_audit.log
```

## File Organization

```
waflens/
├── Cargo.toml              # Dependencies and project metadata
├── .github/
│   └── workflows/
│       └── release.yml     # GitHub Actions for releases
├── src/
│   ├── main.rs            # Entry point, event loop, input handling
│   ├── app.rs             # Application state, search, navigation
│   ├── parser.rs          # ModSecurity log parsing logic
│   ├── ui.rs              # Ratatui UI rendering
│   ├── colors.rs          # Adaptive color scheme
│   ├── loading.rs         # Loading screen
│   └── ipapi.rs           # IP geolocation cache
├── CLAUDE.md              # This file - technical documentation
├── PROJECT_STRUCTURE.md   # High-level project overview
└── README.md              # User-facing documentation
```

## Testing Checklist

When making changes, verify:

- [ ] IPv4 addresses parse correctly
- [ ] IPv6 addresses parse correctly (full and shortened formats)
- [ ] Domain extraction works with various Host header formats
- [ ] HTTP status codes extracted from F section
- [ ] Search filters work: `domain:`, `ip:`, `id:`, `auditid:`, `status:`
- [ ] Mouse click selection works in table view (using actual widget areas)
- [ ] Double-click opens detail view
- [ ] Text selection works in detail view (mouse disabled)
- [ ] Scroll position preserved when switching views
- [ ] Refresh (`r` or `F5`) reloads file and preserves selection
- [ ] Left/right arrows navigate entries in detail view
- [ ] Page Up/Down scrolls in detail view
- [ ] All rule IDs extracted from H section
- [ ] Carriage returns handled in domain names
- [ ] IP geolocation fetches on detail view (if enabled)
- [ ] IP geolocation respects /24 subnet caching
- [ ] Dynamic column sizing works on various terminal widths
- [ ] HTTP status colors correct (2xx=green, 3xx=cyan, 4xx=red, 5xx=purple)
- [ ] JSON syntax highlighting works for IP data
- [ ] Loading screen displays centered during parsing

## Performance Considerations

- Regex compilation is done once in `AuditLogParser::new()` and reused
- `filtered_groups` stores indices, not clones of entries
- Full content is stored once per entry, displayed directly in detail view
- Search filtering is O(n) but only runs when search query changes
- IP geolocation is lazy-loaded only when needed
- /24 subnet caching minimizes API requests
- Dynamic column width calculation is cached per render

## GitHub Actions / Releases

The project uses GitHub Actions for automated releases:

- **Trigger**: Push tags matching `[0-9]+.[0-9]+.[0-9]+` (e.g., `0.1.0`, `1.2.3-beta`)
- **Build targets**:
  - Windows x86-64 (MSVC)
  - Linux x86-64 (glibc)
  - Linux x86-64 (musl - static binary)
- **Artifacts**: Pre-built binaries attached to GitHub releases
- **Future provisions**: Commented configs for macOS (x86-64/ARM64) and Linux ARM64

## Future Enhancement Ideas

- Support for compressed (.gz) log files
- Incremental log loading for better memory efficiency
- Sort options (by time, IP, domain, rule ID, status)
- Export filtered results to CSV/JSON
- Summary statistics view
- Multiple file support
- Real-time log tailing mode (tail -f behavior)
- Rule ID → Rule name mapping from ModSecurity config files
- Configuration file support for defaults
- Custom color scheme configuration
