# Waflens - Project Structure

## Overview

A terminal user interface (TUI) application built with Rust for examining ModSecurity audit logs. Waflens provides an intuitive lens into your Web Application Firewall logs with features like IP geolocation, adaptive colors, advanced search, and live refresh.

## Project Files

```
waflens/
├── Cargo.toml              # Project dependencies and metadata
├── README.md               # User-facing documentation
├── CLAUDE.md               # Technical documentation for development
├── PROJECT_STRUCTURE.md    # This file - project overview
├── .gitignore              # Git ignore rules
├── test_sample.log         # Sample audit log file for testing
├── .github/
│   └── workflows/
│       └── release.yml     # GitHub Actions for automated releases
├── src/
    ├── main.rs            # Entry point, terminal setup, event loop
    ├── app.rs             # Application state and logic
    ├── parser.rs          # ModSecurity log parser (serial format)
    ├── ui.rs              # TUI rendering logic
    ├── colors.rs          # Adaptive color scheme (16/256 colors)
    ├── loading.rs         # Loading screen during log parsing
    └── ipapi.rs           # IP geolocation with subnet caching

```

## Module Breakdown

### main.rs
- Terminal initialization and cleanup with proper state restoration
- Main event loop with view-specific input handling
- Keyboard and mouse input routing
- Dynamic mouse capture (enabled in table view, disabled in detail view)
- View-specific event handling (table vs detail)

### app.rs
- `App` struct - holds application state
- `AppView` enum - defines view modes (Table/Detail)
- Search functionality with tokenized queries (domain, ip, rule, status, auditid)
- Navigation and selection management with scroll tracking
- Filter management with real-time application
- Refresh functionality to reload the log file while preserving position
- Double-click detection for detail view opening
- Table area tracking for accurate mouse click handling
- IP API cache integration

### parser.rs
- `AuditEntry` - represents a single audit log entry with all metadata
- `AuditGroup` - groups related entries by audit ID
- `AuditLogParser` - parses ModSecurity audit logs in serial format
- Regex-based extraction of:
  - Timestamps (section A)
  - Client IPs (IPv4 and IPv6 support from section A)
  - Domains (Host header from section B)
  - Rule IDs (all IDs from section H)
  - HTTP status codes (section F)
- Boundary-based parsing (`--id-part--` format)
- Progress reporting during parsing for loading screen

### ui.rs
- Renders the TUI using Ratatui
- Dynamic column width calculation based on terminal size
- Two main views:
  - **Table view**: List of all audit groups with 6 columns:
    - Audit ID (12-24 chars)
    - Timestamp (16-19 chars)
    - Domain (15-40 chars)
    - Client IP (15-39 chars for IPv6)
    - HTTP Status (6 chars, color-coded)
    - Rule IDs (10-20 chars)
  - **Detail view**: Full request chain with syntax highlighting and IP geolocation
- Color coding logic for syntax highlighting
- JSON syntax highlighting for IP geolocation data
- Help text and search bar rendering
- Case-insensitive header matching (Host, User-Agent)

### colors.rs
- `ColorScheme` struct with all UI colors
- Automatic terminal capability detection via `COLORTERM` and `TERM` env vars
- Two color modes:
  - **16-color mode**: Uses bright variants (LightCyan, LightYellow, etc.)
  - **256-color mode**: Uses indexed colors for better palette
- HTTP status color coding:
  - 2xx: Green
  - 3xx: Cyan
  - 4xx: Red
  - 5xx: Magenta/Purple
- Consistent color scheme across table and detail views

### loading.rs
- `LoadingScreen` struct for rendering parse progress
- Frame-based rendering (shares terminal with main app)
- Centered dialog at 50% terminal width
- Three-step progress display:
  1. Reading log file
  2. Parsing entries
  3. Building index
- Unicode progress indicators (✅, 📁, 📊, 🔗)
- Percentage-based progress gauge

### ipapi.rs
- `IpApiCache` - Thread-safe cache with Mutex
- `IpApiResponse` - Serde-compatible response structure
- IP geolocation from ip-api.com
- Lazy loading (only fetches on detail view)
- Fields: geolocation, network info, ISP, threat intelligence (mobile/proxy/hosting)
- Pretty-printed JSON with syntax highlighting
- Respects rate limits (45 requests/minute free tier)

## Dependencies

- **ratatui** (0.29) - Terminal UI framework
- **crossterm** (0.28) - Cross-platform terminal manipulation
- **chrono** (0.4) - Date/time parsing and formatting
- **regex** (1.11) - Regular expression matching
- **anyhow** (1.0) - Error handling
- **clap** (4.5) - Command-line argument parsing with derive macros
- **indicatif** (0.17) - Progress bars and indicators
- **num-format** (0.4) - Number formatting for display
- **reqwest** (0.12) - HTTP client with blocking and JSON support
- **serde** (1.0) - Serialization framework with derive macros
- **serde_json** (1.0) - JSON serialization/deserialization

## Key Features

### Search Tokenization
The app supports special search tokens:
- `domain:example.com` - Filter by Host header (case-insensitive)
- `ip:1.2.3.4` - Filter by client IP (works with IPv4 and IPv6)
- `rule:942100` - Filter by rule ID (searches all rule IDs)
- `auditid:xyz` - Filter by audit ID (unique transaction ID)
- `status:429` or `http:200` - Filter by HTTP status code
- Regular text - Search across all fields

### Color Coding

#### Table View
- **Green** - 2xx success responses
- **Cyan** - 3xx redirects
- **Red** - 4xx client errors (rate limits, bad requests, etc.)
- **Purple/Magenta** - 5xx server errors

#### Detail View
- **Green** - HTTP request methods, booleans (true/false), User-Agent values
- **Yellow/Orange** - Header names, JSON keys, rule information
- **Blue** - Timestamps, numbers, HTTP status codes
- **Cyan** - Host headers, string values in JSON
- **Red** - ModSecurity alerts
- **Dark Gray** - Boundary markers, null values in JSON

### Dynamic Column Sizing
- Automatically adjusts column widths based on terminal size
- Minimum widths ensure all columns visible on narrow terminals
- Preferred maximums for optimal readability
- Intelligent growth distribution prioritizes important fields

### IP Geolocation
- Automatic IP lookup via ip-api.com (can be disabled with `--ip-api false`)
- Tries to minimize API requests by querying for the `.0` instead of each IP in a /24, and caches the result
- Displays at end of detail view after Z boundary
- Syntax-highlighted JSON with:
  - Geolocation: Country, region, city, timezone, coordinates
  - Network Info: ISP, organization, AS number/name
  - Threat Intelligence: Mobile, proxy, and hosting flags
- Only fetches when entering detail view (lazy loading)
- Updates when navigating between entries with left/right arrows

### Navigation

#### Table View
- `↑/↓` or `k/j` - Navigate up/down
- `PgUp/PgDn` - Page up/down
- `Home/End` - Jump to first/last entry
- `Enter` - View details of selected entry
- **Mouse Click** - Select entry
- **Double-Click** - View details (500ms window)
- `/` - Enter search mode
- `r` or `F5` - Refresh log file
- `ESC` - Clear search
- `q` - Quit application

#### Detail View
- `↑/↓` or `k/j` - Scroll up/down one line
- `PgUp/PgDn` - Scroll up/down one page
- `Home/End` - Jump to top/bottom
- `←/→` or `h/l` - Previous/next entry (resets scroll, fetches new IP info)
- `ESC` or `q` - Return to table view

### Mouse Support
- **Table view**: Mouse capture enabled for click selection and double-click to open details
- **Detail view**: Mouse capture disabled to allow native terminal text selection for copying

### Refresh Functionality
- Press `r` or `F5` to reload the log file
- Preserves current selection and scroll position
- Re-applies current search filter
- Shows loading screen during reload

## Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run against a specific log file
cargo run --release -- /var/log/apache2/modsec_audit.log

# Disable IP geolocation
cargo run --release -- --ip-api false /var/log/apache2/modsec_audit.log
```

## Command-Line Options

- `--ip-api <true|false>` - Enable/disable IP geolocation lookups (default: true)
- `<FILE>` - Path to ModSecurity audit log file (default: modsec_audit.log)

## GitHub Actions / Releases

The project includes automated release builds via GitHub Actions:

- **Trigger**: Push tags matching `[0-9]+.[0-9]+.[0-9]+` (e.g., `0.1.0`, `1.2.3-beta`)
- **Build targets**:
  - Windows x86-64 (MSVC)
  - Linux x86-64 (glibc)
  - Linux x86-64 (musl - static binary)
- **Artifacts**: Pre-built binaries attached to GitHub releases
- **Future provisions**: Commented configs for macOS (x86-64/ARM64) and Linux ARM64

Workflow file: [.github/workflows/release.yml](.github/workflows/release.yml)

## Testing

Use the provided test log file:
```bash
cargo run --release -- test_sample.log
```

Test with IP geolocation disabled:
```bash
cargo run --release -- --ip-api false modsec_audit.log
```

## Known Limitations

- Only serialized ModSecurity Audit logging is supported. JSON Audit Logs **or** Concurrent Audit Logs are **NOT** supported or planned
- Log is fully loaded in memory when starting. This results in high memory usage. A ~400MB log file usually results in ~800MB memory usage
- Refreshing the log usually means re-reading the full file again
- **NO** support for reading compressed (.gz) log files, yet

## Performance Considerations

- **Fast Parsing**: Processes large log files efficiently with streaming parser
- **Responsive UI**: 4K @ 60fps rendering with Ratatui! /s
- **Smart Caching**: IP lookups cached by /24 subnet to minimize API requests
- **Regex Compilation**: Compiled once at parser initialization and reused
- **Index-Based Filtering**: `filtered_groups` stores indices, not clones

## Future Enhancements

Potential improvements:
- [ ] Support for compressed (.gz) log files
- [ ] Incremental log loading for better memory efficiency
- [ ] Tail -f mode for real-time log monitoring
- [ ] Export filtered results to CSV/JSON
- [ ] Sort by different columns (clickable headers)
- [ ] Configuration file support for defaults
- [ ] Custom color scheme configuration
- [ ] Statistics dashboard view
- [ ] Multi-field search with AND/OR operators
- [ ] Rule ID to rule name mapping from ModSecurity config files