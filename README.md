# Waflens

A terminal-based UI (TUI) application for examining ModSecurity audit logs.

The primary motivation for creating this tool was simply to examine the `modsec_audit.log` file on cPanel/WHM machines.

![Waflens](https://123.456.ro/share/2025/11/termtosvg_objwrsmd.svg)

## Features

- **Table View**: Browse all ModSecurity hits with HTTP status codes, timestamps, domains, IPs, and rule IDs
- **IP Geolocation**: Automatic IP lookup with geolocation, ISP, and threat intelligence data (via ip-api.com)
- **Color-Coded HTTP Status**: Instant visual feedback (green for 2xx, cyan for 3xx, red for 4xx, purple for 5xx)
- **Advanced Search**: Tokenized search with filters
  - `domain:example.com` - Filter by domain
  - `ip:1.2.3.4` - Filter by IP address
  - `status:429` - Filter by HTTP status code
  - `rule:123456` - Filter by rule ID
  - `auditid:xyz` - Filter by audit ID
  - Or just type freely to search across all fields
- **Detail View**: View full request chain (A-Z parts) with syntax highlighting
- **Refresh**: Live refresh to see new log entries (press `r` or `F5`)
- **Mouse Support**: Click to select, double-click to view details
- **Adaptive Colors**: Automatically uses 16 or 256 color palette when available

## Installation

### Prerequisites

- Rust toolchain (install from [rustup.rs](https://rustup.rs))

### Download Pre-built Binaries

Download the latest release for your platform from the [Releases](https://github.com/Znuff/Waflens/releases) page.

Available platforms:
- Windows x86-64
- Linux x86-64 (glibc)
- Linux x86-64 (musl)

### Build from source

```bash
git clone https://github.com/Znuff/Waflens
cd waflens
cargo build --release
```

The binary will be available at `target/release/waflens` (or `waflens.exe` on Windows)

## Usage

```bash
# Specify file
waflens /var/log/apache2/modsec_audit.log

# Disable IP API lookups (for offline use)
waflens --ip-api false /var/log/apache2/modsec_audit.log

# Show help
waflens --help
```

### Command-Line Options

- `--ip-api <true|false>` - Enable/disable IP geolocation lookups (default: true)
- `<FILE>` - Path to ModSecurity audit log file (default: modsec_audit.log)

## Keyboard Controls

### Table View
- `↑/↓` or `k/j` - Navigate up/down
- `PgUp/PgDn` - Page up/down
- `Home/End` - Jump to first/last entry
- `Enter` - View details of selected entry
- **Mouse Click** - Select entry
- **Double-Click** - View details
- `/` - Enter search mode
- `r` or `F5` - Refresh log file
- `ESC` - Clear search
- `q` - Quit application

### Search Mode
- Type to search
- `Backspace` - Delete character
- `Enter` - Apply search and exit search mode
- `ESC` - Cancel search and clear

### Detail View
- `↑/↓` or `k/j` - Scroll up/down one line
- `PgUp/PgDn` - Scroll up/down one page
- `Home/End` - Jump to top/bottom
- `←/→` or `h/l` - Previous/next entry
- `ESC` or `q` - Return to table view

## Color Coding

### Table View
- **Green** - 2xx success responses
- **Cyan** - 3xx redirects
- **Red** - 4xx client errors (rate limits, bad requests, etc.)
- **Purple/Magenta** - 5xx server errors

### Detail View
The detail view uses syntax highlighting for easy reading:

- **Green** - HTTP request methods, booleans (true/false)
- **Yellow/Orange** - Header names, JSON keys, rule information
- **Blue** - Timestamps, numbers, HTTP status codes
- **Cyan** - Host headers, string values
- **Red** - ModSecurity alerts
- **Dark Gray** - Boundary markers, null values

## ModSecurity Audit Log Format

This tool expects ModSecurity audit logs in the **serial** format (single file with all entries concatenated). The format uses boundary markers to separate different parts:

```
--unique-id-A--
[timestamp] unique-id source-ip source-port destination-ip destination-port
--unique-id-A--
--unique-id-B--
GET /path HTTP/1.1
Host: example.com
...
--unique-id-B--
--unique-id-H--
ModSecurity: Warning. [id "123456"] ...
--unique-id-H--
--unique-id-Z--
--unique-id-Z--
```

Each request is identified by a unique ID, and the different parts (A, B, H, Z, etc.) contain different aspects of the request and response.

### Common Parts:
- **A**: Audit log header (metadata)
- **B**: Request headers
- **C**: Request body (if any)
- **H**: ModSecurity audit trail messages (rules matched)
- **Z**: Final boundary marker

On cPanel/WHM systems, the audit log is typically located at `/var/log/apache2/modsec_audit.log`.

## IP Geolocation

Waflens uses [ip-api.com](https://ip-api.com) to provide geolocation and network information for client IPs:

- **Geolocation**: Country, region, city, timezone, coordinates
- **Network Info**: ISP, organization, AS number/name
- **Threat Intelligence**: Mobile, proxy, and hosting flags

### Features
- **Smart Caching**: Queries are cached by /24 subnet (ie: 1.2.3.0) to minimize API requests
- **Offline Mode**: Use `--ip-api false` to disable lookups entirely

The free tier allows 45 requests per minute, which should be enough.

## Performance

- **Fast Parsing**: Processes large log files efficiently with streaming parser
- **Responsive UI**: 60fps in glorious 4K rendering with Ratatui!

## Known Limitations / Issues

- Only serialized ModSecurity Audit logging is supported. JSON Audit Logs __or__ Concurrent Audit Logs are **NOT** supported or planned
- Log is fully read loaded up in memory when starting. This will result in high memory usage. A ~400MB log file usually results in about ~800MB memory usage from my observations
- Refreshing the log usually means re-reading the full file again!
- **NO** support for reading compressed (.gz) log files, yet!

## License

MIT

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## Disclaimer

This app is 99.99% "vibe-coded", there might be glaring issues with it. 
