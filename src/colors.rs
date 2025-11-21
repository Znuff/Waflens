use ratatui::style::Color;

/// Color scheme that adapts to terminal capabilities
pub struct ColorScheme {
    // UI Chrome
    pub title: Color,
    pub help_text: Color,
    pub search_highlight: Color,

    // Table headers
    pub header: Color,

    // Table row content
    pub audit_id: Color,
    pub timestamp: Color,
    pub domain: Color,
    pub client_ip: Color,
    pub rule_id: Color,

    // HTTP status colors (table view)
    pub status_2xx: Color,  // Success (200-299)
    pub status_3xx: Color,  // Redirect (300-399)
    pub status_4xx: Color,  // Client error (400-499)
    pub status_5xx: Color,  // Server error (500-599)
    pub status_unknown: Color,

    // Selection/highlight
    pub selected_bg: Color,
    pub selected_fg: Color,

    // Detail view
    pub label: Color,
    pub http_method: Color,
    pub http_status: Color,
    pub host_header: Color,
    pub user_agent: Color,
    pub modsec_message: Color,
    pub rule_id_detail: Color,
    pub boundary: Color,
    pub header_name: Color,
}

impl ColorScheme {
    /// Get color for HTTP status code based on its value
    pub fn status_color(&self, status: Option<u16>) -> Color {
        match status {
            Some(code) if code >= 200 && code < 300 => self.status_2xx,
            Some(code) if code >= 300 && code < 400 => self.status_3xx,
            Some(code) if code >= 400 && code < 500 => self.status_4xx,
            Some(code) if code >= 500 && code < 600 => self.status_5xx,
            _ => self.status_unknown,
        }
    }

    /// Detect terminal color support and return appropriate scheme
    pub fn detect() -> Self {
        // Check COLORTERM environment variable for truecolor/256color support
        if let Ok(colorterm) = std::env::var("COLORTERM") {
            if colorterm.contains("truecolor") || colorterm.contains("24bit") {
                return Self::colors_256();
            }
        }

        // Check TERM environment variable
        if let Ok(term) = std::env::var("TERM") {
            if term.contains("256color") {
                return Self::colors_256();
            } else if term.contains("16color") || term.contains("color") {
                return Self::colors_16();
            }
        }

        // Default to 16-color scheme for better compatibility
        Self::colors_16()
    }

    /// 16-color scheme using bright variants (colors 8-15)
    /// Works on basic terminals but uses the brighter upper range
    fn colors_16() -> Self {
        Self {
            // UI Chrome - use bright variants
            title: Color::LightCyan,
            help_text: Color::DarkGray,
            search_highlight: Color::LightYellow,

            // Table headers
            header: Color::LightYellow,

            // Table row content - use bright colors for better visibility
            audit_id: Color::LightGreen,
            timestamp: Color::LightBlue,
            domain: Color::LightMagenta,
            client_ip: Color::LightRed,
            rule_id: Color::LightYellow,

            // HTTP status colors
            status_2xx: Color::Green,
            status_3xx: Color::Cyan,
            status_4xx: Color::Red,
            status_5xx: Color::Magenta,
            status_unknown: Color::DarkGray,

            // Selection/highlight
            selected_bg: Color::White,
            selected_fg: Color::Black,

            // Detail view
            label: Color::LightYellow,
            http_method: Color::LightGreen,
            http_status: Color::LightBlue,
            host_header: Color::LightCyan,
            user_agent: Color::Green,
            modsec_message: Color::LightRed,
            rule_id_detail: Color::LightMagenta,
            boundary: Color::DarkGray,
            header_name: Color::LightYellow,
        }
    }

    /// 256-color scheme with more nuanced colors
    fn colors_256() -> Self {
        Self {
            // UI Chrome - sophisticated blues and grays
            title: Color::Indexed(117),        // Light cyan blue
            help_text: Color::Indexed(240),    // Dark gray
            search_highlight: Color::Indexed(226), // Bright yellow

            // Table headers
            header: Color::Indexed(214),       // Orange-yellow

            // Table row content - distinct, readable colors
            audit_id: Color::Indexed(78),      // Medium green
            timestamp: Color::Indexed(111),    // Medium blue
            domain: Color::Indexed(177),       // Violet
            client_ip: Color::Indexed(203),    // Light red/pink
            rule_id: Color::Indexed(222),      // Light yellow

            // HTTP status colors
            status_2xx: Color::Indexed(46),    // Bright green (success)
            status_3xx: Color::Indexed(81),    // Cyan (redirect)
            status_4xx: Color::Indexed(196),   // Red (client error)
            status_5xx: Color::Indexed(170),   // Purple/magenta (server error)
            status_unknown: Color::Indexed(240), // Dark gray

            // Selection/highlight
            selected_bg: Color::Indexed(237),  // Dark gray background
            selected_fg: Color::Indexed(231),  // Almost white foreground

            // Detail view - rich, distinct colors
            label: Color::Indexed(214),        // Orange-yellow
            http_method: Color::Indexed(120),  // Bright green
            http_status: Color::Indexed(75),   // Sky blue
            host_header: Color::Indexed(117),  // Light cyan blue
            user_agent: Color::Indexed(34),    // Dark green
            modsec_message: Color::Indexed(203), // Light red
            rule_id_detail: Color::Indexed(213), // Pink/magenta
            boundary: Color::Indexed(237),     // Dark gray
            header_name: Color::Indexed(180),  // Tan/beige
        }
    }
}
