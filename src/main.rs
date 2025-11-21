mod app;
mod colors;
mod ipapi;
mod loading;
mod parser;
mod ui;

use anyhow::Result;
use app::{App, AppView};
use clap::Parser as ClapParser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseEvent, MouseEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};
use std::io;

#[derive(ClapParser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to ModSecurity audit log file
    file: String,

    /// Enable IP API lookups (fetches geo/ISP data from ip-api.com)
    #[arg(long = "ip-api", default_value_t = true, action = clap::ArgAction::Set)]
    ip_api: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Check if file exists and is readable before launching UI
    if !std::path::Path::new(&args.file).exists() {
        eprintln!("Error: File '{}' does not exist", args.file);
        std::process::exit(1);
    }

    if let Err(e) = std::fs::File::open(&args.file) {
        eprintln!("Error: Cannot read file '{}': {}", args.file, e);
        std::process::exit(1);
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app (this will show the loading screen)
    let mut app = App::new(&args.file, &mut terminal, args.ip_api)?;

    // Main loop
    let res = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Error: {:?}", err);
    }

    Ok(())
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    let mut mouse_enabled = false;

    loop {
        // Enable mouse in table view, disable in detail view
        let should_enable_mouse = matches!(app.current_view, AppView::TableView);
        if should_enable_mouse != mouse_enabled {
            if should_enable_mouse {
                execute!(io::stdout(), EnableMouseCapture)?;
            } else {
                execute!(io::stdout(), DisableMouseCapture)?;
            }
            mouse_enabled = should_enable_mouse;
        }

        terminal.draw(|f| ui::draw(f, app))?;

        match event::read()? {
            Event::Key(key) => {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                match app.current_view {
                    AppView::TableView => {
                        if app.search_mode {
                            handle_search_input(app, key.code);
                        } else {
                            let needs_redraw = handle_table_input(app, terminal, key.code);
                            if needs_redraw {
                                // Force a complete terminal redraw after refresh
                                terminal.clear()?;
                            }
                        }
                    }
                    AppView::DetailView => {
                        handle_detail_input(app, key.code);
                    }
                }
            }
            Event::Mouse(mouse) => {
                // Only handle mouse events in table view for row selection
                if matches!(app.current_view, AppView::TableView) && !app.search_mode {
                    handle_mouse_input(app, mouse);
                }
            }
            _ => {}
        }

        if app.should_quit {
            break;
        }
    }

    // Ensure mouse is disabled when exiting
    if mouse_enabled {
        execute!(io::stdout(), DisableMouseCapture)?;
    }

    Ok(())
}

fn handle_table_input(app: &mut App, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, key: KeyCode) -> bool {
    const VISIBLE_HEIGHT: usize = 20;
    let mut needs_redraw = false;

    match key {
        KeyCode::Char('q') => app.quit(),
        KeyCode::Up | KeyCode::Char('k') => app.move_selection_up(),
        KeyCode::Down | KeyCode::Char('j') => app.move_selection_down(VISIBLE_HEIGHT),
        KeyCode::PageUp => app.page_up(VISIBLE_HEIGHT),
        KeyCode::PageDown => app.page_down(VISIBLE_HEIGHT),
        KeyCode::Home => {
            app.selected_index = 0;
            app.scroll_offset = 0;
        }
        KeyCode::End => {
            let last = app.filtered_groups.len().saturating_sub(1);
            app.selected_index = last;
            app.scroll_offset = last.saturating_sub(VISIBLE_HEIGHT - 1);
        }
        KeyCode::Enter => app.show_detail_view(),
        KeyCode::Char('/') => app.enter_search_mode(),
        KeyCode::Char('r') | KeyCode::F(5) => {
            let _ = app.refresh(terminal);
            needs_redraw = true;
        }
        KeyCode::Esc => app.clear_search(),
        _ => {}
    }

    needs_redraw
}

fn handle_search_input(app: &mut App, key: KeyCode) {
    match key {
        KeyCode::Char(c) => app.add_search_char(c),
        KeyCode::Backspace => app.remove_search_char(),
        KeyCode::Enter => app.exit_search_mode(),
        KeyCode::Esc => {
            app.exit_search_mode();
            app.clear_search();
        }
        _ => {}
    }
}

fn handle_detail_input(app: &mut App, key: KeyCode) {
    const PAGE_SIZE: usize = 10;
    const VISIBLE_HEIGHT: usize = 20;

    match key {
        KeyCode::Char('q') | KeyCode::Esc => app.show_table_view(),
        KeyCode::Up | KeyCode::Char('k') => app.scroll_detail_up(),
        KeyCode::Down | KeyCode::Char('j') => app.scroll_detail_down(),
        KeyCode::PageUp => app.page_detail_up(PAGE_SIZE),
        KeyCode::PageDown => app.page_detail_down(PAGE_SIZE),
        KeyCode::Home => app.scroll_detail_home(),
        KeyCode::End => app.scroll_detail_end(),
        KeyCode::Left | KeyCode::Char('h') => {
            app.move_selection_up();
            app.detail_scroll = 0; // Reset scroll to top when switching entries
            // Fetch new IP info for the new entry
            if app.ip_api_enabled {
                if let Some(group) = app.selected_group() {
                    app.current_ip_info = app.ip_api_cache.get_ip_info(&group.client_ip).ok();
                }
            }
        },
        KeyCode::Right | KeyCode::Char('l') => {
            app.move_selection_down(VISIBLE_HEIGHT);
            app.detail_scroll = 0; // Reset scroll to top when switching entries
            // Fetch new IP info for the new entry
            if app.ip_api_enabled {
                if let Some(group) = app.selected_group() {
                    app.current_ip_info = app.ip_api_cache.get_ip_info(&group.client_ip).ok();
                }
            }
        },
        _ => {}
    }
}

fn handle_mouse_input(app: &mut App, mouse: MouseEvent) {
    if let MouseEventKind::Down(_) = mouse.kind {
        // Use the stored table area to properly calculate which row was clicked
        if let Some(table_area) = app.table_area {
            // Table has borders (1 top, 1 bottom) and a header row (1)
            // So content starts at table_area.y + 2 (top border + header)
            let content_start = table_area.y + 2;
            let content_height = table_area.height.saturating_sub(3) as usize; // Subtract top border, header, bottom border

            // Check if click is within the table content area
            if mouse.row >= content_start && mouse.row < table_area.y + table_area.height - 1 {
                let clicked_row = (mouse.row - content_start) as usize;
                let actual_index = app.scroll_offset + clicked_row;

                // Check if click is within valid range
                if actual_index < app.filtered_groups.len() {
                    let should_open = app.handle_click(actual_index, content_height);
                    if should_open {
                        app.show_detail_view();
                    }
                }
            }
        }
    }
}
