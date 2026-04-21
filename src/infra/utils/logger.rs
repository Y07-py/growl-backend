use slog::{o, Drain, Logger};
use slog_async;
use slog_term;

/// Initializes the global application logger using slog.
/// The output format includes:
/// - Timestamp (local time)
/// - Log Level (INFO, ERROR, etc.)
/// - Source file location (file:line)
/// - Log message content
pub fn init_logger() -> Logger {
    // 1. Create a decorator for colored terminal output
    let decorator = slog_term::TermDecorator::new().build();

    // 2. Configure the format. FullFormat automatically includes:
    //    - Timestamps
    //    - Log levels
    //    - Modules and File/Line information (location)
    let drain = slog_term::FullFormat::new(decorator)
        .use_local_timestamp()
        .build()
        .fuse();

    // 3. Wrap in an async drain to avoid blocking the main thread during I/O
    let drain = slog_async::Async::new(drain).build().fuse();

    // 4. Create the root logger with some global attributes
    Logger::root(
        drain,
        o!(
            "version" => env!("CARGO_PKG_VERSION"),
        ),
    )
}
