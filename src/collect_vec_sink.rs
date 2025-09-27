use atomic::{Atomic, Ordering};
use spdlog::{
    ErrorHandler, Record, StringBuf,
    formatter::{Formatter, FormatterContext, PatternFormatter, pattern},
    prelude::*,
    sink::Sink,
};
use spin::{Mutex, RwLock};

#[derive(Clone)]
pub(crate) struct LogContext {
    pub(crate) payload: String,
    pub(crate) level: Level,
}

pub(crate) struct CollectVecSink {
    level_filter: Atomic<LevelFilter>,
    formatter: RwLock<Box<dyn Formatter>>,
    error_handler: Atomic<Option<ErrorHandler>>,
    collected: Mutex<Vec<LogContext>>,
}

impl CollectVecSink {
    pub(crate) fn new() -> Self {
        Self {
            level_filter: Atomic::new(LevelFilter::All),
            formatter: RwLock::new(Box::new(PatternFormatter::new(pattern!(
                "[{time}.{millisecond}] [{^{level_short}}] {payload}"
            )))),
            error_handler: Atomic::new(None),
            collected: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn collected(&self) -> Vec<LogContext> {
        self.collected.lock().clone()
    }
}

impl Sink for CollectVecSink {
    fn log(&self, record: &Record) -> spdlog::Result<()> {
        let mut string_buf = StringBuf::new();
        let mut ctx = FormatterContext::new();
        self.formatter
            .read()
            .format(record, &mut string_buf, &mut ctx)?;
        self.collected.lock().push(LogContext {
            payload: string_buf.to_string(),
            level: record.level(),
        });
        Ok(())
    }

    fn flush(&self) -> spdlog::Result<()> {
        Ok(())
    }

    fn level_filter(&self) -> LevelFilter {
        self.level_filter.load(Ordering::Relaxed)
    }

    fn set_level_filter(&self, level_filter: LevelFilter) {
        self.level_filter.store(level_filter, Ordering::Relaxed);
    }

    fn set_formatter(&self, formatter: Box<dyn Formatter>) {
        *self.formatter.write() = formatter;
    }

    fn set_error_handler(&self, handler: Option<ErrorHandler>) {
        self.error_handler.store(handler, Ordering::Relaxed);
    }
}
