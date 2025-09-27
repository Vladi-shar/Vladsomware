use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering}, Arc,
    Mutex,
};
use std::time::{Duration, Instant};

pub struct Progress {
    total: AtomicU64,
    done: AtomicU64,
    started: AtomicBool,
    finished: AtomicBool,
    // store a clone of the egui context instead of Weak<...>
    ui_ctx: Mutex<Option<egui::Context>>,
    last_ui_nudge: Mutex<Instant>,
}

#[derive(Clone, Copy)]
pub struct ProgressSnapshot {
    pub total: u64,
    pub done: u64,
    pub finished: bool,
}

impl Progress {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            total: AtomicU64::new(0),
            done: AtomicU64::new(0),
            started: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            ui_ctx: Mutex::new(None),
            last_ui_nudge: Mutex::new(Instant::now()),
        })
    }

    #[inline]
    pub fn set_total(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
        self.started.store(true, Ordering::Release);
        self.nudge_ui();
    }

    #[inline]
    pub fn add_done(&self, delta: u64) {
        self.done.fetch_add(delta, Ordering::Relaxed);
        self.nudge_ui();
    }

    #[inline]
    pub fn mark_finished(&self) {
        self.finished.store(true, Ordering::Release);
        self.nudge_ui();
    }

    pub fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            total: self.total.load(Ordering::Relaxed),
            done: self.done.load(Ordering::Relaxed),
            finished: self.finished.load(Ordering::Acquire),
        }
    }

    fn nudge_ui(&self) {
        // throttle to ~30 FPS
        let mut last = self.last_ui_nudge.lock().unwrap();
        if last.elapsed() < Duration::from_millis(33) {
            return;
        }
        *last = Instant::now();

        if let Some(ctx) = self.ui_ctx.lock().unwrap().as_ref() {
            ctx.request_repaint(); // safe from any thread
        }
    }
}
