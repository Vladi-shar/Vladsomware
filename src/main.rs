
use eframe::{
    egui::{self},
    run_native,
    App,
};

struct VladsomwareApp {
}
impl VladsomwareApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self{}
    }
}
fn load_icon_safe(icon_bytes: &[u8]) -> Option<egui::IconData> {
    let image = image::load_from_memory(icon_bytes).ok()?.into_rgba8();
    let (width, height) = image.dimensions();
    let rgba = image.into_raw();

    Some(egui::IconData {
        rgba,
        width,
        height,
    })
}

impl App for VladsomwareApp {
    fn update(&mut self, _ctx: &egui::Context, _frame: &mut eframe::Frame) {}
}

fn main() {
    let mut viewport_builder = egui::ViewportBuilder::default()
        .with_inner_size([400.0, 530.0])
        .with_resizable(false);
    if let Some(icon) = load_icon_safe(include_bytes!("../rsrc/vladsomware.png")) {
        viewport_builder = viewport_builder.with_icon(icon);
    }
    let win_options = eframe::NativeOptions {
        viewport: viewport_builder,
        ..eframe::NativeOptions::default()
    };

    let _ = run_native(
        "Vladsomware",
        win_options,
        Box::new(|_ctx| Ok(Box::new(VladsomwareApp::new(_ctx)))),
    );
}
