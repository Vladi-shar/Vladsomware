
use eframe::{
    egui::{self, CentralPanel},
    run_native,
    App,
};
use egui::{
    Button, Color32, ColorImage, Context, FontId, IconData, Image, InnerResponse, RichText,
    TextStyle, TextureHandle, TextureOptions, Ui, ViewportBuilder,
};

struct VladsomwareApp {
    directory: String,
    recursive: bool,
    multi_threaded: bool,

    encrypt_tex: TextureHandle,
    decrypt_tex: TextureHandle,
}

fn icon_texture_from_icon_data(ctx: &Context, id: &str, icon: &IconData) -> TextureHandle {
    let color =
        ColorImage::from_rgba_unmultiplied([icon.width as usize, icon.height as usize], &icon.rgba);
    ctx.load_texture(id, color, TextureOptions::LINEAR)
}

impl VladsomwareApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let encrypt_icon = load_icon_safe(include_bytes!("../rsrc/lock.ico")).unwrap_or_default();
        let decrypt_icon = load_icon_safe(include_bytes!("../rsrc/unlock.ico")).unwrap_or_default();

        Self {
            directory: String::new(),
            recursive: false,
            multi_threaded: false,
            encrypt_tex: icon_texture_from_icon_data(
                &cc.egui_ctx,
                "encrypt_icon_tex",
                &encrypt_icon,
            ),
            decrypt_tex: icon_texture_from_icon_data(
                &cc.egui_ctx,
                "decrypt_icon_tex",
                &decrypt_icon,
            ),
        }
    }
}
fn load_icon_safe(icon_bytes: &[u8]) -> Option<IconData> {
    let image = image::load_from_memory(icon_bytes).ok()?.into_rgba8();
    let (width, height) = image.dimensions();
    let rgba = image.into_raw();

    Some(IconData {
        rgba,
        width,
        height,
    })
}

fn set_style(ctx: &Context) {
    let mut style = (*ctx.style()).clone();
    style.text_styles = [
        (TextStyle::Heading, FontId::proportional(24.0)),
        (TextStyle::Body, FontId::proportional(18.0)),
        (TextStyle::Monospace, FontId::monospace(18.0)),
        (TextStyle::Button, FontId::proportional(18.0)),
        (TextStyle::Small, FontId::proportional(14.0)),
    ]
    .into();
    ctx.set_style(style);

    if !ctx.style().visuals.dark_mode {
        ctx.set_visuals(egui::Visuals::dark());
    }
}

fn render_dir_selector(
    ui: &mut egui::Ui,
    modified_path: &mut String,
    hover_text: &str,
) -> InnerResponse<()> {
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            ui.add_space(10.0);
            ui.label("Directory to encrypt");
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.add_space(10.0);
            ui.add(egui::TextEdit::singleline(modified_path).desired_width(250.0))
                .on_hover_text(hover_text);
            if ui.button("Browse...").on_hover_text(hover_text).clicked() {
            }
            ui.add_space(10.0);
        });
        ui.add_space(10.0);
    })
}
fn render_encryption_key_handler(_app: &mut VladsomwareApp, ui: &mut Ui) -> InnerResponse<()> {
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            ui.add_space(10.0);
            ui.label("Encryption Key");
        });
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.add_space(10.0);
            if ui
                .button("Load")
                .on_hover_text("Load key to use for encryption\\decryption")
                .clicked()
            {
            };
            ui.add_space(10.0);
            ui.label("Or");
            ui.add_space(10.0);
            if ui
                .button("Generate & Save")
                .on_hover_text("Generate a key to use and save it")
                .clicked()
            {
            }
        });
        ui.add_space(10.0);
    })
}

fn render_encryption_options(app: &mut VladsomwareApp, ui: &mut Ui) -> InnerResponse<()> {
    ui.horizontal(|ui| {
        ui.add_space(10.0);
        ui.vertical(|ui| {
            ui.add_space(10.0);
            ui.checkbox(&mut app.recursive, "Recursive")
                .on_hover_text("Recursively Encrypt\\Decrypt all sub folders");
            ui.checkbox(&mut app.multi_threaded, "Multi-Threaded")
                .on_hover_text("Encrypt\\Decrypt using multiple threads");
            ui.add_space(10.0);
        });
    })
}

fn render_big_button(
    app: &mut VladsomwareApp,
    ui: &mut Ui,
    button_text: &str,
    hover_text: &str,
    encryption: bool,
    button_color: impl Into<Color32>,
) -> InnerResponse<()> {
    let color: Color32 = button_color.into(); // copyable type
    ui.horizontal(|ui| {
        ui.add_space(20.0);
        if ui
            .add_sized(
                [340.0, 40.0],
                Button::image_and_text(
                    Image::new(if encryption {
                        &app.encrypt_tex
                    } else {
                        &app.decrypt_tex
                    })
                    .max_width(25.0),
                    RichText::new(button_text).color(Color32::from_rgb(255, 255, 255)),
                )
                .fill(color),
            )
            .on_hover_text(hover_text)
            .clicked()
        {};
        ui.add_space(20.0);
    })
}

fn render_encrypt_button(app: &mut VladsomwareApp, ui: &mut Ui) -> InnerResponse<()> {
    render_big_button(
        app,
        ui,
        "Encrypt",
        "Encrypt the files in the directory",
        true,
        Color32::from_rgb(188, 40, 46),
    )
}

fn render_decrypt_button(app: &mut VladsomwareApp, ui: &mut Ui) -> InnerResponse<()> {
    render_big_button(
        app,
        ui,
        "Decrypt",
        "Decrypt files in the directory",
        false,
        Color32::from_rgb(155, 176, 179),
    )
}

impl App for VladsomwareApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        set_style(ctx);
        CentralPanel::default().show(ctx, |ui| {
            ui.vertical(|ui| {
                render_dir_selector(
                    ui,
                    &mut self.directory,
                    "Path to directory to encrypt\\decrypt",
                );
                ui.separator();
                render_encryption_key_handler(self, ui);
                ui.separator();
                render_encryption_options(self, ui);
                ui.separator();
                ui.vertical(|ui| {
                    ui.add_space(5.0);
                    render_encrypt_button(self, ui);
                    ui.add_space(5.0);
                    render_decrypt_button(self, ui);
                });
            });
        });
    }
}

fn main() {
    let mut viewport_builder = ViewportBuilder::default()
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
