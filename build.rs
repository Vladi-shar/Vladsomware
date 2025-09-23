use std::path::Path;

fn create_icon_from_png(png_path: &str, ico_out_path: &str) {
    // Create a new, empty icon collection:
    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);
    // Read a PNG file from disk and add it to the collection:

    let file = std::fs::File::open(png_path).unwrap();
    let image = ico::IconImage::read_png(file).unwrap();
    icon_dir.add_entry(ico::IconDirEntry::encode(&image).unwrap());

    // Finally, write the ICO file to disk:
    let file = std::fs::File::create(ico_out_path).unwrap();
    icon_dir.write(file).unwrap();
}

fn set_resource_info() {

    create_icon_from_png("rsrc/vladsomware.png", "rsrc/vladsomware.ico");
    create_icon_from_png("rsrc/lock.png", "rsrc/lock.ico");
    create_icon_from_png("rsrc/unlock.png", "rsrc/unlock.ico");

    let mut res = winres::WindowsResource::new();
    let ico_rel = Path::new("rsrc").join("vladsomware.ico");
    let ico_abs = dunce::canonicalize(&ico_rel).expect("canonicalize failed");

    res.set_icon(ico_abs.to_str().expect("failed to convert to str"));
    res.set("ProductName", "vladsomware");
    res.set("OriginalFilename", "vladsomware.exe");
    res.set("CompanyName", "vladsomware");
    res.set("FileVersion", "0.0.1");

    res.compile().expect("failed to compile VLadsomware");
}

fn main() {
    println!("cargo:rerun-if-changed=rsrc/vladsomware.png");
    set_resource_info();
}