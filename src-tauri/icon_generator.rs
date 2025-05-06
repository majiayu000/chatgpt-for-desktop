use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create icons directory if it doesn't exist
    std::fs::create_dir_all("icons")?;

    // Generate PNG icons
    generate_png_icon("icons/32x32.png", 32)?;
    generate_png_icon("icons/128x128.png", 128)?;
    generate_png_icon("icons/128x128@2x.png", 256)?;

    println!("Icons generated successfully!");
    println!("Note: For production use, you should replace these with professionally designed icons.");
    println!("For .ico and .icns files, you'll need to convert the PNG files using specialized tools.");

    Ok(())
}

fn generate_png_icon(path: &str, size: u32) -> Result<(), Box<dyn std::error::Error>> {
    // Create a new image buffer with the specified size
    let mut imgbuf = image::RgbaImage::new(size, size);

    // Fill the image with a blue color (Gemini-like blue)
    let blue = image::Rgba([66, 133, 244, 255]);

    // Draw a filled circle
    let center = size / 2;
    let radius = size / 2 - 2;

    for x in 0..size {
        for y in 0..size {
            let dx = x as i32 - center as i32;
            let dy = y as i32 - center as i32;
            let distance = ((dx * dx + dy * dy) as f32).sqrt();

            if distance <= radius as f32 {
                imgbuf.put_pixel(x, y, blue);
            }
        }
    }

    // Save the image
    let file = File::create(path)?;
    let w = BufWriter::new(file);
    let encoder = image::codecs::png::PngEncoder::new(w);
    encoder.encode(
        &imgbuf.into_raw(),
        size,
        size,
        image::ColorType::Rgba8,
    )?;

    Ok(())
}
