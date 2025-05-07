// No imports needed

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create icons directory if it doesn't exist
    std::fs::create_dir_all("icons")?;

    // Generate PNG icons with RGBA format
    generate_rgba_icon("icons/32x32.png", 32)?;
    generate_rgba_icon("icons/128x128.png", 128)?;
    generate_rgba_icon("icons/128x128@2x.png", 256)?;

    println!("Icons generated successfully!");
    println!("Note: For production use, you should replace these with professionally designed icons.");
    println!("For .ico and .icns files, you'll need to convert the PNG files using specialized tools.");

    Ok(())
}

fn generate_rgba_icon(path: &str, size: u32) -> Result<(), Box<dyn std::error::Error>> {
    // Create a new image buffer with the specified size (RGBA format)
    let mut imgbuf = image::RgbaImage::new(size, size);

    // Define colors for gradient
    let purple = [138, 43, 226, 255]; // BlueViolet
    let blue = [30, 144, 255, 255];   // DodgerBlue

    // Draw a filled circle with gradient
    let center = size / 2;
    let radius = size / 2 - 2;

    for x in 0..size {
        for y in 0..size {
            let dx = x as i32 - center as i32;
            let dy = y as i32 - center as i32;
            let distance = ((dx * dx + dy * dy) as f32).sqrt();

            if distance <= radius as f32 {
                // Create a gradient based on position
                let angle = (dy as f32).atan2(dx as f32) + std::f32::consts::PI;
                let normalized_angle = angle / (2.0 * std::f32::consts::PI);

                // Interpolate between colors
                let r = (purple[0] as f32 * (1.0 - normalized_angle) + blue[0] as f32 * normalized_angle) as u8;
                let g = (purple[1] as f32 * (1.0 - normalized_angle) + blue[1] as f32 * normalized_angle) as u8;
                let b = (purple[2] as f32 * (1.0 - normalized_angle) + blue[2] as f32 * normalized_angle) as u8;

                // Add a subtle 3D effect
                let edge_factor = (radius as f32 - distance) / radius as f32;
                let edge_brightness = 0.7 + 0.3 * edge_factor;

                let r = (r as f32 * edge_brightness) as u8;
                let g = (g as f32 * edge_brightness) as u8;
                let b = (b as f32 * edge_brightness) as u8;

                imgbuf.put_pixel(x, y, image::Rgba([r, g, b, 255]));
            } else {
                // Set transparent background for pixels outside the circle
                imgbuf.put_pixel(x, y, image::Rgba([0, 0, 0, 0]));
            }
        }
    }

    // Save the image as RGBA PNG
    imgbuf.save(path)?;

    Ok(())
}
