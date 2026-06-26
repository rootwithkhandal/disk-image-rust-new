use std::fs::{create_dir_all, write};
use std::path::Path;

fn main() {
    // Dynamically generate placeholder icon assets if they are missing
    // to satisfy the Tauri resource compiler on Windows/Mac/Linux.
    let icons_dir = Path::new("icons");
    if !icons_dir.exists() {
        let _ = create_dir_all(icons_dir);
    }

    let png_bytes = &[
        137, 80, 78, 71, 13, 10, 26, 10, // PNG Signature
        0, 0, 0, 13, 73, 72, 68, 82,     // IHDR Length & Type
        0, 0, 0, 1, 0, 0, 0, 1,          // Width & Height (1x1)
        8, 6, 0, 0, 0,                   // Bit Depth (8), Color Type (6: RGBA), Compression (0), Filter (0), Interlace (0)
        31, 21, 196, 137,                // IHDR CRC
        0, 0, 0, 10, 73, 68, 65, 84,     // IDAT Length & Type
        120, 156, 99, 0, 1, 0, 0, 5, 0, 1, // IDAT Data (zlib stream of 5 bytes of 0)
        13, 10, 45, 180,                 // IDAT CRC
        0, 0, 0, 0, 73, 69, 78, 68,      // IEND Length & Type
        174, 66, 96, 130                 // IEND CRC
    ];

    // ICO file wrapping the 1x1 PNG
    let mut ico_bytes = vec![
        0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 32, 0, 67, 0, 0, 0, 22, 0, 0, 0,
    ];
    ico_bytes.extend_from_slice(png_bytes);

    // ICNS file header
    let icns_bytes = &[105, 99, 110, 115, 0, 0, 0, 8];

    let _ = write(icons_dir.join("32x32.png"), png_bytes);
    let _ = write(icons_dir.join("128x128.png"), png_bytes);
    let _ = write(icons_dir.join("128x128@2x.png"), png_bytes);
    let _ = write(icons_dir.join("icon.ico"), &ico_bytes);
    let _ = write(icons_dir.join("icon.icns"), icns_bytes);

    tauri_build::build();
}
