use anyhow::Result;
use osedax_core::device;

fn main() -> Result<()> {
    let cmd = std::env::args().nth(1);
    match cmd.as_deref() {
        Some("list") => list_devices(),
        Some("--version") | Some("-V") => {
            println!("osedax {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            eprintln!(
                "osedax {}\n\nUsage: osedax <command>\n  list    list detected disks",
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
    }
}

/// List detected whole disks. Read-only: this never writes to any device.
fn list_devices() -> Result<()> {
    let devices = device::enumerate()?;
    if devices.is_empty() {
        println!("No disks detected.");
        return Ok(());
    }
    for d in &devices {
        let model = d.model.as_deref().unwrap_or("(unknown)");
        let flags = [
            (d.is_usb, "usb"),
            (d.is_removable, "removable"),
            (d.is_system, "system"),
            (d.is_read_only, "ro"),
        ]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(",");

        println!(
            "{:<16} {:>8}  {:<24} [{}]{}",
            d.path.display(),
            human_size(d.size),
            model,
            flags,
            if d.is_safe_default_target() {
                "  <- default"
            } else {
                ""
            },
        );
        for m in &d.mountpoints {
            println!("                 mounted at {}", m.path.display());
        }
    }
    Ok(())
}

/// Format a byte count as a short human-readable size.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
