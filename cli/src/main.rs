use anyhow::Result;

fn main() -> Result<()> {
    println!("osedax {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
