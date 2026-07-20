use anyhow::Result;

fn main() -> Result<()> {
    println!("lufus {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
