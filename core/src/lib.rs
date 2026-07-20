//! lufus-core — the platform-neutral flashing engine.
//!
//! All image detection, device enumeration, safety checks, and the
//! write/verify pipeline live here. Frontends (`lufus-cli`, `lufus-gui`)
//! depend on this crate and only render progress and collect user choices.
//!
//! See `docs/porting/` for the source-level specs this implementation follows.

pub mod detect;

pub use detect::{ImgReport, ImageKind};
