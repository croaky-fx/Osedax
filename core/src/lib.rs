//! osedax-core — the platform-neutral flashing engine.
//!
//! All image detection, device enumeration, safety checks, and the
//! write/verify pipeline live here. Frontends (`osedax-cli`, `osedax-gui`)
//! depend on this crate and only render progress and collect user choices.
//!
//! See `docs/porting/` for the source-level specs this implementation follows.

pub mod detect;
pub mod device;

pub use detect::{ImageKind, ImgReport};
pub use device::{Device, WriteRefusal, check_write_allowed};
