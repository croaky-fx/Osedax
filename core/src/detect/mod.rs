//! Image detection: classify an image file's head bytes into an `ImageKind`
//! and populate an `ImgReport`, without ever touching a real device.
//!
//! Three layers, mirroring `docs/porting/04-iso-detection-tree.md`:
//!   - [`magic`]      — total byte-signature probes (offsets, magic values).
//!   - [`img_report`] — the Rufus `img_report` model + its `IS_*`/`HAS_*` predicates.
//!   - [`tree`]       — the ordered decision tree that turns probes into a verdict.
//!
//! The head buffer the tree needs is ~40 KiB (enough to reach the El Torito
//! BRVD at 0x8800 plus a margin); callers read that prefix and hand it here.

pub mod img_report;
pub mod magic;
pub mod tree;

pub use img_report::ImgReport;
pub use magic::Compression;
pub use tree::{
    BsdFlavor, BsdWarning, ImageKind, IsoHybrid, Verdict, bsd_warning, classify, inspect,
};

/// Bytes of the image head the detection tree needs. Covers every probe window
/// (the furthest is the El Torito BRVD at 0x8800 = 34816); 64 KiB gives margin
/// and aligns to a common block size.
pub const DETECTION_HEAD_LEN: usize = 64 * 1024;
