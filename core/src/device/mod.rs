//! Device model and write-safety checks.
//!
//! This module is split so the *safety* logic (which drive may be written) is a
//! pure function of a [`Device`] value and can be exhaustively unit-tested
//! without ever enumerating or touching real hardware. Actual enumeration
//! (sysfs on Linux, SetupAPI on Windows, geom/sysctl on BSD) is a separate,
//! platform-gated layer that constructs `Device` values to feed in here.
//!
//! See `docs/porting/02-core-architecture.md` §3 and §5-6.

mod enumerate;
mod safety;

pub use enumerate::{EnumerateError, enumerate};
pub use safety::{WriteRefusal, check_write_allowed, is_source_drive};

use std::path::PathBuf;

/// A mount point of a device or one of its partitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountPoint {
    pub path: PathBuf,
}

/// A platform-neutral view of a whole disk, produced by the per-OS enumeration
/// layer and consumed by the safety checks and the write pipeline.
///
/// Osedax only ever offers *whole disks* as targets (`/dev/sdb`, never
/// `/dev/sdb1`) — writing an image includes its own partition table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The whole-disk node to open for writing (e.g. `/dev/sdb`, `\\.\PhysicalDrive2`).
    pub path: PathBuf,
    /// Human-readable model/description, for the picker UI.
    pub model: Option<String>,
    /// Total size in bytes.
    pub size: u64,
    /// Logical sector size (bytes). Never assume 512 — query the real value.
    pub logical_block_size: u32,
    /// Physical sector size (bytes); may exceed logical on 512e/4Kn drives.
    pub physical_block_size: u32,
    /// Attached via USB (detected by bus type, not the unreliable removable flag).
    pub is_usb: bool,
    /// The OS/kernel reports this as removable media.
    pub is_removable: bool,
    /// Best-effort "this is a system/OS disk" flag from the enumeration layer.
    /// Advisory but strong: refused by default, overridable only with force.
    pub is_system: bool,
    /// The device is read-only / write-protected.
    pub is_read_only: bool,
    /// Mount points of the device and its partitions (used by the source-drive check).
    pub mountpoints: Vec<MountPoint>,
}

impl Device {
    /// Whether this device is a sensible default to *show* in the picker: a
    /// removable USB disk that isn't the system disk. (Non-removable disks can
    /// still be offered behind an explicit "unsafe" toggle, as Rufus does.)
    pub fn is_safe_default_target(&self) -> bool {
        self.is_usb && self.is_removable && !self.is_system && !self.is_read_only
    }
}
