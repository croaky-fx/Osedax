//! The write-safety guard: decide whether writing an image to a device is
//! allowed, and if not, exactly why.
//!
//! Reconstructed from balenaEtcher's two-layer model (the constraints live in
//! the Etcher app, not etcher-sdk — see `docs/porting/02-core-architecture.md`
//! §5). The checks run in a deliberate order so the most dangerous, most
//! certain mistakes are reported first.

use std::path::Path;

use super::Device;

/// Why a write was refused. Ordered roughly most-dangerous first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteRefusal {
    /// The device is write-protected.
    ReadOnly,
    /// The image being written physically lives on the target device. Writing
    /// would destroy the source mid-read. **Never overridable** — always a bug.
    SourceOnTarget,
    /// The device is smaller than the image.
    TooSmall { need: u64, have: u64 },
    /// The device looks like a system/OS disk. Overridable only with explicit force.
    SystemDrive,
}

/// Decide whether `image` (of `image_size` bytes) may be written to `device`.
///
/// Order matters:
/// 1. `ReadOnly` — a write can't even begin.
/// 2. `SourceOnTarget` — the hardest, most certain refusal; checked before the
///    size and system checks so it can never be masked by them, and it ignores
///    `force` entirely.
/// 3. `TooSmall` — a physical impossibility.
/// 4. `SystemDrive` — the one soft refusal: overridable via `force`.
///
/// `force` corresponds to an explicit user "I know what I'm doing" flag and
/// relaxes *only* the system-drive check.
pub fn check_write_allowed(
    device: &Device,
    image_path: &Path,
    image_size: u64,
    force: bool,
) -> Result<(), WriteRefusal> {
    if device.is_read_only {
        return Err(WriteRefusal::ReadOnly);
    }
    if is_source_drive(device, image_path) {
        return Err(WriteRefusal::SourceOnTarget);
    }
    if device.size < image_size {
        return Err(WriteRefusal::TooSmall {
            need: image_size,
            have: device.size,
        });
    }
    if device.is_system && !force {
        return Err(WriteRefusal::SystemDrive);
    }
    Ok(())
}

/// True if `image_path` resides on `device` (under one of its mount points).
///
/// The image path is canonicalized so `..`/symlinks can't sneak the source
/// onto the target. If canonicalization fails (e.g. the path doesn't exist),
/// we fall back to the path as-given rather than silently passing the check.
/// Comparison is by whole path components (`Path::starts_with`), so a mount at
/// `/run/media/me` does not spuriously match `/run/media/meSTICK`.
///
/// A bare root mount (`/`) is deliberately ignored here: it is a prefix of
/// every absolute path, so honoring it would flag *any* image as living on the
/// root device and make the documented `force` override of a root/system disk
/// unreachable. The root/system disk is already protected by the `is_system`
/// check in [`check_write_allowed`]; source-on-target exists for the case where
/// a *removable* target happens to host the image, whose mounts are specific
/// (`/run/media/...`, `E:\...`), never bare `/`.
///
/// TODO(enumeration): this path-prefix heuristic is provisional. Once the
/// per-OS enumeration layer supplies device identity (Unix `st_dev`, Windows
/// volume→PhysicalDrive mapping), compare identities instead. That also fixes
/// case-insensitive filesystems (Windows/macOS), where a component-wise,
/// case-sensitive prefix match can miss a genuine source-on-target.
pub fn is_source_drive(device: &Device, image_path: &Path) -> bool {
    let image = std::fs::canonicalize(image_path).unwrap_or_else(|_| image_path.to_path_buf());
    device.mountpoints.iter().any(|mp| {
        // A bare root mount can't distinguish which device holds the file.
        if mp.path == Path::new("/") {
            return false;
        }
        // Canonicalize the mount point too, for a fair prefix comparison.
        let mount = std::fs::canonicalize(&mp.path).unwrap_or_else(|_| mp.path.clone());
        image.starts_with(&mount)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MountPoint;
    use std::path::PathBuf;

    /// A plain, writable, non-system USB stick with no mounted partitions.
    fn usb_stick(size: u64) -> Device {
        Device {
            path: PathBuf::from("/dev/sdb"),
            model: Some("Generic USB".into()),
            size,
            logical_block_size: 512,
            physical_block_size: 512,
            is_usb: true,
            is_removable: true,
            is_system: false,
            is_read_only: false,
            mountpoints: vec![],
        }
    }

    const GB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn allows_a_plain_large_enough_usb_stick() {
        let dev = usb_stick(16 * GB);
        assert_eq!(
            check_write_allowed(&dev, Path::new("/tmp/x.iso"), 4 * GB, false),
            Ok(())
        );
    }

    #[test]
    fn refuses_read_only_device() {
        let mut dev = usb_stick(16 * GB);
        dev.is_read_only = true;
        assert_eq!(
            check_write_allowed(&dev, Path::new("/tmp/x.iso"), 4 * GB, false),
            Err(WriteRefusal::ReadOnly)
        );
    }

    #[test]
    fn refuses_device_smaller_than_image() {
        let dev = usb_stick(2 * GB);
        assert_eq!(
            check_write_allowed(&dev, Path::new("/tmp/x.iso"), 4 * GB, false),
            Err(WriteRefusal::TooSmall {
                need: 4 * GB,
                have: 2 * GB,
            })
        );
    }

    #[test]
    fn refuses_system_drive_but_force_overrides() {
        let mut dev = usb_stick(16 * GB);
        dev.is_system = true;
        assert_eq!(
            check_write_allowed(&dev, Path::new("/tmp/x.iso"), 4 * GB, false),
            Err(WriteRefusal::SystemDrive)
        );
        // Explicit force relaxes only the system-drive check.
        assert_eq!(
            check_write_allowed(&dev, Path::new("/tmp/x.iso"), 4 * GB, true),
            Ok(())
        );
    }

    #[test]
    fn source_on_target_is_refused_even_with_force() {
        // Image lives under a mount point of the target device.
        let mut dev = usb_stick(16 * GB);
        dev.mountpoints = vec![MountPoint {
            path: PathBuf::from("/run/media/me/STICK"),
        }];
        let image = Path::new("/run/media/me/STICK/images/x.iso");
        assert_eq!(
            check_write_allowed(&dev, image, GB, false),
            Err(WriteRefusal::SourceOnTarget)
        );
        // Force must NOT override a source-on-target refusal.
        assert_eq!(
            check_write_allowed(&dev, image, GB, true),
            Err(WriteRefusal::SourceOnTarget)
        );
    }

    #[test]
    fn source_on_target_beats_system_drive_in_ordering() {
        // A device that is BOTH the source drive AND flagged system must report
        // SourceOnTarget (checked first), not SystemDrive. Use a realistic
        // removable mount that actually hosts the image (not bare `/`).
        let mut dev = usb_stick(16 * GB);
        dev.is_system = true;
        dev.mountpoints = vec![MountPoint {
            path: PathBuf::from("/run/media/me/STICK"),
        }];
        let image = Path::new("/run/media/me/STICK/x.iso");
        assert_eq!(
            check_write_allowed(&dev, image, GB, false),
            Err(WriteRefusal::SourceOnTarget)
        );
    }

    #[test]
    fn bare_root_mount_is_not_treated_as_source() {
        // A system disk mounted at `/` must NOT swallow every image path as
        // source-on-target — otherwise force-writing the root disk (with the
        // image safely on a different drive) would be wrongly refused, and the
        // documented `force` override of a system disk would be unreachable.
        let mut dev = usb_stick(16 * GB);
        dev.is_system = true;
        dev.mountpoints = vec![MountPoint {
            path: PathBuf::from("/"),
        }];
        let image = Path::new("/run/media/me/BACKUP/os.iso");
        assert!(!is_source_drive(&dev, image));
        // Without force it's still refused, but for the RIGHT reason...
        assert_eq!(
            check_write_allowed(&dev, image, GB, false),
            Err(WriteRefusal::SystemDrive)
        );
        // ...and force can override the system-drive refusal.
        assert_eq!(check_write_allowed(&dev, image, GB, true), Ok(()));
    }

    #[test]
    fn read_only_beats_everything() {
        // Read-only is checked first: even a too-small, system, source drive
        // reports ReadOnly.
        let mut dev = usb_stick(1); // too small
        dev.is_read_only = true;
        dev.is_system = true;
        dev.mountpoints = vec![MountPoint {
            path: PathBuf::from("/run/media/me/STICK"),
        }];
        assert_eq!(
            check_write_allowed(&dev, Path::new("/run/media/me/STICK/x.iso"), 4 * GB, false),
            Err(WriteRefusal::ReadOnly)
        );
    }

    #[test]
    fn unrelated_mountpoint_is_not_source_drive() {
        let mut dev = usb_stick(16 * GB);
        dev.mountpoints = vec![MountPoint {
            path: PathBuf::from("/run/media/me/OTHER"),
        }];
        // Image is elsewhere entirely.
        assert!(!is_source_drive(&dev, Path::new("/home/me/x.iso")));
        assert_eq!(
            check_write_allowed(&dev, Path::new("/home/me/x.iso"), GB, false),
            Ok(())
        );
    }

    #[test]
    fn safe_default_target_needs_usb_removable_nonsystem_writable() {
        assert!(usb_stick(16 * GB).is_safe_default_target());

        let mut internal = usb_stick(16 * GB);
        internal.is_usb = false;
        internal.is_removable = false;
        internal.is_system = true;
        assert!(!internal.is_safe_default_target());
    }
}
