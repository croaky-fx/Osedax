//! Linux device enumeration via pure sysfs — no external commands, no udev
//! dependency, read-only.
//!
//! We read `/sys/class/block`, keep only whole disks, drop pseudo-devices, and
//! populate a [`Device`] per disk from the sysfs attribute files. Mount points
//! come from `/proc/mounts`. See `docs/porting/02-core-architecture.md` §6 and
//! caligula's `util/device.rs`, whose sysfs approach this follows.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::EnumerateError;
use crate::device::{Device, MountPoint};

const SYS_BLOCK: &str = "/sys/class/block";

/// Enumerate whole disks on Linux.
pub fn enumerate() -> Result<Vec<Device>, EnumerateError> {
    let mounts = read_mounts();
    let mut devices = Vec::new();

    for entry in fs::read_dir(SYS_BLOCK)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();

        if !is_whole_disk(&name) {
            continue;
        }
        if is_pseudo_device(&name) {
            continue;
        }
        if let Some(dev) = build_device(&name, &mounts) {
            devices.push(dev);
        }
    }

    devices.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(devices)
}

/// A `/sys/class/block` entry is a whole disk (not a partition) if it has no
/// `partition` attribute file. Partitions like `sda1` carry one; disks don't.
fn is_whole_disk(name: &str) -> bool {
    !Path::new(&format!("{SYS_BLOCK}/{name}/partition")).exists()
}

/// Drop kernel pseudo-block-devices that are never flash targets.
fn is_pseudo_device(name: &str) -> bool {
    name.starts_with("loop")
        || name.starts_with("sr") // optical
        || name.starts_with("ram")
        || name.starts_with("dm-") // device-mapper
        || name.starts_with("md") // software RAID
        || name.starts_with("zram")
}

/// Build a [`Device`] from a disk's sysfs attributes. Returns `None` if the
/// essential attributes (notably size) can't be read.
fn build_device(name: &str, mounts: &[(String, PathBuf)]) -> Option<Device> {
    let base = format!("{SYS_BLOCK}/{name}");

    // size is reported in 512-byte sectors regardless of the real sector size.
    let sectors: u64 = read_attr(&base, "size")?.trim().parse().ok()?;
    let size = sectors * 512;

    let logical_block_size = read_attr(&base, "queue/logical_block_size")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(512);
    let physical_block_size = read_attr(&base, "queue/physical_block_size")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(logical_block_size);

    let removable = read_attr(&base, "removable")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    let read_only = read_attr(&base, "ro")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);
    let model = read_attr(&base, "device/model").map(|s| s.trim().to_string());

    let is_usb = detect_usb(&base);
    let is_virtual = detect_virtual(&base);
    // A fixed, non-virtual disk is treated as a system disk (Etcher's rule).
    let is_system = !removable && !is_virtual;

    let dev_path = PathBuf::from(format!("/dev/{name}"));
    let mountpoints = mounts_for(name, mounts);

    Some(Device {
        path: dev_path,
        model,
        size,
        logical_block_size,
        physical_block_size,
        is_usb,
        is_removable: removable,
        is_system,
        is_read_only: read_only,
        mountpoints,
    })
}

/// Detect USB attachment by the **bus type**, not the removable flag (which
/// lies for many USB SSDs).
///
/// We must fully resolve the `<dev>/device` symlink, not read a single hop:
/// the one-hop target is only the SCSI address (`../../../H:C:T:L`) for both
/// SATA and USB disks. The `usbN` host-controller segment appears only in the
/// canonicalized `/sys/devices/...` chain, so we `canonicalize` (== `readlink -f`)
/// before scanning path segments.
fn detect_usb(base: &str) -> bool {
    let Ok(target) = fs::canonicalize(format!("{base}/device")) else {
        return false;
    };
    // The canonical chain contains a USB root-hub segment (`usb1`, `usb2`, ...)
    // for USB-attached disks. There is no `usbcore`-style segment in the
    // /sys/devices path, so matching a `usb`-prefixed segment is precise.
    target.components().any(|c| {
        let seg = c.as_os_str().to_string_lossy();
        seg == "usb" || (seg.starts_with("usb") && seg[3..].chars().all(|ch| ch.is_ascii_digit()))
    })
}

/// Detect virtual/non-physical devices.
///
/// The rule is "no backing physical `device` symlink" — matching balena
/// drivelist's `isVirtual` (derived from the subsystem, not the name). We do
/// NOT special-case `vd*` (virtio): a VM's system disk is typically
/// `/dev/vda`, and marking it virtual would make `is_system` false and defeat
/// the system-disk write guard. A virtio disk still has a `device` symlink
/// (into the `virtio` subsystem), so it is correctly treated as non-virtual
/// and thus a system disk when fixed.
fn detect_virtual(base: &str) -> bool {
    !Path::new(&format!("{base}/device")).exists()
}

/// Read a sysfs attribute file, trimming nothing (caller trims).
fn read_attr(base: &str, attr: &str) -> Option<String> {
    fs::read_to_string(format!("{base}/{attr}")).ok()
}

/// Parse `/proc/mounts` into (device-node, mount-point) pairs. Best-effort:
/// a missing or unreadable file yields no mounts rather than an error, since
/// mount info only strengthens the source-on-target safety check.
fn read_mounts() -> Vec<(String, PathBuf)> {
    let Ok(content) = fs::read_to_string("/proc/mounts") else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let dev = cols.next()?;
            let mnt = cols.next()?;
            // Only real block-device mounts (skip proc, sysfs, tmpfs, ...).
            let dev = dev.strip_prefix("/dev/")?;
            Some((dev.to_string(), unescape_mount(mnt)))
        })
        .collect()
}

/// Mount points belonging to a disk: any mount whose device node is the disk
/// itself or one of its partitions (`sda`, `sda1`, `nvme0n1p2`, ...).
fn mounts_for(name: &str, mounts: &[(String, PathBuf)]) -> Vec<MountPoint> {
    mounts
        .iter()
        .filter(|(dev, _)| dev == name || is_partition_of(name, dev))
        .map(|(_, path)| MountPoint { path: path.clone() })
        .collect()
}

/// True if `part` names a partition of whole-disk `disk`.
///
/// Two device naming schemes need different handling:
///   - `sdX`  → partitions append digits directly: `sda` → `sda1`.
///   - `nvmeXnY` (and `mmcblkX`, `loopX`) → the disk name already ends in a
///     digit, so partitions use a mandatory `p` separator: `nvme0n1` → `nvme0n1p1`.
///     Here a digits-only suffix without `p` is a *different namespace*
///     (`nvme0n1` vs `nvme0n11`), NOT a partition — mis-attributing it would
///     wrongly assign that namespace's mounts to this disk.
fn is_partition_of(disk: &str, part: &str) -> bool {
    let Some(rest) = part.strip_prefix(disk) else {
        return false;
    };
    // If the disk name ends in a digit, a partition MUST be `p<digits>`.
    if disk.ends_with(|c: char| c.is_ascii_digit()) {
        return matches!(rest.strip_prefix('p'), Some(d) if !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
    }
    // Otherwise (sdX-style) a partition is just trailing digits.
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

/// Decode a `/proc/mounts` field into a filesystem path.
///
/// `/proc/mounts` escapes space, tab, newline, and backslash as octal `\NNN`.
/// We decode at the **byte** level and build the path via `OsStr::from_bytes`,
/// because Linux paths are arbitrary byte sequences: a mount path may hold
/// non-ASCII UTF-8 (an accented or Arabic volume label), and reinterpreting a
/// raw byte as a `char` would corrupt those multi-byte sequences — which would
/// in turn weaken the source-on-target safety check that compares this path.
/// Parsing octal from the byte slice (not a `&str` sub-slice) also removes any
/// char-boundary panic risk.
fn unescape_mount(s: &str) -> PathBuf {
    let bytes = s.as_bytes();
    if !bytes.contains(&b'\\') {
        return PathBuf::from(s);
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && let Some(code) = parse_octal_byte(&bytes[i + 1..i + 4])
        {
            out.push(code);
            i += 4;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    PathBuf::from(std::ffi::OsStr::from_bytes(&out).to_owned())
}

/// Parse exactly three octal ASCII digits (`0..=7`) into a byte, or `None`.
fn parse_octal_byte(triple: &[u8]) -> Option<u8> {
    if triple.len() != 3 {
        return None;
    }
    let mut val: u16 = 0;
    for &b in triple {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        val = val * 8 + u16::from(b - b'0');
    }
    u8::try_from(val).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whole_disk_vs_partition_naming() {
        // Pure string logic: partition suffixes on both naming schemes.
        assert!(is_partition_of("sda", "sda1"));
        assert!(is_partition_of("sda", "sda15"));
        assert!(!is_partition_of("sda", "sda")); // the disk itself
        assert!(!is_partition_of("sda", "sdb1")); // different disk
        assert!(is_partition_of("nvme0n1", "nvme0n1p1"));
        assert!(!is_partition_of("nvme0n1", "nvme0n1")); // the disk itself
        assert!(!is_partition_of("nvme0n1", "nvme0n1x")); // not a partition suffix
        // NVMe requires the `p` separator: nvme0n11 is a DIFFERENT namespace,
        // not partition 1 of nvme0n1. Mis-attributing it would assign that
        // namespace's mounts to the wrong disk.
        assert!(!is_partition_of("nvme0n1", "nvme0n11"));
        assert!(!is_partition_of("nvme0n1", "nvme0n12"));
        assert!(is_partition_of("mmcblk0", "mmcblk0p2"));
        assert!(!is_partition_of("mmcblk0", "mmcblk01"));
    }

    #[test]
    fn pseudo_devices_are_filtered() {
        for n in ["loop0", "sr0", "ram3", "dm-0", "md0", "zram0"] {
            assert!(is_pseudo_device(n), "{n} should be pseudo");
        }
        for n in ["sda", "nvme0n1", "vdb"] {
            assert!(!is_pseudo_device(n), "{n} should not be pseudo");
        }
    }

    #[test]
    fn unescapes_octal_mount_paths() {
        // /proc/mounts encodes a space as \040.
        assert_eq!(
            unescape_mount("/mnt/my\\040disk"),
            Path::new("/mnt/my disk")
        );
        assert_eq!(unescape_mount("/mnt/plain"), Path::new("/mnt/plain"));
    }

    #[test]
    fn unescape_preserves_non_ascii_utf8() {
        // A mount path with BOTH an escaped space and non-ASCII UTF-8 must not
        // corrupt the multi-byte characters (byte-level decode, not `as char`).
        // "/media/José photos" with the space escaped as \040.
        assert_eq!(
            unescape_mount("/media/José\\040photos"),
            Path::new("/media/José photos"),
        );
        // Arabic label, escaped space.
        assert_eq!(
            unescape_mount("/mnt/قرص\\040صلب"),
            Path::new("/mnt/قرص صلب"),
        );
    }

    #[test]
    fn octal_byte_parsing_is_strict() {
        assert_eq!(parse_octal_byte(b"040"), Some(0x20)); // space
        assert_eq!(parse_octal_byte(b"377"), Some(0xFF)); // max byte
        assert_eq!(parse_octal_byte(b"400"), None); // 256, out of u8 range
        assert_eq!(parse_octal_byte(b"08a"), None); // '8' not octal
        assert_eq!(parse_octal_byte(b"04"), None); // too short
    }

    #[test]
    fn mounts_for_matches_disk_and_partitions_only() {
        let mounts = vec![
            ("sda1".to_string(), PathBuf::from("/")),
            ("sda2".to_string(), PathBuf::from("/home")),
            ("sdb1".to_string(), PathBuf::from("/mnt/usb")),
        ];
        let got = mounts_for("sda", &mounts);
        assert_eq!(got.len(), 2);
        assert!(got.iter().any(|m| m.path == Path::new("/")));
        assert!(got.iter().any(|m| m.path == Path::new("/home")));
    }
}
