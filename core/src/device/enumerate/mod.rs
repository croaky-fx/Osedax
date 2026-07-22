//! Cross-platform device enumeration.
//!
//! [`enumerate`] returns the whole disks present on the system as
//! platform-neutral [`Device`] values, which the safety layer and write
//! pipeline consume unchanged. The interface is cross-platform from day one;
//! each OS is implemented behind its own `#[cfg]` arm.
//!
//! Implementation status:
//!   - Linux   — implemented (pure sysfs, read-only).
//!   - BSD     — planned (geom/sysctl); currently returns `Unsupported`.
//!   - Windows — planned (SetupAPI + IOCTL); currently returns `Unsupported`.
//!
//! The unimplemented arms return an explicit [`EnumerateError::Unsupported`]
//! rather than an empty list, so a caller on those platforms gets a clear
//! "not yet" instead of silently seeing zero devices.

use super::Device;

/// Why enumeration failed.
#[derive(Debug, thiserror::Error)]
pub enum EnumerateError {
    /// Enumeration is not yet implemented for the current platform.
    #[error("device enumeration is not yet implemented on this platform ({0})")]
    Unsupported(&'static str),
    /// An I/O error while reading the platform's device tables.
    #[error("device enumeration failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(target_os = "linux")]
mod linux;

/// Enumerate the whole disks present on the system.
///
/// Returns only whole disks (never partitions), with pseudo-devices
/// (loop/optical/ram) filtered out. Callers should still apply the safety
/// checks in [`super::check_write_allowed`] before writing to any result.
pub fn enumerate() -> Result<Vec<Device>, EnumerateError> {
    #[cfg(target_os = "linux")]
    {
        linux::enumerate()
    }
    #[cfg(target_os = "windows")]
    {
        // Planned: SetupAPI (GUID_DEVINTERFACE_DISK) + IOCTL_STORAGE_QUERY_PROPERTY.
        Err(EnumerateError::Unsupported("windows"))
    }
    #[cfg(any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        // Planned: sysctl kern.disks + geom/camcontrol (FreeBSD),
        // hw.disknames + disklabel (OpenBSD/NetBSD).
        Err(EnumerateError::Unsupported("bsd"))
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )))]
    {
        Err(EnumerateError::Unsupported("unknown"))
    }
}
