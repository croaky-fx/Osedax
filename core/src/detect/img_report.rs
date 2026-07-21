//! The `ImgReport` model — Osedax's single source of truth about an image.
//!
//! This is a direct port of Rufus's `RUFUS_IMG_REPORT` struct (`rufus.h:432-481`)
//! and its `IS_*`/`HAS_*` decision macros (`rufus.h:370-395`). See
//! `docs/porting/01-rufus-img-report.md` for the field-by-field mapping.
//!
//! The scanner fills this in while walking an image; every downstream decision
//! (filesystem choice, partition scheme, boot method) reads from it. Keeping the
//! decision logic here — as pure functions of the report — mirrors Rufus and
//! keeps it exhaustively unit-testable without touching a real device.

/// Maximum number of Windows install images tracked (`MAX_WININST`, rufus.h:92).
/// Bounded at 4 because `has_4gb_file`'s high nibble maps one flag bit per entry.
pub const MAX_WININST: usize = 4;
/// Number of tracked legacy c32 modules (`NB_OLD_C32`).
pub const NB_OLD_C32: usize = 2;

/// FAT32's per-file ceiling: 2^32 - 1 bytes. A single file at or above this
/// cannot live on FAT32 and forces either a WIM split or an NTFS target.
pub const FAT32_MAX_FILE: u64 = u32::MAX as u64; // 4_294_967_295

/// Windows version quadruple (`winver_t`, rufus.h:399-404).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WinVer {
    pub major: u16,
    pub minor: u16,
    pub build: u16,
    pub revision: u16,
}

/// The kind of UEFI boot entry found (`EFI_BOOT_TYPE`, rufus.h:353-358).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EfiBootType {
    /// A regular `boot<arch>.efi` loader.
    Main,
    /// A GRUB EFI loader.
    Grub,
    /// A Secure Boot MOK manager.
    MokManager,
    /// Windows `bootmgr.efi`.
    BootMgr,
}

/// One detected UEFI bootloader (`efi_boot_entry_t`, rufus.h:427-430).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfiBootEntry {
    pub kind: EfiBootType,
    pub path: String,
}

/// Which filesystem a target should be formatted with (`fs_type`, rufus.h:304-316).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    Fat16,
    Fat32,
    Ntfs,
    Udf,
    ExFat,
    Ext2,
    Ext3,
    Ext4,
}

impl FsType {
    /// `IS_FAT` (rufus.h:394).
    pub fn is_fat(self) -> bool {
        matches!(self, FsType::Fat16 | FsType::Fat32)
    }
    /// `IS_EXT` (rufus.h:395).
    pub fn is_ext(self) -> bool {
        matches!(self, FsType::Ext2 | FsType::Ext3 | FsType::Ext4)
    }
}

/// Target firmware type (`target_type`, rufus.h:332-336).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetType {
    Bios,
    Uefi,
}

/// Tri-state DD-bootability (`is_bootable_img`, an `int8_t` in Rufus).
///
/// Modeled as an enum rather than a raw integer so the "forced" state (user
/// overrode a missing boot marker) can't be confused with "genuinely bootable".
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum DdBootable {
    /// No 0x55AA boot marker; not raw-writable as a bootable image.
    #[default]
    No,
    /// A valid boot marker was found.
    Yes,
    /// No marker, but the user forced DD mode (`ignore_boot_marker`).
    Forced,
}

impl DdBootable {
    /// `IS_DD_BOOTABLE = is_bootable_img > 0` (rufus.h:388).
    pub fn is_bootable(self) -> bool {
        matches!(self, DdBootable::Yes | DdBootable::Forced)
    }
}

// ---- has_efi bitmask (see docs/porting/01, §2 notes) --------------------

/// bit 0: `bootmgr.efi` is present.
pub const EFI_BOOTMGR: u16 = 0x0001;
/// Mask of "regular" per-architecture EFI loaders (`HAS_REGULAR_EFI`, 0x7FFE):
/// every bit except bit 0 (bootmgr.efi) and bit 15 (efi.img-only).
pub const EFI_REGULAR_MASK: u16 = 0x7FFE;
/// bit 14: broken-`bootx64.efi` symlink workaround marker.
pub const EFI_BROKEN_BOOTX64: u16 = 0x4000;
/// bit 15: the only EFI bootloader lives inside an `efi*.img`.
pub const EFI_IMG_ONLY: u16 = 0x8000;

// ---- has_grub2 bitmask ---------------------------------------------------

/// bit 7 of `has_grub2`: an EFI GRUB loader is present. The low 7 bits encode
/// the BIOS GRUB directory variant (1 = /boot/grub, 2 = /boot/grub2).
pub const GRUB2_EFI: u8 = 0x80;

// ---- has_grub2_fs bitmask (filesystem drivers a GRUB build carries) ------

pub const GRUB2_FS_FAT: u8 = 0x1;
pub const GRUB2_FS_EXFAT: u8 = 0x2;
pub const GRUB2_FS_NTFS: u8 = 0x4;

// ---- has_4gb_file packed byte -------------------------------------------

/// `has_4gb_file` low nibble is a saturating counter of files >= 4 GiB; the
/// high nibble flags *which* `install.{wim,esd,swm}` entry is oversized
/// (`0x10 << i`). The exact value `0x11` means "count == 1 AND that one file is
/// install.wim (entry 0)" — the splittable-only case.
pub const FOURGB_SPLITTABLE_ONLY: u8 = 0x11;

/// WinPE architecture bits (`winpe`, rufus.h:366-368).
pub const WINPE_I386: u16 = 0x1;
pub const WINPE_AMD64: u16 = 0x2;
pub const WINPE_MININT: u16 = 0x4;

/// The full image report. Defaults to "nothing detected"; the scanner sets
/// fields as it walks the image.
#[derive(Debug, Default, Clone)]
pub struct ImgReport {
    // --- identity / sizes ---
    pub label: String,
    pub image_size: u64,
    pub projected_size: u64,

    // --- top-level classification ---
    pub is_iso: bool,
    pub is_dd_bootable: DdBootable,
    pub is_vhd: bool,
    pub is_windows_img: bool,
    /// Force DD-only: ISO (file-copy) mode is known-broken for this image.
    pub disable_iso: bool,

    // --- Windows installer markers ---
    pub has_bootmgr: bool,
    pub has_bootmgr_efi: bool,
    /// Count of install.wim/.esd/.swm found under */sources.
    pub wininst_index: u8,
    pub wininst_path: Vec<String>,
    pub win_version: WinVer,
    pub winpe: u16,
    pub uses_minint: bool,

    // --- EFI / boot loaders ---
    pub has_efi: u16,
    pub efi_boot_entry: Vec<EfiBootEntry>,
    pub efi_img_path: String,

    // --- bootloader families ---
    pub has_grub2: u8,
    pub has_grub2_fs: u8,
    pub has_grub4dos: bool,
    /// Syslinux/Isolinux version (0 = none).
    pub sl_version: u16,
    pub has_kolibrios: bool,
    pub reactos_path: String,

    // --- filesystem-shaping facts ---
    pub has_4gb_file: u8,
    pub needs_ntfs: bool,
    pub uses_casper: bool,

    // --- misc ---
    pub has_md5sum: u8,
    pub rh8_derivative: bool,
}

impl ImgReport {
    // ---- boot-family predicates (rufus.h:370-395) ----

    /// `HAS_KOLIBRIOS` (rufus.h:370).
    pub fn has_kolibrios(&self) -> bool {
        self.has_kolibrios
    }
    /// `HAS_REACTOS` (rufus.h:371).
    pub fn has_reactos(&self) -> bool {
        !self.reactos_path.is_empty()
    }
    /// `HAS_GRUB` (rufus.h:372).
    pub fn has_grub(&self) -> bool {
        self.has_grub2 != 0 || self.has_grub4dos
    }
    /// `HAS_SYSLINUX` (rufus.h:373).
    pub fn has_syslinux(&self) -> bool {
        self.sl_version != 0
    }
    /// `HAS_BOOTMGR` (rufus.h:376).
    pub fn has_bootmgr(&self) -> bool {
        self.has_bootmgr || self.has_bootmgr_efi
    }
    /// `HAS_REGULAR_EFI` (rufus.h:377) — a real per-arch EFI loader exists.
    pub fn has_regular_efi(&self) -> bool {
        self.has_efi & EFI_REGULAR_MASK != 0
    }
    /// `HAS_WININST` (rufus.h:378).
    pub fn has_wininst(&self) -> bool {
        self.wininst_index != 0
    }
    /// `HAS_WINPE` (rufus.h:379).
    pub fn has_winpe(&self) -> bool {
        self.winpe & (WINPE_I386 | WINPE_AMD64 | WINPE_MININT) != 0
    }
    /// `HAS_WINDOWS` (rufus.h:380).
    pub fn has_windows(&self) -> bool {
        self.has_bootmgr() || self.uses_minint || self.has_winpe()
    }
    /// `HAS_WIN7_EFI` (rufus.h:381): EFI is *only* bootmgr.efi and an installer
    /// exists — Win7 needs bootmgfw.efi extracted from install.wim.
    pub fn has_win7_efi(&self) -> bool {
        self.has_efi == EFI_BOOTMGR && self.has_wininst()
    }
    /// `HAS_FATLESS_GRUB` (rufus.h:382): EFI GRUB present but its build carries
    /// no FAT driver.
    pub fn has_fatless_grub(&self) -> bool {
        (self.has_grub2 & GRUB2_EFI != 0) && (self.has_grub2_fs & GRUB2_FS_FAT == 0)
    }
    /// `IS_WINDOWS_1X` (rufus.h:384).
    pub fn is_windows_1x(&self) -> bool {
        self.has_bootmgr_efi && self.win_version.major >= 10
    }
    /// `IS_WINDOWS_11` (rufus.h:385).
    pub fn is_windows_11(&self) -> bool {
        self.has_bootmgr_efi && self.win_version.major >= 11
    }
    /// `IS_EFI_BOOTABLE = has_efi != 0` (rufus.h:390).
    pub fn is_efi_bootable(&self) -> bool {
        self.has_efi != 0
    }
    /// `IS_BIOS_BOOTABLE` (rufus.h:391).
    pub fn is_bios_bootable(&self) -> bool {
        self.has_bootmgr()
            || self.has_syslinux()
            || self.has_winpe()
            || self.has_grub()
            || self.has_reactos()
            || self.has_kolibrios()
    }
    /// `IS_DD_BOOTABLE` (rufus.h:388).
    pub fn is_dd_bootable(&self) -> bool {
        self.is_dd_bootable.is_bootable()
    }
    /// `IS_DD_ONLY` (rufus.h:389): DD-bootable but not usable in ISO mode.
    pub fn is_dd_only(&self) -> bool {
        self.is_dd_bootable.is_bootable() && (!self.is_iso || self.disable_iso)
    }
    /// `HAS_WINTOGO` (rufus.h:392).
    pub fn has_wintogo(&self) -> bool {
        self.has_bootmgr() && self.is_efi_bootable() && self.has_wininst()
    }
    /// `HAS_PERSISTENCE` (rufus.h:393).
    pub fn has_persistence(&self) -> bool {
        (self.has_syslinux() || self.has_grub())
            && !(self.has_windows() || self.has_reactos() || self.has_kolibrios())
    }

    /// `IS_FAT32_COMPAT` (rufus.h:386).
    ///
    /// FAT32 is viable when there is no >=4 GiB file (and GRUB, if present, can
    /// read FAT), OR the only oversized file is a splittable install.wim and
    /// dual UEFI+BIOS is allowed (so the split will actually be applied) — and
    /// never when the image requires NTFS.
    pub fn is_fat32_compat(&self, allow_dual_uefi_bios: bool) -> bool {
        let clean = self.has_4gb_file == 0 && !self.has_fatless_grub();
        let splittable = self.has_4gb_file == FOURGB_SPLITTABLE_ONLY && allow_dual_uefi_bios;
        (clean || splittable) && !self.needs_ntfs
    }

    /// Whether this image is supported at all: it must be raw-writable, or have
    /// a BIOS or EFI boot method Osedax understands (final gate, rufus.c:1441).
    pub fn is_supported(&self) -> bool {
        self.is_dd_bootable() || self.is_bios_bootable() || self.is_efi_bootable()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_report_detects_nothing() {
        let r = ImgReport::default();
        assert!(!r.has_windows());
        assert!(!r.is_efi_bootable());
        assert!(!r.is_bios_bootable());
        assert!(!r.is_dd_bootable());
        assert!(!r.is_supported());
        assert!(!r.has_wininst());
    }

    #[test]
    fn has_regular_efi_excludes_bootmgr_and_imgonly_bits() {
        // bit 0 (bootmgr.efi) alone is NOT a regular per-arch loader.
        let mut r = ImgReport::default();
        r.has_efi = EFI_BOOTMGR;
        assert!(!r.has_regular_efi());

        // bit 15 (efi.img-only) alone is NOT a regular loader either.
        r.has_efi = EFI_IMG_ONLY;
        assert!(!r.has_regular_efi());

        // A real per-arch loader bit (within the regular mask) counts.
        r.has_efi = 0x0002;
        assert!(r.has_regular_efi());
    }

    #[test]
    fn win7_efi_requires_only_bootmgr_and_an_installer() {
        let mut r = ImgReport::default();
        r.has_efi = EFI_BOOTMGR;
        r.wininst_index = 1;
        assert!(r.has_win7_efi());

        // Any additional EFI bit means it's not the Win7-only-bootmgr case.
        r.has_efi = EFI_BOOTMGR | 0x0002;
        assert!(!r.has_win7_efi());

        // bootmgr.efi but no installer -> not Win7-EFI.
        r.has_efi = EFI_BOOTMGR;
        r.wininst_index = 0;
        assert!(!r.has_win7_efi());
    }

    #[test]
    fn fatless_grub_needs_efi_grub_without_a_fat_driver() {
        let mut r = ImgReport::default();
        // EFI GRUB present, no FAT driver in its build -> fatless.
        r.has_grub2 = GRUB2_EFI;
        r.has_grub2_fs = GRUB2_FS_NTFS;
        assert!(r.has_fatless_grub());

        // Same GRUB, but it carries a FAT driver -> not fatless.
        r.has_grub2_fs = GRUB2_FS_FAT;
        assert!(!r.has_fatless_grub());

        // BIOS-only GRUB (no EFI bit) is never "fatless EFI GRUB".
        r.has_grub2 = 0x01;
        r.has_grub2_fs = 0;
        assert!(!r.has_fatless_grub());
    }

    #[test]
    fn fat32_compat_handles_the_splittable_only_case() {
        let mut r = ImgReport::default();

        // No oversized file, no fatless grub -> FAT32 is fine.
        assert!(r.is_fat32_compat(false));

        // A generic >=4GiB file rules out FAT32 regardless of dual-boot.
        r.has_4gb_file = 0x02; // count 2, not the splittable-only sentinel
        assert!(!r.is_fat32_compat(true));

        // The exact 0x11 state (one oversized file == install.wim, entry 0) is
        // FAT32-compatible ONLY when dual UEFI+BIOS is allowed (so it's split).
        r.has_4gb_file = FOURGB_SPLITTABLE_ONLY;
        assert!(!r.is_fat32_compat(false));
        assert!(r.is_fat32_compat(true));

        // needs_ntfs is an absolute veto even in the splittable case.
        r.needs_ntfs = true;
        assert!(!r.is_fat32_compat(true));
    }

    #[test]
    fn wintogo_requires_bootmgr_efi_and_installer_together() {
        let mut r = ImgReport::default();
        r.has_bootmgr = true; // BIOS bootmgr
        r.has_efi = 0x0002; // some EFI loader
        r.wininst_index = 1; // an install.wim
        assert!(r.has_wintogo());

        // Drop the installer -> not Windows To Go.
        r.wininst_index = 0;
        assert!(!r.has_wintogo());
    }

    #[test]
    fn persistence_excludes_windows_and_family_oses() {
        let mut r = ImgReport::default();
        r.sl_version = 6; // syslinux present -> a Linux live medium
        assert!(r.has_persistence());

        // If it's also a Windows medium, persistence doesn't apply.
        r.has_bootmgr = true;
        assert!(!r.has_persistence());
    }

    #[test]
    fn dd_only_when_bootable_but_iso_mode_unusable() {
        let mut r = ImgReport::default();
        r.is_dd_bootable = DdBootable::Yes;
        r.is_iso = true;
        // Bootable ISO that also works in ISO mode -> not DD-only.
        assert!(!r.is_dd_only());

        // Same image but ISO mode disabled -> DD-only.
        r.disable_iso = true;
        assert!(r.is_dd_only());
    }
}
