//! The image-detection decision tree.
//!
//! This is the heart of Osedax: given the head of an image, classify what it is
//! and how it must be written. The ordering follows
//! `docs/porting/04-iso-detection-tree.md`: compression first, then the
//! ISO/UDF optical family (with the critical hybrid branch), then raw disk
//! images, then bare filesystems, then unknown.
//!
//! Everything here is a pure function of a byte slice — no device, no I/O — so
//! the whole classifier is exhaustively unit-testable against synthetic heads.

use crate::detect::magic;

/// How much of an image head the tree needs. Covers the MBR (0..512), GPT
/// (512/4096), the ISO/UDF VRS and El Torito descriptors (0x8000..0x8800+), and
/// leaves margin. The scanner should read at least this many bytes.
pub const HEAD_LEN: usize = 40 * 1024;

/// Whether a detected ISO can be raw-written (dd) to USB and boot, or is
/// optical-only. This is branch 1a — the single most important distinction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsoHybrid {
    /// Carries an MBR partition table with used entries — BIOS-hybrid, dd-able.
    BiosHybrid,
    /// Carries a GPT / ESP marker — UEFI-hybrid, dd-able.
    UefiHybrid,
    /// Both an MBR table and a GPT/ESP marker are present.
    BiosAndUefiHybrid,
    /// Plain ISO 9660 with no partition table — optical media only. Writing it
    /// raw to USB will very likely not boot. (The BSD-warning path.)
    OpticalOnly,
}

impl IsoHybrid {
    /// True if this ISO can be raw-written to USB and reasonably expected to boot.
    pub fn is_dd_writable(self) -> bool {
        !matches!(self, IsoHybrid::OpticalOnly)
    }
}

/// The result of classifying an image head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageKind {
    /// A compression wrapper was detected; the inner image is unknown until the
    /// head is decompressed and re-classified. Carries the wrapper format.
    Compressed(magic::Compression),

    /// An optical-filesystem image (ISO 9660 and/or UDF).
    Iso {
        hybrid: IsoHybrid,
        /// UDF present (modern large Windows ISOs; also UDF-bridge with CD001).
        udf: bool,
        /// El Torito boot catalog present.
        el_torito: bool,
    },

    /// A raw disk image with its own partition table.
    DiskImage {
        /// True if partitioned by GPT (else MBR).
        gpt: bool,
    },

    /// A partitionless image that is a bare filesystem at offset 0.
    BareFilesystem(magic::FilesystemHint),

    /// A Windows Imaging Format file (a raw install.wim/.esd, not an ISO).
    Wim,

    /// None of the known signatures matched — refuse to auto-burn; require an
    /// explicit user override.
    Unknown,
}

/// Classify the head of an (uncompressed) image.
///
/// Callers must handle [`ImageKind::Compressed`] by decompressing enough of the
/// head and calling this again on the inner bytes.
pub fn classify(head: &[u8]) -> ImageKind {
    // STEP 0 — compression wrapper (offset 0).
    if let Some(c) = magic::detect_compression(head) {
        return ImageKind::Compressed(c);
    }

    // STEP 1 — ISO 9660 / UDF optical family.
    let iso = magic::has_iso9660(head);
    let udf = magic::has_udf(head);
    if iso || udf {
        return ImageKind::Iso {
            hybrid: classify_hybrid(head),
            udf,
            el_torito: magic::el_torito(head).is_some(),
        };
    }

    // STEP 2 — raw install.wim/.esd (before generic disk-image checks, since a
    // WIM has no partition table and would otherwise fall through to Unknown).
    if magic::is_wim(head) {
        return ImageKind::Wim;
    }

    // STEP 3 — raw disk image with a partition table.
    if magic::has_gpt(head) {
        return ImageKind::DiskImage { gpt: true };
    }
    if magic::has_mbr_partition_table(head) {
        return ImageKind::DiskImage { gpt: false };
    }

    // STEP 3b — bare filesystem at offset 0 (partitionless image).
    if magic::is_ntfs_bootsector(head) {
        return ImageKind::BareFilesystem(magic::FilesystemHint::Ntfs);
    }
    if magic::is_fat_or_ntfs_bootsector(head) {
        return ImageKind::BareFilesystem(magic::FilesystemHint::Fat);
    }
    if magic::is_ext(head) {
        return ImageKind::BareFilesystem(magic::FilesystemHint::Ext);
    }

    // STEP 4 — unknown.
    ImageKind::Unknown
}

/// Branch 1a: decide whether an ISO carries a partition table (dd-able) or is
/// optical-only. `head` must contain at least the MBR and GPT regions.
fn classify_hybrid(head: &[u8]) -> IsoHybrid {
    let parts = magic::mbr_partitions(head).filter(|_| magic::mbr_signature(head));

    // A *real* BIOS partition is a used entry that isn't a pure UEFI/GPT marker:
    // 0xEE (GPT protective) and 0xEF (ESP marker) signal UEFI, not legacy boot,
    // so they must not count as BIOS-hybrid on their own.
    let bios = parts.is_some_and(|p| {
        p.iter()
            .any(|e| e.is_used() && !e.is_gpt_protective() && !e.is_esp())
    });
    // A UEFI hybrid is signaled by a GPT header, a 0xEE protective entry, or an
    // 0xEF ESP marker in the MBR.
    let mbr_efi_marker =
        parts.is_some_and(|p| p.iter().any(|e| e.is_gpt_protective() || e.is_esp()));
    let gpt = magic::has_gpt(head) || mbr_efi_marker;

    match (bios, gpt) {
        (true, true) => IsoHybrid::BiosAndUefiHybrid,
        (false, true) => IsoHybrid::UefiHybrid,
        (true, false) => IsoHybrid::BiosHybrid,
        (false, false) => IsoHybrid::OpticalOnly,
    }
}

// ---- BSD optical-only warning -------------------------------------------

/// Which BSD an optical-only ISO looks like, so the warning can name the exact
/// USB image the user should download instead. Derived from filename/volume
/// label patterns (`docs/porting/04-iso-detection-tree.md`, Part C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BsdFlavor {
    FreeBsd,
    OpenBsd,
    NetBsd,
    DragonFly,
    /// Optical-only, but no recognizable BSD name — a generic warning still applies.
    Unknown,
}

impl BsdFlavor {
    /// The vendor's dedicated USB image, for the warning message.
    pub fn usb_image_hint(self) -> &'static str {
        match self {
            BsdFlavor::FreeBsd => "FreeBSD-<ver>-<arch>-memstick.img",
            BsdFlavor::OpenBsd => "install<XX>.img (e.g. install79.img)",
            BsdFlavor::NetBsd => "the install.img.gz memstick image (decompress first)",
            BsdFlavor::DragonFly => "dfly-<arch>-<ver>_REL.img.bz2 (decompress first)",
            BsdFlavor::Unknown => "the vendor's dedicated USB (.img/memstick) image",
        }
    }
}

/// A hard warning that an optical-only ISO is about to be written to USB and
/// will most likely not boot. Callers surface this and require explicit consent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BsdWarning {
    pub flavor: BsdFlavor,
    pub message: String,
}

/// Guess the BSD flavor from an image's filename and/or volume label.
///
/// Matches vendor words (`freebsd`/`openbsd`/`netbsd`/`dragonfly`/`dfly`) and,
/// for OpenBSD whose ISOs are often named without the word, the characteristic
/// `install<NN>`/`cd<NN>` filenames (e.g. `install79.iso`, `cd79.iso`).
/// Returns [`BsdFlavor::Unknown`] when nothing matches — the warning still
/// fires for any optical-only ISO, this only picks which USB image to name.
pub fn guess_bsd_flavor(name_and_label: &str) -> BsdFlavor {
    let s = name_and_label.to_ascii_lowercase();
    if s.contains("freebsd") {
        BsdFlavor::FreeBsd
    } else if s.contains("openbsd") || has_openbsd_iso_name(&s) {
        BsdFlavor::OpenBsd
    } else if s.contains("netbsd") {
        BsdFlavor::NetBsd
    } else if s.contains("dragonfly") || s.contains("dfly") {
        BsdFlavor::DragonFly
    } else {
        BsdFlavor::Unknown
    }
}

/// True if `s` (already lowercased) contains an OpenBSD-style optical filename:
/// the token `install` or `cd` immediately followed by at least two digits
/// (the release number, e.g. `install79`, `cd79`). Requiring two digits keeps
/// this from firing on generic names like `install.iso` or `cd/`.
fn has_openbsd_iso_name(s: &str) -> bool {
    for token in ["install", "cd"] {
        let mut from = 0;
        while let Some(pos) = s[from..].find(token) {
            let after = from + pos + token.len();
            let digits = s[after..].bytes().take_while(u8::is_ascii_digit).count();
            if digits >= 2 {
                return true;
            }
            from = after;
        }
    }
    false
}

/// Produce a BSD warning if `kind` is an optical-only ISO. Returns `None` when
/// the image is dd-writable or isn't an ISO at all. `name_and_label` is the
/// filename and/or volume label, used only to name the right USB image.
pub fn bsd_warning(kind: &ImageKind, name_and_label: &str) -> Option<BsdWarning> {
    let ImageKind::Iso { hybrid, .. } = kind else {
        return None;
    };
    if *hybrid != IsoHybrid::OpticalOnly {
        return None;
    }
    let flavor = guess_bsd_flavor(name_and_label);
    let named = match flavor {
        BsdFlavor::Unknown => String::new(),
        BsdFlavor::FreeBsd => " It looks like a FreeBSD install ISO.".into(),
        BsdFlavor::OpenBsd => " It looks like an OpenBSD install ISO.".into(),
        BsdFlavor::NetBsd => " It looks like a NetBSD install ISO.".into(),
        BsdFlavor::DragonFly => " It looks like a DragonFly BSD install ISO.".into(),
    };
    let message = format!(
        "This is an ISO-9660 image with no hybrid partition table or EFI boot \
         entry, so writing it raw to USB will most likely produce a non-bootable \
         stick.{named} For USB, use {} instead. Write this ISO to USB anyway?",
        flavor.usb_image_hint()
    );
    Some(BsdWarning { flavor, message })
}

// ---- top-level verdict ---------------------------------------------------

/// The complete result of inspecting an image head: what it is, plus any
/// hard warning a caller must surface before writing.
///
/// This is the entry point a frontend uses: hand it the head bytes and the
/// image's filename/label, get back a classification and (for optical-only
/// ISOs) the BSD warning to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub kind: ImageKind,
    /// Present only for optical-only ISOs — a hard "this won't boot" warning.
    pub bsd_warning: Option<BsdWarning>,
}

impl Verdict {
    /// True if this image can be raw-written to USB with a reasonable
    /// expectation of booting. Compressed images return `false` here because
    /// the inner content must be decompressed and re-inspected first.
    pub fn is_dd_writable(&self) -> bool {
        match &self.kind {
            ImageKind::Iso { hybrid, .. } => hybrid.is_dd_writable(),
            ImageKind::DiskImage { .. } | ImageKind::BareFilesystem(_) => true,
            ImageKind::Compressed(_) | ImageKind::Wim | ImageKind::Unknown => false,
        }
    }
}

/// Inspect an image head and produce a [`Verdict`]. `name_and_label` is the
/// filename and/or volume label, used only to name the right USB image in a
/// BSD warning; pass an empty string if unknown.
pub fn inspect(head: &[u8], name_and_label: &str) -> Verdict {
    let kind = classify(head);
    let bsd_warning = bsd_warning(&kind, name_and_label);
    Verdict { kind, bsd_warning }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::magic::{
        Compression, EL_TORITO_BRVD_OFFSET, EL_TORITO_ID, FilesystemHint, ISO9660_MAGIC,
        ISO9660_MAGIC_OFFSET, MBR_PARTITION_TABLE_OFFSET, MBR_SIG_OFFSET,
    };

    fn blank_head() -> Vec<u8> {
        vec![0u8; HEAD_LEN]
    }

    /// Write the ISO 9660 "CD001" identifier into a head buffer.
    fn make_iso(buf: &mut [u8]) {
        buf[ISO9660_MAGIC_OFFSET..ISO9660_MAGIC_OFFSET + 5].copy_from_slice(ISO9660_MAGIC);
    }

    /// Write a valid MBR signature plus one used partition entry.
    fn add_mbr_partition(buf: &mut [u8], part_type: u8) {
        buf[MBR_SIG_OFFSET] = 0x55;
        buf[MBR_SIG_OFFSET + 1] = 0xAA;
        let e = MBR_PARTITION_TABLE_OFFSET;
        buf[e] = 0x80;
        buf[e + 4] = part_type;
        buf[e + 8..e + 12].copy_from_slice(&2048u32.to_le_bytes());
        buf[e + 12..e + 16].copy_from_slice(&1_000_000u32.to_le_bytes());
    }

    #[test]
    fn compression_wins_first() {
        // Even if ISO bytes are present later, a compression wrapper at offset 0
        // must be reported first — the inner content is unknowable until decoded.
        let mut buf = blank_head();
        make_iso(&mut buf);
        buf[0..2].copy_from_slice(&[0x1F, 0x8B]);
        assert_eq!(classify(&buf), ImageKind::Compressed(Compression::Gzip));
    }

    #[test]
    fn plain_iso_is_optical_only() {
        let mut buf = blank_head();
        make_iso(&mut buf);
        assert_eq!(
            classify(&buf),
            ImageKind::Iso {
                hybrid: IsoHybrid::OpticalOnly,
                udf: false,
                el_torito: false,
            }
        );
    }

    #[test]
    fn optical_only_is_not_dd_writable() {
        // This is the BSD-warning trigger: an ISO with no partition table.
        assert!(!IsoHybrid::OpticalOnly.is_dd_writable());
        assert!(IsoHybrid::BiosHybrid.is_dd_writable());
        assert!(IsoHybrid::UefiHybrid.is_dd_writable());
    }

    #[test]
    fn bios_hybrid_iso_is_dd_writable() {
        let mut buf = blank_head();
        make_iso(&mut buf);
        add_mbr_partition(&mut buf, 0x83); // ordinary Linux partition
        match classify(&buf) {
            ImageKind::Iso { hybrid, .. } => {
                assert_eq!(hybrid, IsoHybrid::BiosHybrid);
                assert!(hybrid.is_dd_writable());
            }
            other => panic!("expected Iso, got {other:?}"),
        }
    }

    #[test]
    fn iso_with_gpt_protective_mbr_is_uefi_hybrid() {
        let mut buf = blank_head();
        make_iso(&mut buf);
        // Only a GPT-protective (0xEE) entry, no ordinary partition => UEFI hybrid.
        buf[MBR_SIG_OFFSET] = 0x55;
        buf[MBR_SIG_OFFSET + 1] = 0xAA;
        let e = MBR_PARTITION_TABLE_OFFSET;
        buf[e + 4] = 0xEE;
        buf[e + 8..e + 12].copy_from_slice(&1u32.to_le_bytes());
        buf[e + 12..e + 16].copy_from_slice(&1u32.to_le_bytes());
        match classify(&buf) {
            ImageKind::Iso { hybrid, .. } => assert_eq!(hybrid, IsoHybrid::UefiHybrid),
            other => panic!("expected Iso, got {other:?}"),
        }
    }

    #[test]
    fn detects_el_torito_in_iso() {
        let mut buf = blank_head();
        make_iso(&mut buf);
        let o = EL_TORITO_BRVD_OFFSET;
        buf[o] = 0x00;
        buf[o + 1..o + 6].copy_from_slice(ISO9660_MAGIC);
        buf[o + 7..o + 7 + EL_TORITO_ID.len()].copy_from_slice(EL_TORITO_ID);
        match classify(&buf) {
            ImageKind::Iso { el_torito, .. } => assert!(el_torito),
            other => panic!("expected Iso, got {other:?}"),
        }
    }

    #[test]
    fn gpt_disk_image() {
        let mut buf = blank_head();
        buf[512..520].copy_from_slice(b"EFI PART");
        assert_eq!(classify(&buf), ImageKind::DiskImage { gpt: true });
    }

    #[test]
    fn mbr_disk_image() {
        let mut buf = blank_head();
        add_mbr_partition(&mut buf, 0x83);
        assert_eq!(classify(&buf), ImageKind::DiskImage { gpt: false });
    }

    #[test]
    fn bare_ntfs_filesystem() {
        let mut buf = blank_head();
        buf[0] = 0xEB;
        buf[2] = 0x90;
        buf[3..11].copy_from_slice(b"NTFS    ");
        buf[MBR_SIG_OFFSET] = 0x55;
        buf[MBR_SIG_OFFSET + 1] = 0xAA;
        assert_eq!(
            classify(&buf),
            ImageKind::BareFilesystem(FilesystemHint::Ntfs)
        );
    }

    #[test]
    fn raw_wim_file() {
        let mut buf = blank_head();
        buf[0..8].copy_from_slice(b"MSWIM\0\0\0");
        assert_eq!(classify(&buf), ImageKind::Wim);
    }

    #[test]
    fn unknown_when_nothing_matches() {
        assert_eq!(classify(&blank_head()), ImageKind::Unknown);
    }

    #[test]
    fn total_on_tiny_buffers() {
        // Must never panic regardless of how short the input is.
        for len in 0..600 {
            let _ = classify(&vec![0u8; len]);
        }
    }

    // ---- BSD optical-only warning (the headline safety feature) ----

    #[test]
    fn guesses_bsd_flavor_from_name_or_label() {
        assert_eq!(
            guess_bsd_flavor("FreeBSD-14.0-amd64-disc1.iso"),
            BsdFlavor::FreeBsd
        );
        // OpenBSD ISOs are usually named without the vendor word; the
        // install<NN>/cd<NN> filename pattern must still resolve to OpenBSD.
        assert_eq!(guess_bsd_flavor("install79.iso"), BsdFlavor::OpenBsd);
        assert_eq!(guess_bsd_flavor("cd79.iso"), BsdFlavor::OpenBsd);
        assert_eq!(
            guess_bsd_flavor("OpenBSD/amd64 7.9 Install CD"),
            BsdFlavor::OpenBsd
        );
        // But a generic name without two release digits must NOT be tagged BSD.
        assert_eq!(guess_bsd_flavor("install.iso"), BsdFlavor::Unknown);
        assert_eq!(guess_bsd_flavor("ubuntu-installer.iso"), BsdFlavor::Unknown);
        assert_eq!(guess_bsd_flavor("NetBSD-10.0-amd64.iso"), BsdFlavor::NetBsd);
        assert_eq!(
            guess_bsd_flavor("dfly-x86_64-6.4_REL.iso"),
            BsdFlavor::DragonFly
        );
        assert_eq!(
            guess_bsd_flavor("ubuntu-24.04-desktop.iso"),
            BsdFlavor::Unknown
        );
    }

    #[test]
    fn optical_only_iso_produces_a_bsd_warning() {
        // Plain ISO 9660, no partition table -> optical-only -> must warn.
        let mut buf = blank_head();
        make_iso(&mut buf);
        let kind = classify(&buf);
        let w =
            bsd_warning(&kind, "FreeBSD-14.0-amd64-disc1.iso").expect("optical-only ISO must warn");
        assert_eq!(w.flavor, BsdFlavor::FreeBsd);
        assert!(w.message.contains("memstick.img"));
        assert!(w.message.to_lowercase().contains("non-bootable"));
    }

    #[test]
    fn hybrid_iso_produces_no_bsd_warning() {
        // A dd-writable hybrid ISO is fine to write raw -> no warning.
        let mut buf = blank_head();
        make_iso(&mut buf);
        add_mbr_partition(&mut buf, 0x83);
        let kind = classify(&buf);
        assert!(bsd_warning(&kind, "arch-2026.iso").is_none());
    }

    #[test]
    fn non_iso_never_warns() {
        // A raw disk image is not an ISO; the BSD warning must not fire.
        let mut buf = blank_head();
        add_mbr_partition(&mut buf, 0x83);
        assert!(bsd_warning(&classify(&buf), "anything").is_none());
    }

    #[test]
    fn optical_only_without_bsd_name_still_warns_generically() {
        let mut buf = blank_head();
        make_iso(&mut buf);
        let w = bsd_warning(&classify(&buf), "mystery.iso").expect("still warns");
        assert_eq!(w.flavor, BsdFlavor::Unknown);
        // Generic hint, no vendor-specific filename.
        assert!(w.message.contains("dedicated USB"));
    }

    // ---- inspect() + Verdict ----

    #[test]
    fn inspect_bundles_kind_and_warning() {
        let mut buf = blank_head();
        make_iso(&mut buf);
        let v = inspect(&buf, "OpenBSD 7.9 install");
        assert!(matches!(v.kind, ImageKind::Iso { .. }));
        assert!(!v.is_dd_writable()); // optical-only
        assert_eq!(
            v.bsd_warning.as_ref().map(|w| w.flavor),
            Some(BsdFlavor::OpenBsd)
        );
    }

    #[test]
    fn verdict_dd_writable_matrix() {
        // Hybrid ISO / disk image / bare fs are dd-writable; compressed, WIM,
        // unknown, and optical-only ISO are not.
        let dd_writable = |k: ImageKind| {
            Verdict {
                kind: k,
                bsd_warning: None,
            }
            .is_dd_writable()
        };
        assert!(dd_writable(ImageKind::DiskImage { gpt: true }));
        assert!(dd_writable(ImageKind::BareFilesystem(FilesystemHint::Ext)));
        assert!(dd_writable(ImageKind::Iso {
            hybrid: IsoHybrid::BiosHybrid,
            udf: false,
            el_torito: true,
        }));
        assert!(!dd_writable(ImageKind::Iso {
            hybrid: IsoHybrid::OpticalOnly,
            udf: false,
            el_torito: false,
        }));
        assert!(!dd_writable(ImageKind::Compressed(Compression::Xz)));
        assert!(!dd_writable(ImageKind::Wim));
        assert!(!dd_writable(ImageKind::Unknown));
    }
}
