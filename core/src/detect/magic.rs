//! Byte-signature probes for image/format detection.
//!
//! Every offset and magic value here is sourced from the specs in
//! `docs/porting/04-iso-detection-tree.md` (cross-corroborated against
//! libisofs, libblkid, and the Rufus/Etcher source trees).
//!
//! All probes operate on an in-memory byte slice representing the head of the
//! image (the detection tree reads ~40 KiB, which covers every window below).
//! Probes are total: an out-of-range offset yields `false`/`None`, never a panic.

// ---- Offsets & sizes (decimal / hex) ------------------------------------

/// ISO 9660 Primary Volume Descriptor identifier "CD001", at byte 32769 (0x8001).
pub const ISO9660_MAGIC_OFFSET: usize = 32769;
/// The ISO 9660 / UDF Volume Recognition Sequence starts at byte 32768 (0x8000).
pub const VRS_START: usize = 32768;
/// Each Volume Descriptor in the VRS is one 2048-byte logical sector.
pub const ISO_SECTOR: usize = 2048;
/// El Torito Boot Record Volume Descriptor: LBA 17 = byte 34816 (0x8800).
pub const EL_TORITO_BRVD_OFFSET: usize = 34816;
/// MBR boot signature 0x55 0xAA lives at byte 510 (0x1FE).
pub const MBR_SIG_OFFSET: usize = 510;
/// MBR partition table (4 × 16-byte entries) starts at byte 446 (0x1BE).
pub const MBR_PARTITION_TABLE_OFFSET: usize = 446;
/// GPT header "EFI PART" at byte 512 on 512-byte-logical disks.
pub const GPT_HEADER_OFFSET_512: usize = 512;
/// GPT header "EFI PART" at byte 4096 on 4Kn disks.
pub const GPT_HEADER_OFFSET_4K: usize = 4096;
/// ext2/3/4 superblock magic (0xEF53, little-endian) at byte 1080 (0x438).
pub const EXT_MAGIC_OFFSET: usize = 1080;

pub const ISO9660_MAGIC: &[u8; 5] = b"CD001";
pub const UDF_NSR02: &[u8; 5] = b"NSR02";
pub const UDF_NSR03: &[u8; 5] = b"NSR03";
pub const UDF_BEA01: &[u8; 5] = b"BEA01";
pub const UDF_TEA01: &[u8; 5] = b"TEA01";
pub const EL_TORITO_ID: &[u8] = b"EL TORITO SPECIFICATION";
pub const GPT_MAGIC: &[u8; 8] = b"EFI PART";
/// WIM header magic: "MSWIM\0\0\0". Shared by install.wim and install.esd.
pub const WIM_MAGIC: &[u8; 8] = b"MSWIM\0\0\0";
/// wimlib pipable WIM variant.
pub const WIM_PIPABLE_MAGIC: &[u8; 8] = b"WLPWM\0\0\0";

// ---- Compression wrappers (all at offset 0) -----------------------------

/// A compression wrapper detected at the head of the stream.
///
/// Detection is by magic bytes, **not** file extension — this is the
/// correctness fix over caligula's extension-only classifier: a gzip stream
/// named `image.img` must still be recognized as compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Gzip,
    Xz,
    Zstd,
    Bzip2,
    Lz4,
    /// 7z is a container archive, not a raw stream — handled differently.
    SevenZip,
}

impl Compression {
    /// Human-readable name for messages.
    pub fn name(self) -> &'static str {
        match self {
            Compression::Gzip => "gzip",
            Compression::Xz => "xz",
            Compression::Zstd => "zstd",
            Compression::Bzip2 => "bzip2",
            Compression::Lz4 => "lz4",
            Compression::SevenZip => "7z",
        }
    }

    /// True for stream formats we can decompress on the fly. 7z is a container
    /// (random-access archive), so it is *not* a streamable wrapper.
    pub fn is_streamable(self) -> bool {
        !matches!(self, Compression::SevenZip)
    }
}

/// Detect a compression wrapper by the leading magic bytes.
pub fn detect_compression(head: &[u8]) -> Option<Compression> {
    if starts_with(head, &[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
        return Some(Compression::Xz);
    }
    if starts_with(head, &[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some(Compression::Zstd);
    }
    if starts_with(head, &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some(Compression::SevenZip);
    }
    if starts_with(head, &[0x04, 0x22, 0x4D, 0x18]) {
        return Some(Compression::Lz4);
    }
    // gzip: 1F 8B, then a compression-method byte (08 = deflate in practice).
    if starts_with(head, &[0x1F, 0x8B]) {
        return Some(Compression::Gzip);
    }
    // bzip2: "BZh" then a block-size digit '1'..='9'.
    if starts_with(head, b"BZh") && head.get(3).is_some_and(|b| (b'1'..=b'9').contains(b)) {
        return Some(Compression::Bzip2);
    }
    None
}

// ---- ISO 9660 / UDF ------------------------------------------------------

/// True if an ISO 9660 Primary Volume Descriptor identifier is present.
pub fn has_iso9660(buf: &[u8]) -> bool {
    region(buf, ISO9660_MAGIC_OFFSET, 5) == Some(&ISO9660_MAGIC[..])
}

/// Scan the Volume Recognition Sequence for a UDF NSR descriptor.
///
/// The VRS is a run of 2048-byte descriptors starting at 0x8000; each begins
/// with a 1-byte structure type followed by a 5-byte standard identifier. We
/// walk descriptors until a terminator or a gap, capped to keep it bounded.
pub fn has_udf(buf: &[u8]) -> bool {
    // NSR02 = UDF, NSR03 = UDF 2.00+. CD001 alongside NSR = UDF-bridge.
    for k in 0..16 {
        let off = VRS_START + k * ISO_SECTOR;
        let Some(id) = region(buf, off + 1, 5) else {
            break;
        };
        if id == &UDF_NSR02[..] || id == &UDF_NSR03[..] {
            return true;
        }
    }
    false
}

// ---- El Torito -----------------------------------------------------------

/// El Torito boot information extracted from the Boot Record Volume Descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElTorito {
    /// LBA of the boot catalog (bytes 71..75 of the BRVD, LE u32).
    pub catalog_lba: u32,
}

/// Detect the El Torito Boot Record Volume Descriptor at LBA 17.
///
/// Layout: byte 0 = 0x00, bytes 1..6 = "CD001", bytes 7..39 = the boot system
/// identifier "EL TORITO SPECIFICATION" (null-padded), bytes 71..75 = catalog LBA.
pub fn el_torito(buf: &[u8]) -> Option<ElTorito> {
    let brvd = region(buf, EL_TORITO_BRVD_OFFSET, 75)?;
    if brvd[0] != 0x00 {
        return None;
    }
    if brvd[1..6] != ISO9660_MAGIC[..] {
        return None;
    }
    // The boot system identifier field is 32 bytes; match the leading id text.
    if !brvd[7..39].starts_with(EL_TORITO_ID) {
        return None;
    }
    let catalog_lba = u32::from_le_bytes([brvd[71], brvd[72], brvd[73], brvd[74]]);
    Some(ElTorito { catalog_lba })
}

// ---- MBR -----------------------------------------------------------------

/// A single MBR partition-table entry (16 bytes at 446 + i*16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrPartition {
    /// Status/bootable flag (0x80 = active).
    pub status: u8,
    /// Partition type byte (0xEE = GPT protective, 0xEF = ESP marker).
    pub part_type: u8,
    /// Starting LBA (LE u32 at entry offset +8).
    pub start_lba: u32,
    /// Sector count (LE u32 at entry offset +12).
    pub sectors: u32,
}

impl MbrPartition {
    /// A non-empty entry points somewhere and has a type.
    pub fn is_used(&self) -> bool {
        self.part_type != 0 && (self.start_lba != 0 || self.sectors != 0)
    }
    /// 0xEE: the protective partition that signals a GPT disk.
    pub fn is_gpt_protective(&self) -> bool {
        self.part_type == 0xEE
    }
    /// 0xEF: an EFI System Partition marker in the MBR (isohybrid UEFI).
    pub fn is_esp(&self) -> bool {
        self.part_type == 0xEF
    }
}

/// True if the 0x55AA boot signature is present at byte 510.
pub fn mbr_signature(buf: &[u8]) -> bool {
    region(buf, MBR_SIG_OFFSET, 2) == Some(&[0x55, 0xAA])
}

/// Parse the four MBR partition-table entries. Returns `None` if the buffer is
/// too short to contain the table.
pub fn mbr_partitions(buf: &[u8]) -> Option<[MbrPartition; 4]> {
    let table = region(buf, MBR_PARTITION_TABLE_OFFSET, 64)?;
    let mut out = [MbrPartition {
        status: 0,
        part_type: 0,
        start_lba: 0,
        sectors: 0,
    }; 4];
    for (i, entry) in out.iter_mut().enumerate() {
        let e = &table[i * 16..i * 16 + 16];
        *entry = MbrPartition {
            status: e[0],
            part_type: e[4],
            start_lba: u32::from_le_bytes([e[8], e[9], e[10], e[11]]),
            sectors: u32::from_le_bytes([e[12], e[13], e[14], e[15]]),
        };
    }
    Some(out)
}

/// True if there is a valid MBR (0x55AA) with at least one used partition entry.
pub fn has_mbr_partition_table(buf: &[u8]) -> bool {
    if !mbr_signature(buf) {
        return false;
    }
    mbr_partitions(buf).is_some_and(|p| p.iter().any(|e| e.is_used()))
}

// ---- GPT -----------------------------------------------------------------

/// True if a GPT header ("EFI PART") is present at the given logical block size.
///
/// The primary GPT header sits at LBA 1: byte 512 on 512-byte-logical disks,
/// byte 4096 on 4Kn disks. We check both common layouts.
pub fn has_gpt(buf: &[u8]) -> bool {
    region(buf, GPT_HEADER_OFFSET_512, 8) == Some(&GPT_MAGIC[..])
        || region(buf, GPT_HEADER_OFFSET_4K, 8) == Some(&GPT_MAGIC[..])
}

// ---- Bare filesystems (image with no partition table) --------------------

/// A filesystem recognized directly at offset 0 (a partitionless fs image).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemHint {
    Fat,
    Ntfs,
    Ext,
}

/// True if the head looks like a FAT/NTFS boot sector: a jump instruction
/// (EB xx 90 or E9 xx xx) at offset 0 plus the 0x55AA signature at 510.
pub fn is_fat_or_ntfs_bootsector(buf: &[u8]) -> bool {
    let Some(head) = region(buf, 0, 3) else {
        return false;
    };
    let jump = (head[0] == 0xEB && head[2] == 0x90) || head[0] == 0xE9;
    jump && mbr_signature(buf)
}

/// True if `buf` is an NTFS boot sector ("NTFS    " OEM id at offset 3).
pub fn is_ntfs_bootsector(buf: &[u8]) -> bool {
    is_fat_or_ntfs_bootsector(buf) && region(buf, 3, 8) == Some(b"NTFS    ")
}

/// True if the ext2/3/4 superblock magic (0xEF53 LE) is at byte 1080.
pub fn is_ext(buf: &[u8]) -> bool {
    region(buf, EXT_MAGIC_OFFSET, 2) == Some(&[0x53, 0xEF])
}

// ---- WIM -----------------------------------------------------------------

/// True if the head is a Windows Imaging Format file (install.wim/.esd).
///
/// Checked as the exact 8-byte magic (not a 4-byte "MSWM"): install.esd shares
/// the same magic as install.wim, differing only in compression flags.
pub fn is_wim(buf: &[u8]) -> bool {
    let Some(head) = region(buf, 0, 8) else {
        return false;
    };
    head == &WIM_MAGIC[..] || head == &WIM_PIPABLE_MAGIC[..]
}

// ---- helpers -------------------------------------------------------------

/// Borrow `len` bytes at `offset`, or `None` if out of range.
fn region(buf: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    buf.get(offset..offset.checked_add(len)?)
}

/// True if `buf` begins with `prefix`.
fn starts_with(buf: &[u8], prefix: &[u8]) -> bool {
    buf.len() >= prefix.len() && &buf[..prefix.len()] == prefix
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a zero-filled buffer of `len` bytes with `bytes` written at `at`.
    fn buf_with(len: usize, at: usize, bytes: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; len];
        v[at..at + bytes.len()].copy_from_slice(bytes);
        v
    }

    // ---- compression ----

    #[test]
    fn detects_each_compression_magic() {
        assert_eq!(
            detect_compression(&[0x1F, 0x8B, 0x08]),
            Some(Compression::Gzip)
        );
        assert_eq!(
            detect_compression(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]),
            Some(Compression::Xz)
        );
        assert_eq!(
            detect_compression(&[0x28, 0xB5, 0x2F, 0xFD]),
            Some(Compression::Zstd)
        );
        assert_eq!(detect_compression(b"BZh9"), Some(Compression::Bzip2));
        assert_eq!(
            detect_compression(&[0x04, 0x22, 0x4D, 0x18]),
            Some(Compression::Lz4)
        );
        assert_eq!(
            detect_compression(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
            Some(Compression::SevenZip)
        );
    }

    #[test]
    fn bzip2_requires_valid_block_size_digit() {
        assert_eq!(detect_compression(b"BZh0"), None); // '0' is not 1..=9
        assert_eq!(detect_compression(b"BZhx"), None);
        assert_eq!(detect_compression(b"BZh1"), Some(Compression::Bzip2));
    }

    #[test]
    fn no_compression_on_plain_bytes() {
        assert_eq!(detect_compression(&[0x00, 0x01, 0x02, 0x03]), None);
        assert_eq!(detect_compression(&[]), None);
    }

    #[test]
    fn seven_zip_is_not_streamable() {
        assert!(!Compression::SevenZip.is_streamable());
        assert!(Compression::Gzip.is_streamable());
    }

    // ---- ISO 9660 / UDF ----

    #[test]
    fn detects_iso9660_magic() {
        let buf = buf_with(40 * 1024, ISO9660_MAGIC_OFFSET, ISO9660_MAGIC);
        assert!(has_iso9660(&buf));
    }

    #[test]
    fn no_iso9660_when_absent_or_short() {
        assert!(!has_iso9660(&vec![0u8; 40 * 1024]));
        assert!(!has_iso9660(&[0u8; 100])); // too short to reach 0x8001
    }

    #[test]
    fn detects_udf_nsr() {
        // NSR03 in the second VRS descriptor, magic at +1.
        let off = VRS_START + ISO_SECTOR + 1;
        let buf = buf_with(40 * 1024, off, UDF_NSR03);
        assert!(has_udf(&buf));
    }

    #[test]
    fn no_udf_without_nsr() {
        let buf = buf_with(40 * 1024, ISO9660_MAGIC_OFFSET, ISO9660_MAGIC);
        assert!(!has_udf(&buf));
    }

    // ---- El Torito ----

    #[test]
    fn detects_el_torito_and_reads_catalog_lba() {
        let mut buf = vec![0u8; 40 * 1024];
        let o = EL_TORITO_BRVD_OFFSET;
        buf[o] = 0x00;
        buf[o + 1..o + 6].copy_from_slice(ISO9660_MAGIC);
        buf[o + 7..o + 7 + EL_TORITO_ID.len()].copy_from_slice(EL_TORITO_ID);
        buf[o + 71..o + 75].copy_from_slice(&0x1234u32.to_le_bytes());
        assert_eq!(
            el_torito(&buf),
            Some(ElTorito {
                catalog_lba: 0x1234
            })
        );
    }

    #[test]
    fn no_el_torito_with_wrong_identifier() {
        let mut buf = vec![0u8; 40 * 1024];
        let o = EL_TORITO_BRVD_OFFSET;
        buf[o] = 0x00;
        buf[o + 1..o + 6].copy_from_slice(ISO9660_MAGIC);
        // no "EL TORITO SPECIFICATION" text
        assert_eq!(el_torito(&buf), None);
    }

    // ---- MBR ----

    #[test]
    fn detects_mbr_signature() {
        let buf = buf_with(512, MBR_SIG_OFFSET, &[0x55, 0xAA]);
        assert!(mbr_signature(&buf));
    }

    #[test]
    fn parses_mbr_partition_entry() {
        let mut buf = vec![0u8; 512];
        buf[MBR_SIG_OFFSET] = 0x55;
        buf[MBR_SIG_OFFSET + 1] = 0xAA;
        let e = MBR_PARTITION_TABLE_OFFSET;
        buf[e] = 0x80; // active
        buf[e + 4] = 0x83; // Linux
        buf[e + 8..e + 12].copy_from_slice(&2048u32.to_le_bytes());
        buf[e + 12..e + 16].copy_from_slice(&1_000_000u32.to_le_bytes());
        let parts = mbr_partitions(&buf).unwrap();
        assert_eq!(parts[0].status, 0x80);
        assert_eq!(parts[0].part_type, 0x83);
        assert_eq!(parts[0].start_lba, 2048);
        assert_eq!(parts[0].sectors, 1_000_000);
        assert!(parts[0].is_used());
        assert!(has_mbr_partition_table(&buf));
    }

    #[test]
    fn signature_without_partitions_is_not_a_table() {
        // 0x55AA present but all entries empty (e.g. a bare FAT boot sector).
        let buf = buf_with(512, MBR_SIG_OFFSET, &[0x55, 0xAA]);
        assert!(mbr_signature(&buf));
        assert!(!has_mbr_partition_table(&buf));
    }

    #[test]
    fn recognizes_gpt_protective_and_esp_types() {
        let mut p = MbrPartition {
            status: 0,
            part_type: 0xEE,
            start_lba: 1,
            sectors: 100,
        };
        assert!(p.is_gpt_protective());
        p.part_type = 0xEF;
        assert!(p.is_esp());
    }

    // ---- GPT ----

    #[test]
    fn detects_gpt_at_512_and_4k() {
        assert!(has_gpt(&buf_with(1024, GPT_HEADER_OFFSET_512, GPT_MAGIC)));
        assert!(has_gpt(&buf_with(5000, GPT_HEADER_OFFSET_4K, GPT_MAGIC)));
    }

    // ---- bare filesystems ----

    #[test]
    fn detects_fat_bootsector() {
        let mut buf = vec![0u8; 512];
        buf[0] = 0xEB;
        buf[2] = 0x90;
        buf[MBR_SIG_OFFSET] = 0x55;
        buf[MBR_SIG_OFFSET + 1] = 0xAA;
        assert!(is_fat_or_ntfs_bootsector(&buf));
        assert!(!is_ntfs_bootsector(&buf));
    }

    #[test]
    fn detects_ntfs_bootsector() {
        let mut buf = vec![0u8; 512];
        buf[0] = 0xEB;
        buf[2] = 0x90;
        buf[3..11].copy_from_slice(b"NTFS    ");
        buf[MBR_SIG_OFFSET] = 0x55;
        buf[MBR_SIG_OFFSET + 1] = 0xAA;
        assert!(is_ntfs_bootsector(&buf));
    }

    #[test]
    fn detects_ext_superblock() {
        assert!(is_ext(&buf_with(2048, EXT_MAGIC_OFFSET, &[0x53, 0xEF])));
        assert!(!is_ext(&vec![0u8; 2048]));
    }

    // ---- WIM ----

    #[test]
    fn detects_wim_magic() {
        assert!(is_wim(WIM_MAGIC));
        assert!(is_wim(WIM_PIPABLE_MAGIC));
        assert!(!is_wim(b"NOTAWIM!"));
        assert!(!is_wim(&[0u8; 4])); // too short
    }
}
