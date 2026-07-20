# Rufus → Lufus Porting Spec: `img_report` + decision logic

Source: `~/Lufus/rufus/src/` (`rufus.h`, `iso.c`, `vhd.c`, `format.c`, `drive.c`, `format_fat32.c`, `rufus.c`).

This is the **single source of truth** model. Rufus mutates one global `img_report`
struct while scanning, then every downstream decision (filesystem, partition scheme,
boot method) reads from it. Lufus reproduces this as `ImgReport` in `lufus-core`.

## 1. The `ImgReport` struct (from rufus.h:432-481)

```rust
pub const MAX_WININST: usize = 4;
pub const NB_OLD_C32: usize = 2;

#[derive(Default, Clone)]
pub struct WinVer { pub major: u16, pub minor: u16, pub build: u16, pub revision: u16 }

#[derive(Clone)]
pub struct EfiBootEntry { pub kind: EfiBootType, pub path: String } // EBT_MAIN/GRUB/MOKMANAGER/BOOTMGR

#[derive(Default, Clone)]
pub struct ImgReport {
    pub label: String,
    pub usb_label: String,
    pub cfg_path: String,
    pub reactos_path: String,
    pub wininst_path: Vec<String>,          // <= MAX_WININST
    pub efi_boot_entry: Vec<EfiBootEntry>,  // <= 64
    pub efi_img_path: String,
    pub image_size: u64,
    pub projected_size: u64,
    pub mismatch_size: i64,
    pub wininst_version: u32,
    pub is_iso: bool,
    pub is_bootable_img: i8,                 // 0 non / 1 bootable / 2 forced ; negatives = error
    pub is_vhd: bool,
    pub is_windows_img: bool,                // first 8 bytes == WIM magic
    pub disable_iso: bool,                   // force DD-only; ISO mode broken for this image
    pub rh8_derivative: bool,
    pub winpe: u16,                          // WINPE_I386/AMD64/MININT bitmask
    pub has_efi: u16,                        // bitmask, see §3
    pub has_secureboot_bootloader: u8,
    pub has_md5sum: u8,                      // 1 = md5sum.txt, 2 = MD5SUMS
    pub wininst_index: u8,
    pub has_symlinks: u8,                    // SYMLINKS_RR=0x01, SYMLINKS_UDF=0x02
    pub has_4gb_file: u8,                    // packed counter+flags, note 0x11 ; see §4
    pub has_long_filename: bool,
    pub has_deep_directories: bool,
    pub has_bootmgr: bool,                   // root bootmgr (BIOS)
    pub has_bootmgr_efi: bool,               // root bootmgr.efi
    pub has_autorun: bool,
    pub has_old_c32: [bool; NB_OLD_C32],
    pub has_old_vesamenu: bool,
    pub has_efi_syslinux: bool,
    pub has_grub4dos: bool,                  // root grldr
    pub has_grub2: u8,                       // low7=BIOS dir variant, 0x80=EFI grub present
    pub has_grub2_fs: u8,                    // bit per fs driver (FAT=0x1, exFAT=0x2, NTFS=0x4)
    pub has_compatresources_dll: bool,
    pub has_panther_unattend: bool,
    pub has_kolibrios: bool,
    pub needs_syslinux_overwrite: bool,
    pub needs_ntfs: bool,                    // requires NTFS (working symlinks; Mint LMDE)
    pub uses_casper: bool,
    pub uses_minint: bool,
    pub compression_type: u8,
    pub win_version: WinVer,
    pub sl_version: u16,                     // syslinux/isolinux version
    pub sl_version_str: String,
    pub sl_version_ext: String,
    pub grub2_version: String,
}
```

## 2. Derived predicates (rufus.h:370-395) — port as methods on ImgReport

- `HAS_KOLIBRIOS = has_kolibrios`
- `HAS_REACTOS = !reactos_path.is_empty()`
- `HAS_GRUB = has_grub2 != 0 || has_grub4dos`
- `HAS_SYSLINUX = sl_version != 0`
- `HAS_BOOTMGR = has_bootmgr || has_bootmgr_efi`
- `HAS_REGULAR_EFI = has_efi & 0x7FFE`  (any EFI bit except bit0 bootmgr.efi + bit15 efi.img-only)
- `HAS_WININST = wininst_index != 0`
- `HAS_WINPE = winpe & (WINPE_I386|AMD64|MININT)`
- `HAS_WINDOWS = HAS_BOOTMGR || uses_minint || HAS_WINPE`
- `HAS_WIN7_EFI = (has_efi==1) && HAS_WININST`
- `HAS_FATLESS_GRUB = (has_grub2 & 0x80) && !(has_grub2_fs & 0x1)`
- `HAS_NTFSLESS_GRUB = (has_grub2 & 0x80) && !(has_grub2_fs & 0x4)`
- `IS_WINDOWS_1X = has_bootmgr_efi && win_version.major>=10`
- `IS_WINDOWS_11 = has_bootmgr_efi && win_version.major>=11`
- `IS_FAT32_COMPAT = ((has_4gb_file==0 && !HAS_FATLESS_GRUB) || (has_4gb_file==0x11 && allow_dual_uefi_bios)) && !needs_ntfs`
- `IS_DD_BOOTABLE = is_bootable_img > 0`
- `IS_DD_ONLY = (is_bootable_img > 0) && (!is_iso || disable_iso)`
- `IS_EFI_BOOTABLE = has_efi != 0`
- `IS_BIOS_BOOTABLE = HAS_BOOTMGR || HAS_SYSLINUX || HAS_WINPE || HAS_GRUB || HAS_REACTOS || HAS_KOLIBRIOS`
- `HAS_WINTOGO = HAS_BOOTMGR && IS_EFI_BOOTABLE && HAS_WININST`
- `HAS_PERSISTENCE = (HAS_SYSLINUX || HAS_GRUB) && !(HAS_WINDOWS || HAS_REACTOS || HAS_KOLIBRIOS)`

## 3. DD-vs-ISO decision + disable_iso blocklist (rufus.c:1398-1441)

`IsBootableImage` (vhd.c:164): tri-state i8. Checks compressed formats first (bled),
then `AnalyzeMBR` = boot marker `buf[0x1FE]==0x55 && buf[0x1FF]==0xAA`. WIM magic =
little-endian u64 `0x0000004D4957534D` ("MSWIM\0\0\0").

After scan, for is_iso images:
1. RHEL8-derivative regex on label → `rh8_derivative` (`^OL-[8-9]`, `^RHEL-[8-9]`, `^Rocky-[8-9]`, `^MIRACLE-LINUX-[8-9]`).
2. **SUSE blocklist** (label prefix): `Install-SUSE`, `Install-LEAP`, `openSUSE-Tumbleweed` → `disable_iso`.
3. **FS-incapable EFI-GRUB**: if `(has_grub2 & 0x80)` and grub lacks needed fs driver → `disable_iso`.
4. **ISOHybrid fallback**: if `IS_DD_BOOTABLE && (disable_iso || (!BIOS && !EFI))` → force `is_iso=false` (DD enforced).

Scan-time disable_iso: Pop!_OS (`/casper`+`pop-os`), Proxmox (`/proxmox`), Manjaro (`.miso`).
Final gate: `!IS_DD_BOOTABLE && !IS_BIOS_BOOTABLE && !IS_EFI_BOOTABLE` → reject as unsupported.

## 4. has_4gb_file packing + install.wim split

- Low nibble (0-3) = **counter** of ≥4GB files, capped 0x0f.
- High nibble bit `0x10<<i` = the i-th `install.{wim,esd,swm}` in `*/sources` is ≥4GB.
- `0x11` = exactly "count==1 AND that file is install.wim" → splittable-only case.
- Split at write time: `WimSplitFile` → `wimlib_split(wim, dst, 4094 MiB, FSYNC)`. **4094 MiB** parts.
- Custom large-FAT32 formatter mandatory > 32GB (`LARGE_FAT32_SIZE`) and for ESP; Windows API refuses FAT32 > 32GB.

## 5. Write pipeline order (format.c:1445 FormatThread)

1. Compute extra partitions (persistence / ESP+MSR / UEFI:NTFS / compat).
2. Lock physical drive; remove drive letters.
3. Delete partitions (VDS).
4. **ClearMBRGPT** — zero head (8MB/512 sectors) AND tail (/8 sectors) — secondary GPT at `DiskSize - 33 sectors`.
5. Optional bad-blocks pass → re-zero MBR/GPT afterward.
6. If write_as_image → WriteDrive raw, done.
7. CreatePartition (see 04 for alignment).
8. Format persistence (ext) partition FIRST, then main partition.
9. **WriteMBR AFTER format** (Windows format rewrites MBR; fix type bytes 0x1c2 + bootable 0x1be).
10. Remount volume.
11. Boot setup / file copy / patch / finalize.

### WriteDrive raw writer (format.c:1151)
- `target_size = min(DiskSize, image_size)` — clamp to image.
- DD_BUFFER_SIZE 32MB, `_mm_malloc` sector-aligned, sizes rounded up to sector multiple.
- Fast-zeroing: skip blocks where every u32 word identical AND == 0x00000000 or 0xFFFFFFFF.
- Write retries: WRITE_RETRIES=4, WRITE_TIMEOUT=5000ms, seek back to block offset on retry.
- VHD read clamp: reads past mounted-VHD end corrupt earlier sectors too.

## Edge cases a naive port misses
See the research report; key ones: has_4gb_file is packed not bool; has_efi bit layout;
has_grub2 byte overload; WIM magic is u64 LE; head+tail MBR zero; WriteMBR after format;
fast-zeroing only 0x00/0xFF; split size 4094 MiB; custom FAT32 formatter > 32GB;
distro blocklists in 3 phases; ext partition formatted before main; locking relaxed on Win11.
