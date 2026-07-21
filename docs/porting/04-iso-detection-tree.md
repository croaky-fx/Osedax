# Image-Type Detection Tree & Edge Cases

The core intelligence of Osedax. Read ~40 KB of the head plus targeted regions; decide
handling before touching any device. Probe windows: `0..512` (MBR/boot sector),
byte `512` (GPT), `32768..34816` (ISO/UDF VRS + El Torito).

## Decision order (compression → partition tables → filesystem magics)

```
STEP 0  Compression wrapper (offset 0) — sniff by MAGIC, not extension
  FD 37 7A 58 5A 00      -> xz
  1F 8B [08]             -> gzip   (length field unreliable for >4 GB)
  28 B5 2F FD            -> zstd
  42 5A 68 ("BZh")       -> bzip2
  04 22 4D 18            -> lz4 (frame)
  37 7A BC AF 27 1C      -> 7z (container, not a raw stream)
  => decompress head, re-run STEP 1+ on inner bytes. Final size unknown until
     fully decompressed (capacity check deferred).

STEP 1  ISO 9660 / UDF
  offset 32769 (0x8001), 5 bytes == "CD001"  -> ISO 9660 present
    scan VRS at 0x8000 + k*2048, magic at +1:
      "NSR02"/"NSR03" -> UDF (or UDF-bridge if CD001 also present) -> likely Windows/large ISO
      "BOOT2"         -> boot descriptor present
    then STEP 1a.

STEP 1a  Is the ISO HYBRID (dd-able to USB)?  <-- THE critical branch
  byte 510-511 == 55 AA AND non-empty MBR partition table at 446
     -> BIOS-hybrid (dd-able for legacy boot)
  byte 512 == "EFI PART" OR MBR entry type 0xEF/0xEE
     -> UEFI-hybrid (dd-able for UEFI boot)
  inspect El Torito (1b) for a platform-0xEF (UEFI) boot entry.
  IF neither MBR-with-partitions nor GPT/ESP present:
     -> PLAIN ISO 9660, optical-only. dd to USB will very likely NOT boot. (BSD warning path)

STEP 1b  El Torito (optical boot catalog)
  Boot Record VD at LBA 17 = byte 34816 (0x8800):
     byte 0 == 0x00, bytes 1-5 == "CD001", bytes 7-38 == "EL TORITO SPECIFICATION"
     bytes 71-74 (LE u32) = boot-catalog LBA
  Validation entry: byte0=0x01, byte1=platform (00=x86,01=PPC,02=Mac,EF=EFI), byte30=0x55, byte31=0xAA
  Initial entry: byte0 0x88=bootable, byte1 media type (00=no-emul, 04=HDD-emul)

STEP 2  Windows install media (only once ISO/UDF confirmed)
  /sources/{install.wim|install.esd|install.swm}  -> Windows install payload
  /bootmgr (root)      -> BIOS boot
  /bootmgr.efi (root)  -> UEFI boot
  /efi/**/boot{x64,ia32,aa64}.efi -> UEFI bootloader
  WIM magic (inside install.wim): offset 0 == "MSWIM\0\0\0" (4D 53 57 49 4D 00 00 00)
  install.wim >= 4 GiB + FAT target -> must split to .swm OR use NTFS+UEFI:NTFS

STEP 3  Raw disk image (.img)
  byte 510-511 == 55 AA + valid MBR entries at 446   -> MBR disk image
  byte 512 == "EFI PART"                             -> GPT disk image
  else bare filesystem at offset 0:
     EB xx 90 / E9 xx xx (+55 AA at 510) -> FAT/NTFS boot sector
     0xEF53 at byte 1080 (0x438)         -> ext2/3/4
  -> raw image, dd-able as-is.

STEP 4  Unknown -> refuse auto-burn; require explicit user override + extension hint.
```

## Magic bytes / offsets reference

| Format | Offset (dec / hex) | Bytes | Notes |
|---|---|---|---|
| ISO 9660 "CD001" | 32769 / 0x8001 | `43 44 30 30 31` | VD at LBA 16; byte0=VD type, bytes1-5=id, byte6=version 0x01 |
| ISO system area | 0-32767 | reserved | 16 × 2048 B; where isohybrid writes the MBR |
| El Torito BRVD | 34816 / 0x8800 | `00`+`CD001`+`"EL TORITO SPECIFICATION"` | catalog LBA at bytes 71-74 (LE u32) |
| UDF VRS | 0x8000+, magic at +1 | `NSR02`/`NSR03` | NSR03 = UDF 2.00+; CD001+NSR = UDF-bridge |
| MBR boot signature | 510 / 0x1FE | `55 AA` | LE u16 reads 0xAA55 |
| MBR partition table | 446 / 0x1BE | 4 × 16 B | entry: +0 status(0x80=active), +4 type, +8 start LBA, +12 sector count |
| MBR type = GPT protective | entry +4 | `EE` | signals GPT present |
| MBR type = ESP (isohybrid EFI) | entry +4 | `EF` | UEFI hybrid marker |
| GPT header "EFI PART" | 512 / 0x200 (512n); 4096 (4Kn) | `45 46 49 20 50 41 52 54` | LE u64 0x5452415020494645 |
| ESP type GUID | in GPT entry | `28732AC1-1FF8-11D2-BA4B-00A0C93EC93B` | — |
| WIM (install.wim/esd) | 0 | `4D 53 57 49 4D 00 00 00` | wimlib-pipable = "WLPWM\0\0\0" |
| FAT boot sector | 0 | `EB ?? 90` or `E9 ?? ??` | fs-type label at 54/82 is display-only, don't key on it |
| ext2/3/4 superblock | 1080 / 0x438 | `53 EF` (LE of 0xEF53) | superblock at 1024, s_magic at +56 |
| gzip | 0 | `1F 8B [08]` | length unreliable >4 GB |
| xz | 0 | `FD 37 7A 58 5A 00` | — |
| zstd | 0 | `28 B5 2F FD` | — |
| bzip2 | 0 | `42 5A 68` | 4th byte = block size '1'-'9' |
| lz4 frame | 0 | `04 22 4D 18` | block format has NO magic |

Caveats: legacy `.lzma` (alone-format) has NO reliable magic (props byte, often `5D`) — fall back to
extension. Intra-PVD numeric fields use both-endian encoding (LE value then BE value); exact offsets
need ECMA-119.

## BSD ISO-vs-IMG (the user's explicit requirement)

BSD install ISOs are built for optical media and are generally NOT hybrid. Each BSD ships a
separate purpose-built USB image:

- **FreeBSD** — USB: `FreeBSD-<ver>-<arch>-memstick.img`. Optical: `-bootonly/-disc1/-dvd1.iso`.
- **OpenBSD** — USB: `install<XX>.img` / `miniroot<XX>.img`. Written to the RAW node `rsd6c`, not `sd6c`.
- **NetBSD** — USB: `install.img.gz` (decompress first). Optical: `.iso`.
- **DragonFly** — USB: `dfly-<arch>-<ver>_REL.img.bz2` (decompress first).

Trigger warning when: ISO 9660 present AND no MBR-with-partitions AND no GPT/ESP AND (optionally) no
El Torito platform-0xEF entry. Strengthen when filename/label matches a BSD pattern
(`disc1`/`dvd1`/`bootonly`, `install79.iso`, `NetBSD-*.iso`, `dfly-*_REL.iso`).

**Hard warning message (optical-only BSD ISO):** explain it's an optical ISO with no hybrid table,
name the vendor's dedicated USB image, and require an explicit confirm to proceed.

## Edge-case checklist (what separates Osedax from a naive dd)

1. Non-hybrid ISO written raw → silent no-boot. Detect via 1a; warn.
2. FAT32 4 GiB file limit vs install.wim. Split to `.swm` OR NTFS+UEFI:NTFS.
3. Device smaller than image → hard-block. For compressed, re-check after decompression.
4. System/mounted/source-disk protection. Refuse OS disk and the disk hosting the image. Whole-disk only (`/dev/sdb`, not `sdb1`).
5. Verify only up to the image's logical size (SHA-512 or xxh3); ignore trailing device data.
6. Alignment & sector size (512 vs 4Kn). Never hardcode 512; query real logical/physical size. Align partitions to 1 MiB.
7. Partition scheme MBR vs GPT + persistence (`casper-rw`).
8. Flush, don't just close (`oflag=sync`/`fdatasync`; `conv=sync` only NUL-pads).
9. Auto-mount races mid-write corrupt write+verify. Unmount before, prevent remount during verify.
10. Stale signatures / old partition tables → `wipefs -a` then re-read table.
11. Fake/counterfeit flash (over-reported capacity) → test-pattern bad-blocks pass.

## Verification notes (from research)

Load-bearing offsets confirmed by multiple primary sources (0x8000 ISO/UDF system area via libisofs+libblkid;
0x55AA@510 via libisofs+MBR spec; "EFI PART"@512 via libisofs+GPT spec; Windows markers from Rufus `iso.c`).
Corrections to early assumptions: Rufus keys Windows detection off `install.{wim,esd,swm}` under `/sources`
(not `boot.wim`); `install.esd` shares the `MSWIM` magic with `install.wim`.
