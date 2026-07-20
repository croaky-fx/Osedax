# WoeUSB → Lufus Windows-media path

Sources: `~/Lufus/WoeUSB-ng/src/WoeUSB/{core,utils,workaround}.py`, `~/Lufus/WoeUSB/sbin/woeusb`, `~/Lufus/uefi-ntfs/`.

## 0. Dependencies WoeUSB shells out to → Rust plan

| Tool | Purpose | Rust plan |
|---|---|---|
| mount/umount | mount source ISO + target FS | pure-Rust: parse ISO directly to avoid privileged mount; else subprocess |
| wipefs --all | erase FS/partition signatures | pure-Rust: zero known signature offsets |
| lsblk | enumerate + verify wipe | pure-Rust: sysfs + ioctl reread |
| blockdev --rereadpt | reload partition table | `ioctl(BLKRRPART)` |
| df | free-space | `statvfs` (nix) |
| parted | mklabel msdos, mkpart | **pure-Rust: write MBR directly** |
| mkdosfs | format FAT32 | **`fatfs` pure-Rust ✅** |
| mkntfs (ntfs-3g) | format NTFS | **subprocess — no mature pure-Rust ❌** |
| grub-install | BIOS bootloader | **subprocess — no pure-Rust ❌** |
| 7z | extract bootmgfw.efi from install.wim | pure-Rust WIM reader, or subprocess |
| wimlib-imagex split | split install.wim → .swm | wimlib FFI or subprocess (only if SWM mode chosen) |
| wget uefi-ntfs.img | download driver img | **BUNDLE via include_bytes! ✅** |

**Verdict:** Linux/BSD path can be ZERO subprocess. Windows-media path = pure Rust EXCEPT
`mkntfs`, `grub-install`, and (optionally) WIM split/`7z`. Far better than ng which shells out for everything.

## 1. Command sequence (core.py:116-207)

1. deps check → 2. unmount busy target → 3. mount source (loop,ro) →
4. **FAT→NTFS auto-switch** if any file > 2³²−1 (utils.py:169-188) →
5. `wipefs --all` → 6. **verify wipe** (count TYPE="part"; if >0 abort — dead flash) →
7. `parted mklabel msdos` (GPT UNSUPPORTED in WoeUSB — Lufus SHOULD add GPT) →
8. data partition at **4MiB** start (FAT: `4MiB 100%`; NTFS: `4MiB -- -2049s`) →
9. `blockdev --rereadpt` + **sleep 3** (Lufus: udev settle instead) →
10. format (FAT `-F 32` / NTFS `--quick`) →
11. UEFI:NTFS partition (NTFS only): `parted --align none mkpart primary fat16 -- -2048s -1s` →
12. write uefi-ntfs.img to partition 2 →
13. mount target → 14. free-space check → 15. copy files (chunked 5MiB) →
16. **Win7 UEFI workaround** → 17. `grub-install --target=i386-pc` (unless --skip-grub) →
18. write grub.cfg (`ntldr /bootmgr` + `boot`) → 19. optional boot-flag → 20. cleanup.

## 2. install.wim > 4GB — TWO strategies

- **A. Split to .swm** (bash only): `wimlib-imagex split <src> <dst>.swm 4095` → keeps FAT32.
- **B. NTFS + UEFI:NTFS** (ng): drop split, auto-switch FAT→NTFS, add trailing driver partition.

**Lufus default: B** (no wimlib dep, verbatim copy, UEFI:NTFS restores bootability).
Offer A as opt-in (pure-Rust WIM splitter or wimlib).

## 3. uefi-ntfs.img — BUNDLE it

- Small FAT partition with UEFI:NTFS bootloader + MS-signed NTFS drivers (GPLv2 ntfs-3g only under SB).
- Boot chain: firmware runs FAT partition's `boot<arch>.efi` → loads `\efi\rufus\ntfs_<arch>.efi`
  driver → finds NTFS partition → chainloads its `/efi/boot/boot<arch>.efi`.
- ng DOWNLOADS at runtime (network failure = non-bootable stick, silent) — **replace with `include_bytes!`**.
- Source the signed img from Rufus `res/uefi/uefi-ntfs.img`. Fits ~1MiB (2048-sector) trailing partition.

## 4. Windows-7 UEFI workaround (workaround.py:43-107)

Win7 puts bootmgfw.efi inside install.wim, not at /efi/boot/. Detect via
`grep '^MinServer=7[0-9]{3}\.' sources/cversion.ini` + bootmgr.efi present. If no /efi/boot/boot*.efi:
`7z e -so install.wim Windows/Boot/EFI/bootmgfw.efi` → write to `/efi/boot/bootx64.efi`.
Lufus: pure-Rust WIM reader preferred (drops 7z dep).

## 5. Critical edge cases

- **Data partition MUST be partition 1** — Windows only sees first partition on removable media; UEFI:NTFS is partition 2.
- **Verify-after-wipe**: count partitions after wipefs; if nonzero, flash silently ignored write (dead flash) → **abort** (ng has a bug: ignores the return value).
- **4MiB start**: GRUB post-MBR gap + flash erase-block alignment.
- NTFS ends at `-2049s`, UEFI:NTFS spans `-2048s..-1s` with `--align none`.
- ng warns-but-doesn't-abort on non-root → Lufus check capabilities up front.
- free-space adds fixed 10MB for GRUB; use `statvfs` not `df`/`awk`.
- GRUB legacy config is literally `ntldr /bootmgr` + `boot` (chainloads Windows MBR bootloader for BIOS).

## Boot story summary
- **BIOS**: GRUB in MBR → `ntldr /bootmgr` → Windows.
- **UEFI + FAT**: firmware directly boots `/efi/boot/bootx64.efi`.
- **UEFI + NTFS**: firmware boots small FAT UEFI:NTFS partition → NTFS driver → chainload NTFS partition's EFI loader.
