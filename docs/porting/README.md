# Lufus Porting & Research Docs

These documents capture the source-level analysis of the reference tools that Lufus
draws its logic from. Each spec is tied to real `file:line` references in the local
clones under `~/Lufus/` (siblings of this repo). They are the implementation contract
for `lufus-core`.

## Reference repos analysed (in `~/Lufus/`)

| Repo | Language | What Lufus takes from it |
|------|----------|--------------------------|
| `rufus` | C | The whole image-intelligence model: `img_report`, DD/ISO decision, `disable_iso` blocklist, WIM split, UEFI:NTFS, large-FAT32 formatter |
| `caligula` | Rust | Raw write engine (O_DIRECT + aligned buffers + read-back verify), privileged-helper re-exec + stdio RPC, escalation detection |
| `popsicle` | Rust | Workspace layout (core lib + frontends), srmw multi-writer fan-out, UDisks2 delegation (optional Linux backend) |
| `WoeUSB` / `WoeUSB-ng` | Bash / Python | Windows-on-Linux path step-by-step, FAT→NTFS auto-switch, Win7 workaround, GRUB config |
| `etcher-sdk` / `drivelist` | TS / C++ | SourceDestination abstraction, hash-while-write + read-back verify, system-drive safety, anti-automount trick |
| `uefi-ntfs` | C | UEFI:NTFS boot chain + the `uefi-ntfs.img` to bundle |
| `rs-drivelist` | Rust | Cross-platform enumeration reference (wrap, don't depend directly) |

## Spec documents

- [`01-rufus-image-model.md`](01-rufus-image-model.md) — `img_report`, detection rules, DD/ISO decision, FAT32/WIM, write pipeline
- [`02-device-io-safety.md`](02-device-io-safety.md) — enumeration, write/verify ordering per OS, safety layers, hashing (from etcher/drivelist + caligula/popsicle)
- [`03-woeusb-windows-path.md`](03-woeusb-windows-path.md) — the Windows bootable-USB path, subprocess-vs-Rust map, uefi-ntfs bundling
- [`04-iso-detection-tree.md`](04-iso-detection-tree.md) — image-type detection tree, magic bytes, BSD ISO-vs-IMG, edge-case checklist

## Key cross-cutting decisions

- **Workspace:** `core` (all logic) + `cli` (ships first) + `gui` (egui, deferred) + `helper` (privileged worker).
- **Privilege:** caligula-style re-exec'd privileged child + bincode RPC over stdio (generalises to Win/Linux/BSD). UDisks2 is an optional Linux backend, not the foundation.
- **Compression detection:** magic-byte sniffing, NOT extension-only (fixes a real caligula bug).
- **Subprocess policy:** zero on Linux/BSD raw-write path. Windows path shells out only for NTFS format (`mkntfs`), WIM split (`wimlib`), and UDF/Joliet reads (`7z`/libarchive) — no mature pure-Rust equivalents.
- **uefi-ntfs.img:** bundle via `include_bytes!`, never download at runtime (WoeUSB-ng's runtime download is a known failure mode).
