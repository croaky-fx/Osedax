# caligula + popsicle + etcher-sdk → Lufus core architecture

Sources: `~/Lufus/{caligula,popsicle,etcher-sdk,drivelist,rs-drivelist}/`.

## 1. Workspace layout (popsicle model, refined)

```
lufus/
├── Cargo.toml          # virtual workspace manifest, [workspace.dependencies]
├── core/   (lufus-core) # ALL logic: detect, enumerate, write, verify, ipc, codec
├── cli/    (lufus-cli)  # thin binary → `lufus`
├── gui/    (lufus-gui)  # egui, deferred (stub now)
└── helper/ (lufus-helper) # privileged worker (re-exec target)
```

- Use a dedicated `core/` member (not popsicle's dual-role root) — scales better.
- Frontends depend on core via `path`. `[[bin]] name = "lufus"` remaps binary name.
- All enumeration, write/verify engine, IPC/privilege, codecs live in `core/`.
- Prefer caligula's newer pins: anyhow 1.0.100, serde 1.0.228, libc 0.2.177, tokio 1.48.

## 2. Privilege model — ADOPT caligula's (only one that generalizes to Win/Linux/BSD)

**Re-exec a privileged child of self + bincode RPC over stdio.**
- Hidden `_herder` subcommand; parent finds own exe via `process_path`, spawns `<self> _herder <log>`.
- Transport: length-prefixed mux over stdio — frame = `u16 channel_id` + `u32 length` + payload, zero-length = EOF.
- On top: typed `HerderService`/`HerderAction` (Start/Event/Error assoc types), bincode
  `DefaultOptions::new().with_fixint_encoding().with_native_endian().with_limit(1024)`.
- Flashing action `WVAction { dest, src, verify, compression, target_type, block_size }`,
  events `WVEvent::{TotalBytes, FinishedWriting, Success, ...}`.

**Escalation** (`facade/escalation/unix.rs`): try `[Sudo, Doas, Run0, Su]` in order, detect by
`which(cmd).is_ok()`, render with `shell_words` (prevents injection). macOS = osascript.
Policy flag `--root ask/always/never` (default ask). Idempotent (no-op if child exists).
- Windows: `ShellExecuteW` with `runas` verb (UAC) — net-new.
- popsicle's UDisks2/D-Bus is Linux-desktop-only → optional Linux backend later, NOT foundation.

## 3. Write/verify engine — ADOPT caligula's I/O core

- Device open O_DIRECT (`OpenOptions.custom_flags(O_DIRECT)`); macOS `fcntl(F_NOCACHE)`;
  Windows `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH` (net-new arm).
- Aligned buffers: `aligned-vec` `avec_rt![[disk_block_size] | 0u8; buf_size]`.
- Write loop: always write ENTIRE aligned buffer even on short final read (O_DIRECT requires).
- Verify loop: read source block + disk block, `if file_buf[..n] != disk_buf[..n]` → VerificationFailed.
- Decoupling point: `tx: impl FnMut(Event)` callback — CLI → progress bar, GUI → channel send.

```rust
pub struct WriteOp<S: Read, D: Write> {
    pub file: S, pub disk: D, pub cf: CompressionFormat,
    pub buf_size: usize, pub disk_block_size: usize,
    pub checkpoint_period: usize, pub file_read_buf_size: usize,
}
impl<S: Read, D: Write> WriteOp<S, D> {
    pub fn execute(&mut self, tx: impl FnMut(Event)) -> Result<u64, Error> { /* aligned loop */ }
}
```

- popsicle's `srmw` (single-reader multi-writer) fan-out: adopt ONLY if parallel multi-USB is a requirement.

## 4. etcher-sdk contributions (it is BLIND to image type — take only these 4)

1. **hash-while-write + read-back verify** (xxh3, seed `b"ETCH"`): tee source into hasher while
   writing (single source read), then reopen device RO and hash back exactly `bytes_written`, compare.
   Crate: `xxhash-rust` (xxh3 feature). If cross-compat with etcher digests not needed, any fixed seed.
2. **Write first 64 KiB LAST** (`WIN32_FIRST_BYTES_TO_KEEP = 64KiB`): hold first chunk in memory,
   write it in `_final`. Prevents Windows/macOS auto-mounting mid-flash. **Most important behavior to port.**
3. **retry-on-transient**: 5 retries, 100ms*n backoff. Transient codes per-OS
   (linux EIO/EBUSY, win ENOENT/UNKNOWN/EBUSY, mac ENXIO/EBUSY).
4. **SourceDestination trait**: capability probes as `Option`-returning factories (None = NotCapable).

Close sequence: on unmount-on-success, `sleep(2s)` before unmount (closing fd re-mounts on macOS).

## 5. Two-layer safety (NOT in these repos — reconstruct; lives in Etcher app)

```rust
pub enum WriteRefusal { SystemDrive, SourceOnTarget, TooSmall{need:u64,have:u64}, ReadOnly }

pub fn check_write_allowed(d: &Device, image_path: &Path, image_size: u64, force_unsafe: bool)
    -> Result<(), WriteRefusal>
{
    if d.is_read_only { return Err(ReadOnly); }
    if is_source_drive(d, image_path) { return Err(SourceOnTarget); } // HARD, no override
    if d.size < image_size { return Err(TooSmall{need:image_size, have:d.size}); }
    if d.is_system && !force_unsafe { return Err(SystemDrive); }      // override via --force
    Ok(())
}
```
- `is_source_drive`: canonicalize image path, check `img.starts_with(mountpoint)` for each target mountpoint.
- Linux O_EXCL on block device = kernel-enforced third net (fails if mounted).

## 6. Enumeration flag logic per platform

| Platform | isSystem derivation | isUSB | source |
|---|---|---|---|
| Linux | `!isRemovable && !isVirtual` | `tran == "usb"` | lsblk JSON / pure sysfs |
| Windows | system folder resolves under a device mountpoint | enumerator USBSTOR + BusTypeUsb | SetupAPI + IOCTL |
| macOS | `diskutil` OSInternal | — | diskutil -plist |
| BSD | net-new (no removable heuristic) | umass in device chain | sysctl + geom/camcontrol |

- **Detect USB by bus type, NOT `removable` flag** (removable lies for many USB SSDs).
- Linux pure-sysfs (caligula): read `/sys/class/block/*`, `removable`, `size`×512,
  `queue/physical_block_size`, `device/model`; skip entries with a `partition` file.
- Drop `/dev/loop*`, `/dev/sr*`, `/dev/ram*`.
- **rs-drivelist decision**: depend initially (fast Windows FFI), but WRAP behind own `Device`
  type and re-derive safety flags ourselves (their code has many `.unwrap()`, weak Windows heuristic).

## 7. Decompression — fix caligula's extension-only bug

caligula detects by extension ONLY (a gzip named `.img` silently written compressed). Lufus:
sniff magic bytes via `BufReader::fill_buf()` (no consumption), use extension only as tiebreaker.
Magics: gzip `1F 8B`, xz `FD 37 7A 58 5A 00`, bzip2 `42 5A 68`, zstd `28 B5 2F FD`, lz4 `04 22 4D 18`.
Keep caligula's macro-generated uniform-`Read` DecompressRead design; only selection changes.
Crates: flate2 (gz), bzip2 `static` (bz2), xz2/liblzma `static` (xz), lz4_flex (lz4), ruzstd/zstd.
