# ps5-1160-probe

A kernel-memory collection payload for retail firmware 11.60 (raw version
0x11600005). It collects what we need to plan 11.60 support for the PS5 Pro,
and it also runs on a regular PS5 as a control. Its own logic does not install
or arm loader/hypervisor hooks, and it refuses before creating files unless
the firmware is exactly 11.60 and a writable USB drive is mounted.

Like other payloads built with ps5-payload-sdk, the SDK runtime and KEX are
initialized before `main`: they patch the payload process's credentials and
syscall bounds, and the SDK's `kernel_copyout` read primitive temporarily
updates exploit-pipe metadata. The narrower safety claim here applies to the
probe logic after that standard initialization: it applies no loader,
kernel-text or hypervisor patches and never reads HV target data or MMIO.

## What it does

- Prints the firmware, SoC ID, model name and kit type.
- Finds the page tables using only SDK values (`kernel_get_proc`,
  `KERNEL_OFFSET_*`, `KERNEL_ADDRESS_*`), the same ones elfldr depends on,
  and cross-checks the direct map against the SDK and proc0.
- Measures the kernel text extent by page walks (execute-only frames below
  kdata) and keeps its physical frames off limits.
- Checks two 11.60 anchors in kernel data: the build string and the
  image-size record (header and size).
- Finds the boot metadata by signature, walks it, and lists the EFI memory
  map and the HV region candidates (type 0, 24-64 MiB, below 64 GiB) with
  base and size.
- Walks the page tables for every 4-KiB frame in the first HV candidate and
  reports contiguous mapped/unmapped runs. It never reads the target frames.
  It separately checks whether the regular and Pro VMCB scan hypotheses are
  completely identity-mapped before a later census payload is built.
- If the anchors match the regular 11.60 build, also reads FACS, the IW620
  hash, the EFI slot, IDT, TSS, DATA_CAVE and VBIOS state the loader depends
  on. These use regular-build offsets, so they are skipped on a mismatch.
- Lists PCI devices and device IDs (serials and addresses are filtered out).
- Dumps kernel data (0x5450000 bytes from the kdata base, the same window as
  the regular reference dump), whether or not the anchors match.
- Walks, without reading, 16 MiB past the window to show whether kernel data
  continues there.

Every kernel data read is checked first, one 4-KiB frame at a time: the frame
must be present, not execute-only at any page-table level, write-back cached,
mapped linearly with kdata (part of the loaded kernel image), and not in
kernel text, an HV, MMIO, reserved or non-RAM range. Frames that fail are
zero-filled and listed as holes. Probe output is written only to the mounted
USB drive; the probe logic does not write internal storage or enter rest mode.
`check-readonly.sh` fails the build if the sources use a write primitive or
the objects import anything not on its list.

It never prints IDPS/PSID, serials, MAC addresses or account IDs. The dump
is raw kernel data and may still contain console-specific values, so treat
it and the report as private.

## Build

    make probe

For a follow-up after the full dump has already been collected, build the
targeted map/TSS variant instead:

    make probe-map

Outputs: `bin/ps5-1160-probe.elf` and, for the targeted target,
`bin/ps5-1160-map-probe.elf`. The targeted variant performs the identity,
anchor, boot-metadata, HV-candidate, direct-map, TSS and page-walk checks but
skips PCI enumeration, the raw kernel-data dump and the beyond-window walk.
It needs ps5-payload-sdk (v0.44 tested).

## Run

1. Cold boot. Run the kernel exploit and elfldr only (no etaHEN, kstuff or
   other hooks if you can avoid it).
2. Plug in a USB drive (exFAT or FAT32). The full probe needs at least 200 MB
   free; the targeted map/TSS probe only writes a small report.
3. Send the ELF to elfldr on port 9021 and keep the connection open to see
   the output:

       socat -t 9999999 - TCP:PS5_IP:9021 < ps5-1160-map-probe.elf

   Use `ps5-1160-probe.elf` instead only when the raw kdata dump is actually
   required. `nc PS5_IP 9021 < ps5-1160-map-probe.elf` works on macOS. On
   Linux use `nc -N`. A GUI payload sender works too but shows no output.

It takes under a minute, up to a few minutes on a slow drive. A notification
shows when it is done. No output at all means the SDK runtime failed before
the probe started; report the elfldr version and exit status.

## Files

Written to the root of the first mounted USB drive (`/mnt/usb0` to
`/mnt/usb7`). The probe requests mode 0600, although FAT/exFAT cannot enforce
Unix ownership and permissions, so the drive and report must still be treated
as private. If no writable mounted USB is present, the probe refuses without
collecting data or creating files. Nothing is overwritten: a second run adds
`-02`, a third `-03`, and so on.

- `ps5-1160-probe-report.txt`: the full report.
- `ps5-1160-map-probe-report.txt`: the targeted map/TSS report; this is the
  only file created by `ps5-1160-map-probe.elf`.
- `ps5-1160-kdata.bin`: raw kernel memory. It is written as `.part` and
  renamed when complete; only the full probe creates it.

Send probe output privately. Never post a report or dump publicly (forums,
issues, Discord, public links). The Summary lines at the end of the terminal
output are safe to share.

## Offline check

`kdata_windows.py DUMP REPORT` compares the masked 64-KiB window hashes in a
report against any dump, so two consoles can be compared without sharing the
dump itself.
