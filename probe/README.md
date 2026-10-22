# ps5-1160-probe

A read-only payload for retail firmware 11.60 (raw version 0x11600005). It
collects what we need to plan 11.60 support for the PS5 Pro, and it also runs
on a regular PS5 as a control. It does not install or arm anything.

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
zero-filled and listed as holes. It never writes kernel memory, never reads
kernel text, and never touches the hypervisor, MMIO or rest mode.
`check-readonly.sh` fails the build if the sources use a write primitive or
the objects import anything not on its list.

It never prints IDPS/PSID, serials, MAC addresses or account IDs. The dump
is raw kernel data and may still contain console-specific values, so treat
it and the report as private.

## Build

    make probe

Output: `bin/ps5-1160-probe.elf`. It needs ps5-payload-sdk (v0.44 tested).

## Run

1. Cold boot. Run the kernel exploit and elfldr only (no etaHEN, kstuff or
   other hooks if you can avoid it).
2. Plug in a USB drive (exFAT or FAT32) with at least 200 MB free.
3. Send the ELF to elfldr on port 9021 and keep the connection open to see
   the output:

       socat -t 9999999 - TCP:PS5_IP:9021 < ps5-1160-probe.elf

   `nc PS5_IP 9021 < ps5-1160-probe.elf` works on macOS. On Linux use
   `nc -N`. A GUI payload sender works too but shows no output.

It takes under a minute, up to a few minutes on a slow drive. A notification
shows when it is done. No output at all means the SDK runtime failed before
the probe started; report the elfldr version and exit status.

## Files

Written to the root of the first mounted USB drive (`/mnt/usb0` to
`/mnt/usb7`), or to `/data/ps5-1160-probe/` if there is none. Nothing is
overwritten: a second run adds `-02`, a third `-03`, and so on.

- `ps5-1160-probe-report.txt`: the full report.
- `ps5-1160-kdata.bin`: raw kernel memory. It is written as `.part` and
  renamed when complete.

Send both privately. Never post either publicly (forums, issues, Discord,
public links). The Summary lines at the end of the output are safe to share.

## Offline check

`kdata_windows.py DUMP REPORT` compares the masked 64-KiB window hashes in a
report against any dump, so two consoles can be compared without sharing the
dump itself.
