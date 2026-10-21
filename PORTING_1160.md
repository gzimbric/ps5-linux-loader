# Firmware 11.60 Sonic-style Linux port

This fork's `main` branch contains a dedicated `linux-1160` build. It preserves the public
`ps5-linux-loader` flow and substitutes exact 11.60 inputs at the same seam
used by Sonic's known-working 13.60 ELF:

1. fetch `bzImage` and `initrd.img`;
2. publish the public 0x98-byte wake argument block;
3. map the position-independent wake blob at the existing fixed alias;
4. use the hardware-proven 11.60 startup-AP carrier to disable nested paging;
5. corrupt `AcpiGbl_FACS` so resume reaches the #GP/#SX copy-and-transfer
   chain;
6. copy the wake blob into the verified 11.60 executable ktext cave;
7. patch VMEXIT and stage Linux at Sonic's established physical addresses;
8. perform Sonic's VBIOS, DisplayPort, MP3, and 29-call HDMI handoff using
   the authenticated native 11.60 homologs; and
9. rendezvous all CPUs into `vmmcall(1)`.

Run 15 completed the full hardware proof on an exact retail 11.60 regular PS5.
The same rest-mode resume produced directly observed physical HDMI output and
authenticated Linux userspace over wired SSH. This validates the complete
Sonic-equivalent sequence as one containing path: carrier, resume pivots, HV
transition, Linux transfer, MP3 commands 21/22, and the 29-record display
table. No UART or per-operation return telemetry was available, so Run 15 does
not identify the minimal display subset. Static, build, byte-provenance, and
position-independence checks remain automated for the release configuration.

## Deliberate 11.60 substitutions

- The raw firmware gate is exactly `0x11600005`; other revisions fail before
  setup or mutation.
- The startup-AP payload is the byte-identical hardware-proven 11.60 donor:
  1,158 bytes, SHA-256
  `918ac3d8ccc16ec31e40fc069cf5ba46b168afd493acb12461adc8f96c7ee997`.
- PS5 Pro is refused before setup because that donor's physical HV layout was
  proven only on regular PS5 hardware.
- `AcpiGbl_FACS` is `ktext + 0x39cd1f0` and `memcpy` is
  `ktext + 0x2e7e40`.
- Sonic's two resume pivots remain distinct. The startup #DB carrier uses
  `ktext + 0x2a0ede` (`add rsp,0x28; ret`), while the final #GP/#SX gates use
  the exact cross-firmware homolog `ktext + 0xa57354`
  (`add rsp,0x28; pop rbp; ret`) for their six-qword IST frames.
- The VMEXIT transition stub uses Sonic's established physical HV padding at
  `0x62806f00`. The local 11.60 HV dump proves the full
  `[0x62806f00,0x62807000)` interval is `0xcc` padding. A live reverse walk
  proves the page executable and identity-mapped before the CR3 switch;
  post-switch coverage is guaranteed statically by the staged executable
  1-GiB identity leaf.
- The wake destination is the live-tested executable NOP range
  `[ktext+0xd2b000, ktext+0xd30000)`. The dedicated wake blob must remain at
  or below `0x5000` bytes.
- Sonic's optional UART breadcrumb writes are omitted because their accidental
  `or dword ptr [rcx], eax ; ret` gadget has no 11.60 equivalent. The essential
  `memcpy` and final transfer sequence is unchanged.
- The 11.60 display handoff uses `G_VBIOS = ktext + 0x3db7a40`, transmitter
  control at `ktext + 0xc800c0`, MP3 initialization at
  `ktext + 0xa88270`, and MP3 invocation at `ktext + 0xa86e70`. These are
  authenticated from the exact 11.60 ktext dump; the three functions are
  normalized matches to Sonic's 13.60 functions and the VBIOS address is
  resolved from the native 0x10000-byte copy loop.
- Sonic's display order is retained exactly: copy the 64-KiB VBIOS to physical
  `0xc0000`, enable the four-lane transmitter at 81000, wait 349,999,999 TSC
  ticks, initialize MP3, invoke MP3 commands 21 and 22, then execute the same
  29 HDMI operations with their native 11.60 function homologs and arguments.
  The operation table is dump-pinned by function hashes and checked byte for
  byte in the final wake ELF.
- The compact 11.60 build reuses the otherwise-free tail of the aligned
  `linux_info_va` page for the MP3 response/request work buffers. Matching
  Sonic's observed layout, the 0x1408-byte response buffer begins at `0x1000`,
  an 0x18-byte gap follows, and the 0x1404-byte request buffer begins at
  `0x2420`. Both are 32-byte aligned, end at `0x3824`, and therefore do
  not overlap the 0xc38-byte Linux information structure or exceed its
  0x4000-byte page.
- The retained page is zeroed before suspend, matching Sonic's zero-filled
  static storage. The 11.60 production path therefore performs no wake-time
  MP3 buffer clear; diagnostic builds can explicitly set
  `PS5_1160_DIAG_CLEAR_MP3_BUFFERS=1` only to reproduce the failing Run 13
  write pattern. Legacy firmware builds retain their original clear.
- Sonic's inner-HV UART-enable operation and reserved E820 range
  `[0x980000000, 0xa00000000)` are retained.

## Build and audit

The PS5 payload SDK, an x86-64 ELF cross-toolchain, and the authenticated 11.60
kernel-text and extended-HV dumps are required for the release check. The
top-level Makefile now defaults to the exact hardware-tested Run 15 gates:
`PS5_1160_DIAGNOSTIC=1`, `PRE=5`, `OP=29`, and clear disabled. On the macOS
toolchain used for the release:

```sh
PATH=/opt/homebrew/opt/llvm/bin:$PATH \
PS5_1160_KTEXT_DUMP=/absolute/path/to/ps5-11.60-ktext.bin \
PS5_1160_HV_DUMP=/absolute/path/to/ps5-11.60-hv-extended-62800000.bin \
make linux-1160-check \
  PS5_PAYLOAD_SDK=/absolute/path/to/ps5-payload-sdk
```

The output is `bin/ps5-linux-loader-1160.elf`. The release check pins all
three generated identities to the hardware-tested Run 15 artifacts:

- outer ELF: `422b87ec39ca0edfce8dddd609c2eff1cc7adcb2732b7909b76fafbd60dd2336`;
- wake blob: `83756ca9eddffbcf075cb3660ec80755263ce147793922a54414b57c15d11319`;
- wake ELF: `19c9e7fc396520bad8e49f8f4c97ffe10830d494a2fe9346d6d944ff6f09ac3a`.

The source list is sorted in byte order, so these hashes do not depend on the
shell locale (`LANG=en_US.UTF-8` used to change the link order).

Changing a diagnostic gate changes a tracked build stamp and forces the wake
blob and outer payload to rebuild. Such builds remain useful for controlled
experiments, but `linux-1160-check` rejects them as release artifacts.

The 13.60 support from upstream (8cda4c1) also changes the stock 13.60 inner
HV so Linux only gets `[0x00100000, 0x01000000)` as low RAM and sees
`[0x01000000, 0x40000000)` as reserved. Run 15 keeps the original map
(`[0x00100000, 0x3fffc000)` RAM, `[0x3fffc000, 0x40000000)` reserved). The
same reservation is available for 11.60 as a separate opt-in build:

```sh
PATH=/opt/homebrew/opt/llvm/bin:$PATH \
PS5_1160_KTEXT_DUMP=/absolute/path/to/ps5-11.60-ktext.bin \
PS5_1160_HV_DUMP=/absolute/path/to/ps5-11.60-hv-extended-62800000.bin \
make linux-1160-dma-e820-check \
  PS5_PAYLOAD_SDK=/absolute/path/to/ps5-payload-sdk
```

This writes `bin/ps5-linux-loader-1160-dma-e820.elf` (169,872 bytes,
`2e1758a2d013305bcb9faa0eb3adf18c34ed76ad85313dd945719c8bf2a0c9c0`). It
differs from Run 15 only in the three E820 operands inside the inner HV (and
so in the wake blob that carries it and the outer build id). It is not the
Run 15 release and does not pass that hash gate. `linux-1160-dma-e820-check`
audits the new E820 operands and prints the ELF hash, but does not pin it.
The hash above came from Homebrew LLVM 23.1.0, x86_64-elf-gcc 16.2.0 and
binutils 2.47 on macOS; other toolchain versions are not expected to
reproduce it. Expect about 1008 MiB less usable RAM. The gate follows the
target name: `linux-1160` always builds the original map, setting
`PS5_1160_DMA_E820_SAFE` on the command line is refused, and the two targets
have to be built in separate `make` runs because they share the nested blobs.
The corresponding `bin/*.elf` file targets carry the same target-specific
mode into their prerequisites. Before linking, each file target checks the
nested HV build configuration, so a direct file-target build cannot silently
put the original map in a DMA-named ELF. CI checks both target spellings and
rejects a mixed direct Run 15/DMA invocation.

Run 18 booted this ELF once with a CachyOS image carrying the exact Run 15
boot files. Run 19 booted it once with the CI-built Ubuntu 24.04 image from
release `ubuntu2404-1160-build-3`, the image the tester guide uses; see the
hardware validation status below. For testers, the ELF is attached to the
[`firmware-11.60-dma-e820-run18`](https://github.com/gzimbric/ps5-linux-loader/releases/tag/firmware-11.60-dma-e820-run18)
release. Check its SHA-256 against the value above before sending it. The
[tester guide](https://github.com/gzimbric/ps5-linux-porting/blob/main/docs/ubuntu2404-tester-guide.md)
in the porting repo covers the Ubuntu 24.04 image, the boot steps and what to
report.

`make linux-1160-dma-e820-visible` (or `linux-1160-dma-e820-visible-check`
with the same dumps) builds the DMA E820 map into
`bin/ps5-linux-loader-1160-dma-e820-visible.elf`. It differs from the DMA
build only in the two size refusals in `fetch_linux`. When `bzImage` or
`initrd.img` is not the validated size, it shows a notification with the file
name, its size and the size it needs, where the other builds only print that
to the log. Payload menus show only notifications, so with the other builds a
wrong image ends with "Something went wrong while installing linux files." and
no reason. The check runs the DMA checks on this ELF and prints its hash,
which is not pinned. Setting `PS5_1160_VISIBLE_REFUSALS` on the command line
is refused, and the target cannot share a `make` run with `linux-1160`. This
build has not been booted on hardware.

`make linux-1160-dma-e820-wifi` (or `linux-1160-dma-e820-wifi-check` with the
same dumps) builds `bin/ps5-linux-loader-1160-dma-e820-wifi.elf`: the visible
build plus the 11.60 IW620 Wi-Fi firmware range in the offset table. The range
is the one returned by the native 11.60 firmware helper at
`ktext + 0x4ecfd0`: `ktext + 0x1585d90`, length `0x799bc` (498,108 bytes).
With it set, the existing dump in `source/firmware.c` copies the console's own
firmware to `lib/nxp/pcieuartiw620_combo_v1.bin` on the boot partition, next
to `initrd.img`, as upstream does on other firmwares. The other 11.60 builds
keep both fields zero, print `PS5 WiFi firmware offset missing for firmware
1160` and write nothing. Against the visible ELF it differs in 27 bytes: 7 in
those two `off_1160` fields and 20 in the build ID. The nested HV and wake
blobs are the DMA E820 ones. On the console used for this port, that kernel
range hashes to
`eafef24af118f96f84a652e17aeed555ec4ac719b9fac11ff98a2de7e2b4b369` and
identifies itself as firmware `17.130.3.p47`. The firmware is read from each
console at boot and is not in this repository or any release.
The loader release contains no firmware blob. Do not redistribute the runtime
dump at `lib/nxp/pcieuartiw620_combo_v1.bin`; it came from the individual
console and is not a release artifact.
`PS5_1160_WIFI_FW` is passed only to this target's objects, so no other build
can pick it up. The check prints the hash, which is not pinned. This build has
not been booted on hardware. The bounded Wi-Fi build below has the same range
and ran the dump in Run 21.

`make linux-1160-dma-e820-bounded` and `make linux-1160-dma-e820-bounded-wifi`
(and their `-check` targets, with the same dumps) build
`bin/ps5-linux-loader-1160-dma-e820-bounded.elf` and
`bin/ps5-linux-loader-1160-dma-e820-bounded-wifi.elf`, for kernels and initrds
other than the Run 15 pair. They are the visible and Wi-Fi builds with the two
exact-size gates replaced by checks on what the inner HV relies on; the HV and
wake code take the sizes from `linux_info`. They refuse:

- a `bzImage` under 620 bytes or over 64 MiB, an `initrd.img` under 512 bytes
  or over 128 MiB, or a pair over 160 MiB once each is rounded up to 16-KiB
  pages. Under that cap the wake copy ends by `0x10a009000`, below CPU 0's HV
  stack;
- a setup header that lacks any of: boot flag `0xaa55`, `HdrS`, protocol
  2.15 or later, `setup_sects` 1 to 64 (the inner HV does not read 0 as 4),
  `syssize * 16` bytes inside the file, `LOADED_HIGH`, `XLF_KERNEL_64`,
  `XLF_CAN_BE_LOADED_ABOVE_4G`, a relocatable kernel, a power-of-two
  `kernel_alignment` of 2 to 16 MiB with `pref_address` aligned to it and no
  higher than `0x3fffc000`, a payload at `0x100000` that ends by the
  decompression base (15 MiB with the usual 16 MiB base), a decompression
  range that ends by `0x3fffc000`, `cmdline_size` of at least 2047, and a zero
  `setup_data` (the inner HV passes the header to Linux as it is);
- a kernel built without `CONFIG_RANDOMIZE_BASE`. The header does not show it,
  so the loader looks for the decompressor's "Physical KASLR disabled: no
  suitable memory region!" message, which is only there when KASLR is built
  in;
- an `initrd.img` that is not a newc cpio (`070701` or `070702`, after any NUL
  padding, at a multiple of 4 bytes) or zstd, gzip, xz, lz4, lzma, bzip2 or lzo
  data. The kernel rejects the old `070707` cpio format;
- a `vram.txt` size that is not a multiple of 16 MiB or is over `0x35f000000`.
  The inner HV puts VRAM right below `0x470000000`, and it has to stay above
  the wake copy and the HV stacks, which end at `0x11000f000`;
- `nokaslr`, any `mem=` or `memmap=` option, or any byte above `0x7f` in
  `cmdline.txt`. The kernel reads `0xa0`, a non-breaking space, as a space,
  so an option after one would get past the option check;
- a `linux_info` page, alias page table (new or already present), PID 1's PML4,
  DMAP page table for the copy or the #SX stack, kernel code cave page or page
  table that maps it, or the #SX stack page or the page under it, inside
  `[0x100000000, end of the wake copy)`, which the wake blob overwrites before
  Linux starts. A `bzImage` or `initrd.img` page is refused only if the copy
  would reach it before reading it, because the blob copies forward;
- any of those pages or tables in the page under the #SX stack page. The ROP
  chain leaves the stack 0x1040 bytes into the #SX page, and a deeper stack
  runs into the page under it. The wake arguments page is not refused there;
  it is allocated again instead.

KASLR is required with the DMA map: the only RAM it leaves below 1 GiB is 1 to
16 MiB, so the kernel has to be moved above the reservation. The decompressor
keeps the kernel at 16 MiB, inside the reservation, whenever it finds no slot:
with `nokaslr`, a kernel without `CONFIG_RANDOMIZE_BASE`, a `mem=` below about
1 GiB plus the kernel size, or more than four `memmap=` options. `memmap=` can
also turn reserved memory back into RAM. Hence those refusals. None of the
shipped `cmdline.txt` files use `mem=` or `memmap=` or bytes above `0x7f`.
The loader only sees `cmdline.txt`. A command line built into the kernel with
`CONFIG_CMDLINE` is not visible to it, so a kernel built with `nokaslr`,
`mem=` or `memmap=` there gets past these checks.

Only `[0x100000000, 0x1040048c0)`, the Run 15 files, has been overwritten on
hardware. The Run 21 copy ended at `0x103c9d000`, inside it. With larger
files the copy reaches up to `0x10a009000`. After the copy, the wake blob
still runs the 29 display calls, `printf` and `smp_rendezvous` on GameOS
kernel memory that the loader cannot check. How deep the wake blob's stack
goes is not measured either. Past 0x1040 bytes it writes into the page under
the #SX stack page. The checks above keep what the blob reads out of that
page, but it can hold GameOS kernel memory that the loader does not check.

Every refusal is a notification, so payload menus show it. "boot header check
N failed" means 1 short file, 2 boot flag, 3 `HdrS`, 4 protocol, 5
`setup_sects`, 6 `syssize`, 7 load flags, 8 not relocatable, 9
`kernel_alignment`, 10 `pref_address` or a payload over 15 MiB, 11
`init_size`, 12 `cmdline_size`, 13 no KASLR, 14 `setup_data`. The boot file
refusals all come before the Wi-Fi build writes the firmware to the boot
drive.

The copy range and #SX stack checks all run before the first alias write,
with one exception: a new alias page table is allocated, and checked, while
the aliases are being installed. A refusal there rolls back the alias writes
made so far and checks that they are gone; if that check fails, the loader
holds until a cold reboot. The #SX stack page is taken during staging rather
than when the wake chain is armed, because any failure after staging holds
for a cold reboot. A staging refusal leaves nothing armed. Source pages, alias
tables and the #SX stack page are new on each run, so running the loader again
can get past those refusals. A page table or the code cave inside the copy
range stays where it is until a reboot; that refusal says to reboot, and the
loader does not add that it can be run again.

The checks also run `tests/test_boot_files_1160.c`. It checks that a kernel
passes, and that the same kernel without the KASLR message or with a
`setup_data` pointer is refused, on images built from the header fields and
KASLR message offset of the Run 15 7.1.7 and CachyOS 7.3 bzImages. That is
what CI runs; the kernels are not in the repository.
`PS5_1160_TEST_BZIMAGE=/path/to/bzImage` runs the same checks on real files
and, for those two, checks that the fields still match. Setting
`PS5_1160_BOUNDED_BOOT_FILES` on the command line is refused. `linux-1160`,
`linux-1160-dma-e820`, `linux-1160-dma-e820-visible` and
`linux-1160-dma-e820-wifi` stay byte-identical (`422b87ec`, `2e1758a2`,
`681b22ea`, `3cda033e`). The public
[`firmware-11.60-dma-e820-bounded-run21` tester prerelease](https://github.com/gzimbric/ps5-linux-loader/releases/tag/firmware-11.60-dma-e820-bounded-run21)
pins both bounded files. The bounded ELF is `1c80b040c5a808b3f09418728424a875d5598fe6b2a5d68adeb4db5979a7541a`
(`fdabc92c7f7373e2805c66e8614d36703d63e1df67c32b4230bf8f6168651724`
with `.comment` and the build ID removed). It remains unbooted and is the
loader for MediaTek consoles on Image 4 because it does not write IW620
firmware. The bounded Wi-Fi ELF for IW620 consoles is
`e9fe6469943e97a635eccd3f674e55876b56cd1bbd69023eee3af4acea3a1b5f`
(`7b4588e3441fb83b3843196c6ebb20fb630dc737cdd7b9e0945dc7a86fdfbace`
with those sections removed). Run 21 booted that Wi-Fi build once with an
earlier local image.

Run 21 used the bounded Wi-Fi ELF built at commit `98925a2`
(170,904 bytes,
`e9fe6469943e97a635eccd3f674e55876b56cd1bbd69023eee3af4acea3a1b5f`). The boot
files were not the Run 15 pair: an 11,613,184-byte Linux 7.3.0 `bzImage` and a
51,900,862-byte `initrd.img`, which the exact-size builds refuse. The loader
printed `11.60 bounded: bzImage protocol 0x20f, setup 20480, payload 11592704
at 0x100000, decompress 0x1000000-0x36c5000` and `11.60 bounded: wake copy
0x100000000-0x103c9d000 (3878 logical pages)`. It also printed that it had
dumped the Wi-Fi firmware to `lib/nxp/pcieuartiw620_combo_v1.bin` (498,108
bytes). This is the first time a loader dumped the IW620 firmware on 11.60,
and the file on the boot drive has the hash given above. See the hardware
validation status below.

Current `main` keeps that ELF byte-identical and adds fail-closed mode checks
for direct file targets plus CI coverage for all six 11.60 variants. The
historical `firmware-11.60-dma-e820` branch remains only as provenance for the
Run 18 through Run 21 commits.

The bounded tester prerelease is for exact retail firmware 11.60 only.
[CachyOS Image 3](https://github.com/gzimbric/ps5-linux-image/releases/tag/cachyos1160-k73-image-3),
still the newest CachyOS image with an identity-verified hardware boot, uses
the bounded Wi-Fi ELF on IW620 hardware; follow the
[Image 3 tester guide](https://github.com/gzimbric/ps5-linux-porting/blob/main/docs/cachyos1160-k73-image-3-tester-guide.md).
The public
[CachyOS Image 4](https://github.com/gzimbric/ps5-linux-image/releases/tag/cachyos1160-k73-image-4)
tester prerelease is one image for both Wi-Fi chipsets, so select the loader
by PCI device:

| Console Wi-Fi device | Loader | SHA-256 | Firmware path |
|---|---|---|---|
| Marvell/NXP IW620 `1b4b:2b56` | `ps5-linux-loader-1160-dma-e820-bounded-wifi.elf` | `e9fe6469943e97a635eccd3f674e55876b56cd1bbd69023eee3af4acea3a1b5f` | Copies that console's own IW620 firmware to the USB boot partition |
| MediaTek MT7921 `14c3:7961` | `ps5-linux-loader-1160-dma-e820-bounded.elf` | `1c80b040c5a808b3f09418728424a875d5598fe6b2a5d68adeb4db5979a7541a` | Does not dump IW620 firmware; Image 4 packages the firmware used by `mt7921e` |

The non-Wi-Fi loader has not been booted, and the exact Image 4 artifact has
only been built and checked in CI; it has not been booted. MediaTek Wi-Fi has
passed source and structural checks only. MediaTek Bluetooth hardware and its
usable driver path remain unknown, so none of this establishes MediaTek
hardware support. Follow the
[Image 4 tester guide](https://github.com/gzimbric/ps5-linux-porting/blob/main/docs/cachyos1160-k73-image-4-tester-guide.md)
for its exact artifact identity, evidence and clean-flash requirements.

`linux-1160-check` fails unless all of the following hold:

- the exact startup-AP donor hash and size match;
- the wake blob fits the five-page 11.60 cave;
- the wake and inner-HV raw payload ELFs are PIE (`ET_DYN`) with no relocation
  entries or linked-VMA immediates;
- each raw `.shell_code` begins at `main` and embeds correctly;
- the public wake ABI remains exactly 0x98 bytes;
- the exact 11.60 offsets are present and selected 13.60 offsets are absent;
- all four display offsets are non-NULL before any carrier mutation;
- Sonic's VBIOS/transmitter/MP3 ordering, constants, and exact 29-record HDMI
  call table are present, and the dispatcher loads the required `rdi`/`rsi`
  arguments before every indirect call;
- every unique 11.60 HDMI target matches its authenticated ktext hash;
- the startup #DB and final #GP/#SX pivots are both present, distinct, and used
  only at their Sonic-matching exception sites;
- the VMEXIT transition targets `0x62806f00`, not the unusable `0x6284ac20`
  address used by the failed run-6 candidate. The latter's low VA is absent
  under the active runtime host CR3 and is present-but-NX only under the
  inactive bootstrap tables;
- Sonic's two required inner-HV deltas are encoded;
- the final payload contains exactly one wake blob and one AP donor blob.

The integration also fails closed unless the boot media contains the
audited 12,702,720-byte `bzImage` and the final 54,376,639-byte `initrd.img`.

## Hardware validation status

Runs 10, 12, 14, and 15 reached authenticated Linux userspace over wired SSH.
Run 14 isolated the direct `mp3_initialize(0)` call with the redundant
wake-time buffer clear disabled and booted successfully without visible HDMI.
Run 15 retained that no-clear behavior, matched Sonic's response-first work
buffer geometry and two-layer dispatcher, enabled commands 21/22 and all 29
display records, and produced physical output plus authenticated Linux in the
same cycle.

The exact tested Run 15 source was local commit
`815b1fdc5c76088762e42ad0ad80b0099a54e60d`. Its source tree is byte-identical
to published commit `e0b7a2e9ac1fe6ec8de8f1883ba9470ad7ee690d` on branch
`firmware-11.60-sonic-display`; both resolve to tree
`97e96d7d6fbec038812e0a1f9919b1d7c91a9410`. A fresh published-tree build
with the release configuration and authenticated dumps reproduced all three
Run 15 hashes above.

Run 18 booted the DMA E820 build once on the same console, from cold boot,
with automatic Rest Mode and wake. The USB was a CachyOS image built from the
official `ps5-linux-image` CachyOS release, with the exact Run 15 `bzImage`,
`initrd.img`, `cmdline.txt` and `vram.txt` on the FAT partition. The ELF was
sent once, and the loader's 2,832 bytes of output were byte-identical to
Runs 16 and 17. Linux 7.1.7 reached authenticated wired SSH. The kernel's
e820 map had System RAM at `[0x00100000, 0x01000000)`, device reserved at
`[0x01000000, 0x40000000)` and System RAM again from `0x40000000`, which is
the intended reservation. MemTotal was 14,783,608 kB, about 14.1 GiB. Three
4 GiB files were written to the USB root and hashed, caches were dropped, and
all three were re-read with matching hashes (12 GiB, about two minutes). A
scan of 22 minutes of kernel log found no I/O, ext4, USB reset, xHCI, IOMMU or
machine check errors. See the
[Run 18 evidence](https://github.com/gzimbric/ps5-linux-porting/blob/main/evidence/11.60-cachyos-run-18-dma-e820.md).

Run 18 is one boot on one console, with no A/B control. The Run 15 ELF was
never put through the same I/O check, and the read/write errors reported by
testers have not been reproduced on this console, so Run 18 does not show
that the reservation fixes them. The I/O check was short and covered only the
USB root. DRM reported a connected 1920x1080 output and a desktop session
started, but the picture was not recorded as directly observed, so Run 18 is
not a display result.

Run 19 booted the DMA E820 build once more on the same console, with the
image and ELF from the tester guide: the CI-built Ubuntu 24.04 image from
release `ubuntu2404-1160-build-3` and the ELF from the
`firmware-11.60-dma-e820-run18` release, with the hash above. The image's
`bzImage` is the same as in Runs 15 to 18, and its `initrd.img` is a new CI
build of the validated size. The ELF was sent once from cold boot, and the
loader's 2,832 bytes of output were byte-identical to Run 18. After automatic
Rest Mode, one press of the PS button woke it, the light turned white, and
TCP port 22 opened about 20 seconds after the wake was reported. The operator
directly observed the HDMI picture, and a GNOME session logged in
automatically. Ubuntu 24.04.5 with Linux 7.1.7 reached authenticated wired SSH.
The e820 map was the same as in Run 18, with `[0x01000000, 0x40000000)`
reserved, and MemTotal was again 14,783,608 kB. The tester guide's checks were
run as written. The storage error search printed nothing. The optional I/O
check wrote three 4 GiB files to the USB root, dropped the page cache and
re-read all three with matching hashes in under two minutes; the script
reported a pass. A scan of the whole boot's kernel log found no Buffer I/O,
blk_update_request, uas_eh, AMD-Vi, DMAR or machine check lines and no BUG,
Oops or Call Trace. See the
[Run 19 evidence](https://github.com/gzimbric/ps5-linux-porting/blob/main/evidence/11.60-ubuntu-ci-run-19.md).

Like Run 18, Run 19 is one boot on one console with no A/B control, and the
testers' read/write errors were not reproduced, so it does not show that the
reservation fixes them. Wi-Fi (the image has no driver), Bluetooth, M.2,
sustained GPU load, a soak and repeat boots were not tested. It shows that the
image and ELF from the tester guide boot on this console with a picture, apply
the intended map and pass the guide's checks. Run 18 remains the validation
run for this build, and Run 15 remains the release baseline.

Run 21 was the first boot of the bounded Wi-Fi build. It ran once on the same
console, from cold boot, with a local build of the CachyOS 7.3 image from the
`cachyos-1160-k73` branch of `ps5-linux-image`, on the same official CachyOS
base as Run 18 and flashed to the same USB drive. Its kernel is Linux 7.3.0,
built from v7.3 with the PS5 patch from rmux (Armandas Kvietkus),
[`ps5-linux-patches-1`](https://github.com/rmuxnet/ps5-linux-patches-1),
which carries the 7.3 port and the CPU and GPU frequency drivers. The
frequency drivers were built as modules; their idle temperature results are
in the evidence. `cmdline.txt` is the same as in Runs 15 and 18. The ELF was
sent once, and the loader's 3,035 bytes of output had the two bounded lines,
the firmware dump line and the `wake chain armed` line. One press of the PS
button woke it, the light turned white, and TCP port 22 opened about 25
seconds after the wake was reported. The operator directly observed the HDMI
picture. CachyOS with Linux 7.3.0 reached authenticated SSH over wired
Ethernet. The e820 lines were the same as in Runs 18 and 19, and KASLR put
the kernel code at physical `0x26ec00000`, about 9.7 GiB, well above the
reservation. MemTotal was 14,788,356 kB. The kernel log had no I/O, ext4,
IOMMU, BUG or Oops lines.

The dumped firmware matched the known 11.60 p47 hash (`eafef24a...`). The
image's firmware service put it in place and reloaded the driver, which
reported `WLAN FW is active` with version `PCIEIW620-17.130.3.p47`. The
console joined a 5 GHz WPA3 network with `nmcli`, and a 50 MB HTTPS download
bound to the Wi-Fi interface ran at about 192 Mbit/s. The driver first probed
before the firmware was in place, and joining from the KDE network menu
failed. Both are image issues and are in the evidence.

Run 21 is one boot on one console, with a local image build rather than the CI
build and no A/B control. A roughly 54 GB Steam install completed while a
four-hour watcher took 480 samples; each sample had zero new lines matching
the selected storage-error patterns, and displayed free space fell from 213
GB to 159 GB. The watcher's `/proc/diskstats` fields were wrong, so its
throughput and total-I/O figures are invalid. This was not a read-back/hash
test, and no completed Steam integrity check was captured.

A later 45-minute telemetry log contained 88 samples with `GameThread` and 76
samples with the GPU at 2.23 GHz. The temperature reached 84.0 °C, and the log
ended while the game thread and 2.23 GHz state were still active. That is a
brief game-load result, not a sustained stability or thermal-soak pass; no
operator-confirmed gameplay or game display was recorded. The frequency
drivers therefore remain manual. Bluetooth did not work. Video decode,
reboot and suspend were not tested.

Run 21 shows that the bounded Wi-Fi build accepts a kernel and initrd other
than the Run 15 pair and boots them with the DMA map, that KASLR moved the
kernel above the reservation, and that the loader's firmware dump gave the
driver working firmware on this console. The bounded build without Wi-Fi has
not been booted. Run 18 remains the DMA validation run, Run 19 the Ubuntu
tester-pair run, and Run 15 the release baseline. See the
[Run 21 evidence](https://github.com/gzimbric/ps5-linux-porting/blob/main/evidence/11.60-cachyos-k73-run-21.md).

The public
[CachyOS image 2 tester prerelease](https://github.com/gzimbric/ps5-linux-image/releases/tag/cachyos1160-k73-image-2)
is independently pinned by tag `cachyos1160-k73-image-2` at source commit
`346088a48f66eb956dafdec9de5085e73b2d44a5`. It still uses rmux's complete
Linux 7.3 patch set at `36f173f` as the kernel baseline, then applies a
separate, hash-pinned IW620 Bluetooth follow-up and changes the image's Wi-Fi
firmware/driver load order. Those image changes do not alter the bounded
loader contract. Run 21 booted neither tagged CI image, and image 2 remains
unbooted; a successful image build is not a loader or hardware result. Use
the tester guide linked above for that exact image and loader pair.

The later exact public
[CachyOS Image 3](https://github.com/gzimbric/ps5-linux-image/releases/tag/cachyos1160-k73-image-3)
artifact completed one identity-verified cold boot on the same CFI-1115B with
the bounded Wi-Fi ELF
`e9fe6469943e97a635eccd3f674e55876b56cd1bbd69023eee3af4acea3a1b5f`.
That run reached HDMI and wired SSH, joined Wi-Fi through Plasma with the
loader-copied console IW620 firmware, paired and reconnected a DualSense
through the internal IW620 Bluetooth path, and completed both session
switches. Those are Image 3 results on one IW620 console, not evidence for the
unbooted non-Wi-Fi loader or for MediaTek hardware.

The public
[CachyOS Image 4 tester prerelease](https://github.com/gzimbric/ps5-linux-image/releases/tag/cachyos1160-k73-image-4)
is pinned by tag `cachyos1160-k73-image-4` at source commit
`e82cefaac9f4c166b4b961ea64597bb5a2a1d1e3`. It keeps rmux's Linux 7.3 patch
set and the IW620 path, and adds a structurally checked `mt7921e` path for
MediaTek consoles. CI built it and passed the image verifier, but the exact
Image 4 artifact has not been booted and the MediaTek Bluetooth path remains
unknown.

## Hardware test boundary

Use only on an exact retail 11.60 regular PS5, with the same USB Linux files
and rest-mode procedure documented by upstream. This release mutates
IDT/TSS/FACS state and the hypervisor path. If it refuses because carrier state
is stale, cold reboot; do not retry it in the same GameOS boot.

UART is optional. Authenticate Linux over wired SSH independently of monitor
state; a white light, ping, DRM connector state, or modeset return alone is not
a Linux or physical-display pass. Run 15 is one successful full-path cycle,
not a repeatability, long-duration, or multi-monitor campaign. The physical
display result is the operator's direct observation, while Linux, network, and
DRM state are separately machine-captured evidence.

The older `wake-1160` and `stage2a-1160-check` targets remain available as
non-arming staging diagnostics. They are not the full port.
