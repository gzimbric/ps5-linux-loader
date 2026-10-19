# Firmware 11.60 Sonic-style Linux port

This branch adds a dedicated `linux-1160` build. It preserves the public
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

Run 18 booted this ELF once with a CachyOS image carrying the exact Run 15
boot files; see the hardware validation status below. It has not been booted
with the Ubuntu 24.04 image. For testers, the ELF is attached to the
[`firmware-11.60-dma-e820-run18`](https://github.com/gzimbric/ps5-linux-loader/releases/tag/firmware-11.60-dma-e820-run18)
release. Check its SHA-256 against the value above before sending it. The
[tester guide](https://github.com/gzimbric/ps5-linux-porting/blob/main/docs/ubuntu2404-tester-guide.md)
in the porting repo covers the Ubuntu 24.04 image, the boot steps and what to
report.

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
not a display result. Run 15 remains the release baseline.

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
