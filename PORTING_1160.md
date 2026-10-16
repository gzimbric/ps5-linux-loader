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

Run 7 completed the hardware proof on an exact retail 11.60 regular PS5.
Linux became reachable over Ethernet and an SSH session confirmed the running
kernel and system after rest-mode resume. This validates the Sonic-style
carrier, resume pivots, HV transition, and Linux transfer without relying on
UART. Static, build, byte-provenance, and position-independence checks remain
automated for every candidate.

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

The PS5 payload SDK and an x86-64 ELF cross-toolchain are required. On the
macOS toolchain used for the release candidate:

```sh
PATH=/opt/homebrew/opt/llvm/bin:$PATH \
make linux-1160-check \
  PS5_PAYLOAD_SDK=/absolute/path/to/ps5-payload-sdk
```

The output is `bin/ps5-linux-loader-1160.elf`.

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

Run 7 booted Linux on retail firmware 11.60 and was verified through live
Ethernet, ping, and SSH evidence. Its initial black display was diagnosed
inside the running system: the kernel requested uncompressed Cyan Skillfish
AMDGPU firmware while the image exposed compressed firmware files. That
display symptom did not indicate a failed loader transition.

Run 9 pairs the hardware-proven Linux carrier with the final 54,376,639-byte
initrd and Sonic's complete pre-Linux display handoff, translated to exact
native 11.60 targets. Its dump-backed audit and two clean, byte-identical
builds are complete. A cold boot has not yet verified Run 9, so Run 7 remains
the hardware-proven Linux boot and Run 9 is the pending display-validation
candidate.

## Hardware test boundary

Use only on an exact retail 11.60 regular PS5, with the same USB Linux files
and rest-mode procedure documented by upstream. This candidate mutates
IDT/TSS/FACS state and the hypervisor path. If it refuses because carrier state
is stale, cold reboot; do not retry it in the same GameOS boot.

UART is optional. Run 7 established that Ethernet reachability and SSH provide
an authoritative success signal when the display is black. For Run 9, verify
the Linux transition over the network independently of the monitor, then
confirm that Sonic's display handoff and the integrated AMDGPU media state
survive a cold boot. Do not describe display as verified until that test
passes.

The older `wake-1160` and `stage2a-1160-check` targets remain available as
non-arming staging diagnostics. They are not the full port.
