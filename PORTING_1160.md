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
7. patch VMEXIT, stage Linux at Sonic's established physical addresses, and
   rendezvous all CPUs into `vmmcall(1)`.

The result is an exact-11.60 regular-model candidate, not a claim of a
completed hardware boot test. Static, build, byte-provenance, and
position-independence checks are automated; final confirmation still requires
a retail 11.60 console.

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
  `[0x62806f00,0x62807000)` interval is `0xcc` padding, and prior live page
  walks prove that page executable and identity-mapped before and after the
  CR3 switch.
- The wake destination is the live-tested executable NOP range
  `[ktext+0xd2b000, ktext+0xd30000)`. The dedicated wake blob must remain at
  or below `0x5000` bytes.
- Sonic's optional UART breadcrumb writes are omitted because their accidental
  `or dword ptr [rcx], eax ; ret` gadget has no 11.60 equivalent. The essential
  `memcpy` and final transfer sequence is unchanged.
- The 11.60 wake build is headless: unknown 11.60 VBIOS, transmitter, MP3, and
  shared-memory addresses remain NULL and are never dereferenced. UART output
  from the inner bare-metal stage remains enabled.
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
- the startup #DB and final #GP/#SX pivots are both present, distinct, and used
  only at their Sonic-matching exception sites;
- the VMEXIT transition targets `0x62806f00`, not the unusable `0x6284ac20`
  address used by the failed run-6 candidate. The latter's low VA is absent
  under the active runtime host CR3 and is present-but-NX only under the
  inactive bootstrap tables;
- Sonic's two required inner-HV deltas are encoded;
- the final payload contains exactly one wake blob and one AP donor blob.

## Hardware test boundary

Use only on an exact retail 11.60 regular PS5, with the same USB Linux files
and rest-mode procedure documented by upstream. This candidate mutates
IDT/TSS/FACS state and the hypervisor path. If it refuses because carrier state
is stale, cold reboot; do not retry it in the same GameOS boot.

Because display firmware offsets are intentionally unknown, first testing
should be treated as UART/headless. A black screen alone does not distinguish
a failed Linux transition from a successful headless boot.

The older `wake-1160` and `stage2a-1160-check` targets remain available as
non-arming staging diagnostics. They are not the full port.
