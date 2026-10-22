# 11.60 PS5 regular-control and Pro census

These are opt-in diagnostic payloads for retail PS5 consoles on firmware
11.60. They are the step between the bounded map probe and any attempt to boot
Linux on PS5 Pro. Neither payload stages Linux, patches FACS, installs the
#GP/#SX wake chain, nor changes any hypervisor byte.

The artifacts are compile-time variants, not one auto-detecting binary:

- `ps5-linux-loader-1160-regular-census.elf` accepts only a non-Pro retail
  console with the exact `0x62800000 / 0x2029000` HV region. It scans only
  `R+0x200000..R+0x1000000`.
- `ps5-linux-loader-1160-pro-census.elf` accepts only a retail Pro with SoC ID
  `0x840fd0` and the exact `0x8e0000000 / 0x2000000` HV region. It scans only
  `R+0xa00000..R+0x1800000`.

The model-name query must succeed and is included in the private report, but
the payload is deliberately not pinned to one chassis label. This permits the
same census on any retail Pro that satisfies the exact SoC and layout gates.

The startup-AP component has its own source directory and never links the
production `break_hv` object. Hypervisor-derived pointers are `const volatile`.
The AP writes only its bounded report, the 16 IST6 slots it restores to their
saved values, and the carrier-state word it clears. It has no HV write helper.
The main payload temporarily owns the IDT1 low qword, IST6 slots, and a known
zero kernel data cave; it restores and reads back the gate and every IST6 slot,
clears the carrier state, then clears and reads back the complete cave. An
unexpected IDT1 high-qword value is never overwritten.

The payload fails closed unless all of these hold:

- raw firmware is exactly `0x11600005`, neither kit library is present, and
  the SoC class matches the compile-time artifact;
- the 11.60 build anchors and boot metadata at `ktext+0x3e10000` match;
- the metadata contains exactly one HV candidate, precisely the base and size
  compiled into that artifact;
- every 4 KiB page in that artifact's bounded census window is identity-mapped
  and scan-safe;
- IDT vector 1 uses IST4, every IST4 is unique, every rsp0 is nonzero and
  canonical, and all IST6 slots are zero;
- CPU 15 can be selected for TSS slot zero and the data cave is unused.

The complete region mapping bitmap is prepared before rest. The AP reads HV
data only from pages admitted by that bitmap. The first pass records the exact
candidate PAs selected by the production predicate. Both before and after
hashes cover those same addresses in the same order and include only PA,
`NESTED_CTRL`, and `CLEAN`, the identity plus fields production would mutate.

## Relocation-safe anchors

`B` is the variant-resolved HV image base: `B=R` for regular and
`B=R+0x800000` for Pro. Report version 2 hashes these exact byte ranges with
FNV-1a-64:

| Name | Range | Length | Regular reference hash |
|---|---:|---:|---:|
| code-to-padding boundary | `B+0x67d9..B+0x6919` | `0x140` | `18f1b0469f16d1ab` |
| code-cave window | `B+0x6ec0..B+0x6f40` | `0x80` | `1111e7a924292b25` |
| VMEXIT window | `B+0x47540..B+0x47580` | `0x40` | `fb06e5672b906885` |

These values were independently reproduced from the authenticated regular
11.60 reference dump with SHA-256
`ada1624ce72ef2fe4e9400e13d544116be4050f5187234a1fa19c6bd26988fee`.
The earlier experimental `0x67d9/0x80` and `0x6819/0x100` hashes are not used.

All three pages must be bitmap-valid on both variants. The regular-control run
also requires `anchor_match_mask == 7` for a complete report. The first Pro
run records the match mask as evidence but does not treat an unknown hash as a
payload failure. Anchor matching is report acceptance policy, not carrier
restoration policy: cleanup and readback run regardless of the mask or any AP
validation error.

## Build

```sh
make pro-census
```

Outputs:

- `bin/ps5-linux-loader-1160-regular-census.elf`
- `bin/ps5-linux-loader-1160-pro-census.elf`

The target is separate from `all`. The build enforces `-Wcast-qual -Werror`,
checks that no VMCB write helper is present, records separate link maps, and
rejects production loader objects in either census ELF.

## Controlled run

The approved order is two cold-boot runs of the regular-control artifact on
the CFI-1115B, followed by one cold-boot run of the Pro artifact. Do not run
the Pro artifact until both regular-control reports complete and agree.

For each run:

1. Cold boot firmware 11.60 and run only the kernel exploit plus elfldr.
2. Mount a writable FAT32 or exFAT USB drive.
3. Send the census ELF to elfldr and keep the sender connection open.
4. Wait for the payload notification, let the console enter rest mode, then
   wake it normally.
5. Wait for the completion notification before removing the USB drive.

Before arming, the payload creates and fsyncs a unique, variant-labelled
`pending` report. A successful run atomically writes and fsyncs
`ps5-1160-regular-census.txt` or `ps5-1160-pro-census.txt` (or a numbered
variant), then removes the marker. A failed AP/report validation writes a
separate `.diagnostic` file and retains the pending marker. If the marker
remains, report whether GameOS resumed and cold reboot before another attempt.

The report is bounded text and contains hashes and selected physical addresses,
not raw HV bytes. It is private runtime evidence: do not attach it to a public
issue, release, or repository. A complete report establishes census facts only;
it does not approve the production Linux boot payload.
