# Firmware 11.60 wake-source candidate

This branch is a source-level comparison candidate for porting the public
PS5 Linux wake blob to firmware 11.60. It is intentionally **not** a payload
to send to a console.

The pinned public source has no 13.xx outer hypervisor/resume dispatcher. Its
top-level path only supports firmware below 8.00. Consequently, this branch
does not invent an 11.60 outer path or import the older custom pLinux path.
It limits the port to behavior that can be expressed safely in the public
wake-source ABI:

- preserve the public `shellcode_kernel_args` layout at exactly 0x98 bytes;
- recognize exactly firmware `0x1160` in the embedded wake entry;
- validate all mutation-critical 11.60 arguments before doing anything;
- return without UART, CFI, hypervisor, display, or Linux mutations;
- preserve unknown optional offsets as NULL;
- make UART, VBIOS, transmitter, and MP3 operations optional for a future
  headless path.

No 11.60 offsets are added here. In particular, no values have been copied
from unverified comments or inferred from another firmware. The exact 11.60
branch remains deliberately non-arming until a separately audited outer
resume path and every required firmware-specific input are available.

The 13.xx-only display-operation concepts observed in Sonic's binary are not
part of this candidate.

## Dedicated inert wake blob

`make wake-1160` builds and checks a separate exact-11.60 blob under
`shellcode_kernel_1160/`. It is not a prerequisite of the ordinary
multi-firmware `all` target and does not change that target's linked inputs.

The dedicated blob links only its 11.60 entry and the inline argument
validator. It does not link the legacy HV defeat, Linux boot, UART, VBIOS,
transmitter, MP3, printf, SMP, or vmmcall sources. Its entry validates the
0x98 ABI block and returns; it cannot arm resume or Linux.

The dedicated linker script gives its sole load segment RX permissions and
rejects shell code larger than 0x4000 bytes. The `check` target independently
checks the binary size, unique argument marker, absence of relocations,
absence of forbidden legacy/display symbols, and RX-without-W permissions.
