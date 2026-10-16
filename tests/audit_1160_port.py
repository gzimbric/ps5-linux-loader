#!/usr/bin/env python3
"""Fail-closed structural checks for the dedicated 11.60 build."""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
ELF = ROOT / "bin/ps5-linux-loader-1160.elf"
WAKE = ROOT / "shellcode_kernel_port_1160/shellcode_kernel_port_1160.bin"
INNER_HV = ROOT / "shellcode_hv_port_1160/shellcode_hv_port_1160.bin"
AP = ROOT / "shellcode_break_hv/break_hv.bin"
WAKE_ELF = ROOT / "shellcode_kernel_port_1160/shellcode_kernel_port_1160.elf"
INNER_HV_ELF = ROOT / "shellcode_hv_port_1160/shellcode_hv_port_1160.elf"
LOADER = ROOT / "source/loader.c"
STAGING = ROOT / "source/loader_staging_1160.c"
HV_DEFEAT = ROOT / "source/hv_defeat_1160.c"


def u32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def u64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def tool_output(tool: str, *args: object) -> str:
    return subprocess.check_output(
        [tool, *(str(arg) for arg in args)], text=True
    )


def elf_symbol_bytes(path: Path, symbol: str) -> bytes:
    """Return one file-backed ELF symbol without relying on byte uniqueness."""
    symbols = tool_output("x86_64-elf-nm", "-anS", path)
    match = re.search(
        rf"^([0-9a-f]+)\s+([0-9a-f]+)\s+\S\s+{re.escape(symbol)}$",
        symbols,
        re.MULTILINE,
    )
    assert match, symbol
    address = int(match.group(1), 16)
    size = int(match.group(2), 16)

    sections = tool_output("x86_64-elf-readelf", "-SW", path)
    for row in sections.splitlines():
        section = re.search(
            r"\[\s*\d+\]\s+\S+\s+(\S+)\s+([0-9a-f]+)\s+"
            r"([0-9a-f]+)\s+([0-9a-f]+)\s+",
            row,
        )
        if not section or section.group(1) == "NOBITS":
            continue
        section_address = int(section.group(2), 16)
        section_offset = int(section.group(3), 16)
        section_size = int(section.group(4), 16)
        if section_address <= address and address + size <= section_address + section_size:
            start = section_offset + address - section_address
            return path.read_bytes()[start : start + size]
    raise AssertionError(f"file-backed section for {symbol} not found")


def assert_raw_blob_is_pic(path: Path, raw_path: Path) -> None:
    """A copied raw section must not depend on its ELF link address."""
    header = tool_output("x86_64-elf-readelf", "-h", path)
    assert re.search(r"Type:\s+DYN\b", header), path

    relocations = tool_output("x86_64-elf-readelf", "-rW", path)
    assert "There are no relocations in this file." in relocations, path

    sections = tool_output("x86_64-elf-readelf", "-SW", path)
    match = re.search(
        r"\]\s+\.shell_code\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+"
        r"([0-9a-f]+)\s+",
        sections,
    )
    assert match, path
    start = int(match.group(1), 16)
    file_offset = int(match.group(2), 16)
    size = int(match.group(3), 16)
    end = start + size

    elf_bytes = path.read_bytes()
    assert raw_path.read_bytes() == elf_bytes[file_offset : file_offset + size], (
        path,
        raw_path,
    )
    assert not re.search(r"\s\.(?:got|got\.plt|plt|plt\.got)\s", sections), path

    dynamic = tool_output("x86_64-elf-readelf", "-dW", path)
    assert "(NEEDED)" not in dynamic, path
    assert tool_output("x86_64-elf-nm", "-u", path).strip() == "", path

    symbols = tool_output("x86_64-elf-nm", "-n", path)
    main = re.search(r"^([0-9a-f]+)\s+T\s+main$", symbols, re.MULTILINE)
    assert main and int(main.group(1), 16) == start, path

    # Catch the exact regression that originally left raw linked VMAs such as
    # `mov rbx,0x2c60` in a blob later copied somewhere else.  The one
    # legitimate in-range scalar is the exact firmware number used by the wake
    # validator.  Every symbolized PC-relative target must remain inside the
    # section that objcopy extracts.
    disassembly = tool_output("x86_64-elf-objdump", "-d", "-Mintel", path)
    bad = []
    for line in disassembly.splitlines():
        instruction = line.split("#", 1)[0]
        immediate = re.search(
            r"\bmov(?:abs)?\s+[^,]+,0x([0-9a-f]+)\b", instruction
        )
        absolute_memory = re.search(r"\[(?:ds:)?0x([0-9a-f]+)\]", instruction)
        for candidate in (immediate, absolute_memory):
            if candidate:
                value = int(candidate.group(1), 16)
                if start <= value < end and value != 0x1160:
                    bad.append(line.strip())

        for target in re.finditer(r"(?:#\s*)?([0-9a-f]+)\s+<[^>]+>", line):
            value = int(target.group(1), 16)
            if not (start <= value < end):
                bad.append(line.strip())
    assert not bad, f"absolute linked VMA in {path}: {bad}"


elf = ELF.read_bytes()
wake = WAKE.read_bytes()
inner_hv = INNER_HV.read_bytes()
ap = AP.read_bytes()

assert_raw_blob_is_pic(WAKE_ELF, WAKE)
assert_raw_blob_is_pic(INNER_HV_ELF, INNER_HV)

assert 0 < len(wake) <= 0x5000
assert wake.count(bytes.fromhex("aa11aa11aa11aa11")) == 1
assert wake.count(inner_hv) == 1
assert elf.count(wake) == 1
assert elf.count(ap) == 1
assert hashlib.sha256(ap).hexdigest() == (
    "918ac3d8ccc16ec31e40fc069cf5ba46b168afd493acb12461adc8f96c7ee997"
)

# Validate the fields in the actual off_1160 object. Whole-ELF byte counts are
# brittle because an immediate or embedded blob can legitimately contain the
# same eight bytes.
off_1160 = elf_symbol_bytes(ELF, "off_1160")
assert len(off_1160) == 51 * 8
for field_index, value in {
    4: 0x39CD1F0,   # ACPIGBL_FACS
    11: 0x2E7E40,   # FUN_MEMCPY
    23: 0xD2B000,   # KERNEL_CODE_CAVE
    39: 0xC885D0,   # HV_MP_STARTUP_CALL
    41: 0x2D02000,  # RESUME_DATA_CAVE
}.items():
    assert off_1160[field_index * 8 : field_index * 8 + 8] == u64(value), hex(value)

# Do not accidentally ship the corresponding 13.60 offsets.
for value in (0x39C9490, 0x2590B0, 0xCB92C0):
    assert u32(value) not in elf, hex(value)

assert elf.count(u32(0x11600005)) >= 2
assert elf.count(u32(0x840FD0)) >= 2
assert b"PS5 Pro HV layout is not validated" in elf

# The dedicated build must use the live-tested Stage-1A/1B checked alias
# transaction rather than entering the upstream unchecked helper from
# fetch_linux.  Keep every checkpoint in the final ELF so a headless run can
# identify the precise boundary reached.
for marker in (
    b"11.60 loader REFUSED bzImage size",
    b"11.60 loader REFUSED initrd size",
    b"selective CFI/wake-cave text permissions complete",
    b"failed; retaining all backing until cold reboot",
    b"building checked source plan",
    b"11.60 alias staging: source preflight passed",
    b"target range preflight passed",
    b"installing checked aliases",
    b"all aliases installed",
    b"verifying alias PTEs",
    b"PASS; source, info, and page-table backing retained",
    b"install/verify failed; rolling back",
    b"rollback verified",
):
    assert marker in elf, marker

loader_source = LOADER.read_text()
staging_source = STAGING.read_text()
hv_defeat_source = HV_DEFEAT.read_text()
assert loader_source.count("stage_linux_aliases_1160(") == 1
for required in (
    "get_proc_pmap_checked",
    "source_page_pa",
    "preflight_target_page",
    "tx_install_page",
    "verify_aliases",
    "tx_rollback",
    "verify_targets_absent",
    "retained_staging.active = 1",
    "writes_started = 0",
):
    assert required in staging_source, required
assert "mlock(" not in staging_source
assert "VALIDATED_BZIMAGE_SIZE_1160 12702720ULL" in loader_source
assert "VALIDATED_INITRD_SIZE_1160 28777476ULL" in loader_source

# Firmware 11.60 XOM remains NPT-enforced until the startup-AP strike.  A live
# ktext content read before that strike hard-freezes the console even after the
# guest XO bit is cleared.  Preserve Sonic's ordering: metadata/PTE validation
# now, copy into the cave only after NPT is disabled during resume.
assert "page-table-only wake-cave validation passed" in hv_defeat_source
validate_wake_cave_source = hv_defeat_source.split(
    "static int validate_wake_cave", 1
)[1].split("static uint64_t tss_ist_slot", 1)[0]
for forbidden_read in ("kread(", "kread64(", "kernel_copyout(", "pa_to_dmap("):
    assert forbidden_read not in validate_wake_cave_source, forbidden_read

# Sonic's two high-firmware inner-HV deltas: reserved E820 start and direct
# UART enable.  Check operand constants rather than compiler register choice.
assert u64(0x980000000) in inner_hv
assert u32(0xC0115110) in inner_hv
assert u32(0xFFFFFDFF) in inner_hv

print(
    f"11.60 audit OK: elf={len(elf)} wake={len(wake)} "
    f"inner_hv={len(inner_hv)} ap={len(ap)}"
)
