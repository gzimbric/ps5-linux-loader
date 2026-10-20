#!/usr/bin/env python3
"""Fail-closed structural checks for the dedicated 11.60 build."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess


ROOT = Path(__file__).resolve().parents[1]
ELF = Path(os.environ.get("PS5_1160_ELF", ROOT / "bin/ps5-linux-loader-1160.elf"))
WAKE = ROOT / "shellcode_kernel_port_1160/shellcode_kernel_port_1160.bin"
INNER_HV = ROOT / "shellcode_hv_port_1160/shellcode_hv_port_1160.bin"
AP = ROOT / "shellcode_break_hv/break_hv.bin"
WAKE_ELF = ROOT / "shellcode_kernel_port_1160/shellcode_kernel_port_1160.elf"
INNER_HV_ELF = ROOT / "shellcode_hv_port_1160/shellcode_hv_port_1160.elf"
LOADER = ROOT / "source/loader.c"
STAGING = ROOT / "source/loader_staging_1160.c"
HV_DEFEAT = ROOT / "source/hv_defeat_1160.c"
BOOT_LINUX = ROOT / "shellcode_kernel/boot_linux.c"
CONFIG = ROOT / "include/config.h"
WAKE_MAKEFILE = ROOT / "shellcode_kernel_port_1160/Makefile"
WAKE_MAIN = ROOT / "shellcode_kernel/main.c"
INNER_HV_BOOT_LINUX = ROOT / "shellcode_hv/boot_linux.c"
INNER_HV_BOOT_LINUX_H = ROOT / "shellcode_hv/boot_linux.h"
INNER_HV_MAIN = ROOT / "shellcode_hv/main.c"
WAKE_UTILS = ROOT / "shellcode_kernel/utils.c"
BOOT_FILES = ROOT / "include/boot_files_1160.h"

RUN15_ELF_SHA256 = (
    "422b87ec39ca0edfce8dddd609c2eff1cc7adcb2732b7909b76fafbd60dd2336"
)
RUN15_WAKE_SHA256 = (
    "83756ca9eddffbcf075cb3660ec80755263ce147793922a54414b57c15d11319"
)
RUN15_WAKE_ELF_SHA256 = (
    "19c9e7fc396520bad8e49f8f4c97ffe10830d494a2fe9346d6d944ff6f09ac3a"
)

diag_mode_text = os.environ.get("PS5_1160_DIAGNOSTIC")
assert diag_mode_text in (None, "0", "1")
diagnostic_build = diag_mode_text == "1"
release_check_text = os.environ.get("PS5_1160_RELEASE_CHECK")
assert release_check_text in (None, "0", "1")
release_check = release_check_text == "1"
dma_e820_safe_text = os.environ.get("PS5_1160_DMA_E820_SAFE", "0")
assert dma_e820_safe_text in ("0", "1")
dma_e820_safe = dma_e820_safe_text == "1"
visible_refusals_text = os.environ.get("PS5_1160_VISIBLE_REFUSALS", "0")
assert visible_refusals_text in ("0", "1")
visible_refusals = visible_refusals_text == "1"
wifi_fw_text = os.environ.get("PS5_1160_WIFI_FW", "0")
assert wifi_fw_text in ("0", "1")
wifi_fw_enabled = wifi_fw_text == "1"
bounded_text = os.environ.get("PS5_1160_BOUNDED_BOOT_FILES", "0")
assert bounded_text in ("0", "1")
bounded = bounded_text == "1"
# The bounded build is the visible DMA E820 build with the size gates swapped.
assert not bounded or (dma_e820_safe and visible_refusals)
if diagnostic_build:
    diag_pre_text = os.environ.get("PS5_1160_DIAG_PRE_STAGE", "5")
    diag_op_text = os.environ.get("PS5_1160_DIAG_OP_LIMIT", "29")
    diag_clear_text = os.environ.get("PS5_1160_DIAG_CLEAR_MP3_BUFFERS", "0")
    diag_pre_stage = int(diag_pre_text, 0)
    diag_op_limit = int(diag_op_text, 0)
    diag_clear_mp3_buffers = int(diag_clear_text, 0)
    assert 0 <= diag_pre_stage <= 5
    assert 0 <= diag_op_limit <= 29
    assert diag_clear_mp3_buffers in (0, 1)


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

if release_check:
    assert diagnostic_build, "release check requires PS5_1160_DIAGNOSTIC=1"
    assert not dma_e820_safe, "Run 15 release check requires the original E820 map"
    assert not visible_refusals, "Run 15 release check requires printf-only refusals"
    assert not wifi_fw_enabled, "Run 15 release check has no Wi-Fi firmware range"
    assert not bounded, "Run 15 release check requires the exact Run 15 sizes"
    assert (diag_pre_stage, diag_op_limit, diag_clear_mp3_buffers) == (5, 29, 0), (
        "release check requires the hardware-tested Run 15 gates",
        diag_pre_stage,
        diag_op_limit,
        diag_clear_mp3_buffers,
    )
    assert hashlib.sha256(elf).hexdigest() == RUN15_ELF_SHA256
    assert hashlib.sha256(wake).hexdigest() == RUN15_WAKE_SHA256
    assert hashlib.sha256(WAKE_ELF.read_bytes()).hexdigest() == RUN15_WAKE_ELF_SHA256

assert_raw_blob_is_pic(WAKE_ELF, WAKE)
assert_raw_blob_is_pic(INNER_HV_ELF, INNER_HV)

assert 0 < len(wake) <= 0x5000
assert 0 < len(inner_hv) <= 0x2000
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
    12: 0xA57354,   # final #GP/#SX: add rsp,0x28; pop rbp; ret
    23: 0xD2B000,   # KERNEL_CODE_CAVE
    29: 0x62806F00,  # Sonic's executable identity-mapped HV cave
    30: 0x62847551,  # HV_HANDLE_VMEXIT_PA
    33: 0x3DB7A40,  # G_VBIOS, resolved by 0x10000-byte copy-loop xref
    34: 0xC800C0,   # transmitter_control
    35: 0xA88270,   # mp3_initialize wrapper
    36: 0xA86E70,   # mp3_invoke
    39: 0xC885D0,   # HV_MP_STARTUP_CALL
    41: 0x2D02000,  # DATA_CAVE (startup-AP resume carrier)
    42: 0x2A0EDE,   # startup #DB: add rsp,0x28; rep ret
}.items():
    assert off_1160[field_index * 8 : field_index * 8 + 8] == u64(value), hex(value)
# PS5_WIFI_FW_OFFSET and PS5_WIFI_FW_SIZE.  Zero makes the loader skip the
# firmware dump, which is what the Run 15 and DMA E820 builds shipped with.
if wifi_fw_enabled:
    assert off_1160[37 * 8 : 38 * 8] == u64(0x1585D90)
    assert off_1160[38 * 8 : 39 * 8] == u64(0x799BC)
    assert elf.count(b"lib/nxp/pcieuartiw620_combo_v1.bin\0") == 1
else:
    assert off_1160[37 * 8 : 39 * 8] == bytes(2 * 8)
assert u64(0x6284AC20) not in off_1160
assert off_1160[12 * 8 : 13 * 8] != off_1160[42 * 8 : 43 * 8]

# Sonic's complete post-stage HDMI sequence, translated entry-for-entry to
# authenticated 11.60 homologs.  Preserve the original 0x18-byte record ABI,
# order, EDI values, and the one two-argument call.
display_records = (
    (0x00362730, 0, 0, 0),
    (0x00362980, 0, 0, 0),
    (0x00362AD0, 0, 0, 0),
    (0x00362C90, 0, 0, 0),
    (0x00C16F70, 0, 0, 0),
    (0x00333410, 0, 0, 0),
    (0x00751F20, 0, 0, 0),
    (0x00B01800, 0, 0, 0),
    (0x005381C0, 0, 0, 0),
    (0x005383B0, 0, 0, 0),
    (0x00362AA0, 0, 0, 0),
    (0x00B88B80, 0, 0, 0),
    (0x00B896F0, 0, 0, 0),
    (0x00B89900, 0, 0, 0),
    (0x00B89A40, 0, 0, 0),
    (0x00334460, 0, 0, 0),
    (0x00334460, 1, 0, 0),
    (0x00334460, 2, 0, 0),
    (0x00334460, 3, 0, 0),
    (0x00362CC0, 0, 0, 0),
    (0x00538580, 0, 0, 0),
    (0x00538700, 0, 0, 0),
    (0x00B88C70, 0, 0, 0),
    (0x007585F0, 0, 0, 0),
    (0x009DC910, 1, 2, 0x7F0),
    (0x0053D9F0, 0, 0, 0),
    (0x00539460, 1, 0, 0),
    (0x00538ED0, 0, 0, 0),
    (0x00538D70, 0, 0, 0),
)
expected_display_table = b"".join(
    struct.pack("<QIIQ", offset, arg1, mode, arg2)
    for offset, arg1, mode, arg2 in display_records
)
display_table = elf_symbol_bytes(WAKE_ELF, "ps5_display_ops_1160")
assert len(display_table) == 29 * 0x18
assert display_table == expected_display_table
if diagnostic_build:
    assert elf_symbol_bytes(WAKE_ELF, "ps5_diag_pre_stage_1160") == struct.pack(
        "<I", diag_pre_stage
    )
    assert elf_symbol_bytes(
        WAKE_ELF, "ps5_diag_display_op_limit_1160"
    ) == struct.pack("<I", diag_op_limit)
    assert elf_symbol_bytes(
        WAKE_ELF, "ps5_diag_clear_mp3_buffers_1160"
    ) == struct.pack("<I", diag_clear_mp3_buffers)

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
printed_refusals = (
    b"11.60 loader REFUSED bzImage size",
    b"11.60 loader REFUSED initrd size",
)
shown_refusals = (
    b"11.60 loader refused bzImage: %zu bytes, needs exactly %llu.",
    b"11.60 loader refused initrd.img: %zu bytes, needs exactly %llu.",
)
bounded_refusals = (
    b"11.60 loader refused bzImage: %zu bytes, allowed %u to %llu.",
    b"11.60 loader refused bzImage: boot header check %d failed.",
    b"11.60 loader refused initrd.img: %zu bytes, allowed %u to %llu.",
    b"11.60 loader refused initrd.img: not a cpio or compressed initramfs.",
    b"11.60 loader refused boot files: bzImage and initrd.img need %zu bytes"
    b" staged, allowed %llu.",
    b"11.60 loader refused cmdline.txt: nokaslr would run Linux inside",
    b"11.60 loader refused cmdline.txt: mem= and memmap= can undo the DMA"
    b" reservation.",
    b"11.60 loader refused vram.txt: 0x%zx bytes, needs a multiple of 16 MiB"
    b" up to 0x%llx.",
    b"11.60 loader refused staging: %zu source pages would be overwritten by"
    b" the Linux copy, first page %zu at 0x%llx. Run the loader again.",
    b"11.60 loader refused staging: alias table page 0x%llx is inside the"
    b" Linux copy range.",
    b"11.60 loader refused staging: %s 0x%llx is inside the Linux copy range."
    b" Reboot before trying again.",
    b"wake code page",
    b"REFUSED wake copy preflight; no writes attempted",
    b"11.60 checked Linux alias staging failed. Nothing is armed, so the"
    b" loader can be run again.",
    b"11.60 #SX stack page 0x%llx is inside the Linux copy range",
    b"11.60 bounded: bzImage protocol 0x%x",
    b"11.60 bounded: wake copy 0x%llx-0x%llx",
    # What check_bzimage_1160 looks for to see CONFIG_RANDOMIZE_BASE.
    b"Physical KASLR disabled: no suitable memory region!",
)
if bounded:
    refusal_markers = bounded_refusals
    absent_refusals = (*printed_refusals, *shown_refusals)
elif visible_refusals:
    refusal_markers = shown_refusals
    absent_refusals = (*printed_refusals, *bounded_refusals)
else:
    refusal_markers = printed_refusals
    absent_refusals = (*shown_refusals, *bounded_refusals)
for marker in absent_refusals:
    assert marker not in elf, marker
for marker in (
    *refusal_markers,
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
boot_linux_source = BOOT_LINUX.read_text()
config_source = CONFIG.read_text()
wake_makefile = WAKE_MAKEFILE.read_text()
wake_main_source = WAKE_MAIN.read_text()
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
assert "VALIDATED_INITRD_SIZE_1160 54376639ULL" in loader_source

# The bounded checks mirror how the inner HV loads Linux.  If any of these
# lines change, revisit include/boot_files_1160.h before relaxing the audit.
inner_hv_boot_linux_source = INNER_HV_BOOT_LINUX.read_text()
boot_files_source = BOOT_FILES.read_text()
for required in (
    "uintptr_t kernel_pa = 0x100000;",
    "uintptr_t setup_pa = 0x10000;",
    "uintptr_t cmdline_pa = 0x20000;",
    "memcpy(shdr, &bzimage_bp->hdr, sizeof(struct setup_header));",
    "size_t setup_size = (shdr->setup_sects + 1) * 512;",
    "size_t kernel_size = shdr->syssize * 16;",
    "memcpy((void *)kernel_pa, (void *)(info.bzimage + setup_size), kernel_size);",
    "(void *)(kernel_pa + 0x200);",
    "bp->ext_ramdisk_image = info.initrd >> 32;",
    "append_e820_table(bp, 0x000100000, 0x03fffc000, E820_TYPE_RAM);",
    "append_e820_table(bp, 0x001000000, 0x040000000, E820_TYPE_RESERVED);",
):
    assert required in inner_hv_boot_linux_source, required
for required in (
    "#define BZ_LOAD_PA_1160 0x100000ULL",
    "#define BZ_DECOMPRESS_LIMIT_1160 0x3fffc000ULL",
    "#define BZ_MIN_VERSION_1160 0x020fU",
    "#define BZ_XLF_KERNEL_64_1160 0x0001U",
    "#define BZ_XLF_CAN_BE_LOADED_ABOVE_4G_1160 0x0002U",
    "if (setup_sects == 0 || setup_sects > BZ_MAX_SETUP_SECTS_1160)",
    "if (BZ_LOAD_PA_1160 + layout.payload_size > layout.decompress_base)",
    "layout.decompress_end > BZ_DECOMPRESS_LIMIT_1160)",
    # Keeps decompress_base + init_size from wrapping.
    "if (pref_address > BZ_DECOMPRESS_LIMIT_1160 ||",
    '#define BZ_KASLR_MESSAGE_1160 "Physical KASLR disabled: no suitable memory region!"',
    "return BZ_KASLR_1160;",
    "if (bz_u64_1160(image + 0x250) != 0)",
    "{6, {'0', '7', '0', '7', '0', '1'}},",
    "{6, {'0', '7', '0', '7', '0', '2'}},",
    "#define VRAM_TOP_1160 0x470000000ULL",
    "#define VRAM_UNIT_1160 0x1000000ULL",
    "#define HV_STACKS_END_1160 0x11000f000ULL",
):
    assert required in boot_files_source, required
assert "'0', '7', '0', '7', '0'}}" not in boot_files_source

# vram.txt: VRAM sits right below 0x470000000, programmed in 16 MiB units,
# and the RAM under it holds the wake copy and the 16 HV stacks.
assert "#define VRAM_BASE (0x470000000 - info.vram_size)" in (
    INNER_HV_BOOT_LINUX_H.read_text()
)
assert "#define MAXCPU 16" in INNER_HV_BOOT_LINUX_H.read_text()
assert "(uintptr_t)hv_base_rsp + ((uint64_t)(cpu_id)*hv_stack_size);" in (
    INNER_HV_MAIN.read_text()
)
assert "GCMC_VM_FB_OFFSET) = vram_start >> 24;" in inner_hv_boot_linux_source
assert "static_assert(HV_STACKS_END_1160 == hv_base_rsp + 15 * hv_stack_size," in (
    loader_source
)
assert 0x100000000 + 0x10000000 + 15 * 0x1000 == 0x11000F000
assert (0x470000000 - 0x11000F000) & ~0xFFFFFF == 0x35F000000

# KASLR has to stay on: nokaslr, mem= and memmap= are refused in the bounded
# build, before the Wi-Fi firmware is written to the boot drive.
assert 'cmdline_has_option_1160(cmdline, "mem=")' in loader_source
assert 'cmdline_has_option_1160(cmdline, "memmap=")' in loader_source
assert loader_source.count("dump_device_firmwares(initrd_path)") == 2
assert (
    "#if !PS5_1160_BOUNDED_BOOT_FILES\n  if (dump_device_firmwares(initrd_path)"
    in loader_source
)
assert loader_source.index('"memmap=")') < loader_source.rindex(
    "dump_device_firmwares(initrd_path)"
)

# The relaxed source page test relies on the wake blob copying forward, one
# byte at a time, bzImage then initrd, and on the cave size the blob fits.
wake_utils_source = WAKE_UTILS.read_text()
assert "for (uint64_t i = 0; i < len; i++) {\n    d[i] = s[i];" in wake_utils_source
for required in (
    "memcpy((void *)PHYS_TO_DMAP(info.bzimage), (void *)bzimage,",
    "memcpy((void *)PHYS_TO_DMAP(info.initrd), (void *)initrd, info.initrd_size);",
    "info.initrd = cave_bzImage + ALIGN_UP(info.bzimage_size, PAGE_SIZE);",
):
    assert required in boot_linux_source, required
assert boot_linux_source.index(
    "memcpy(&info, (void *)args.linux_info_va, sizeof(struct linux_info));"
) < boot_linux_source.index("memcpy((void *)PHYS_TO_DMAP(info.bzimage)")
assert "#define WAKE_CAVE_SIZE_1160 0x5000ULL" in staging_source
assert "#define KTEXT_1160_END 0xD30000ULL" in hv_defeat_source
assert "#define CODE_CAVE_CAPACITY (KTEXT_1160_END - 0xD2B000ULL)" in hv_defeat_source
assert 0xD30000 - 0xD2B000 == 0x5000 == 20480
assert "pa_in_wake_copy_1160(sx_ist_pa - PAGE_SIZE)" in hv_defeat_source
assert "if (preflight_wake_copy_1160(&tx, pages, page_count)) {" in staging_source
assert "#error \"the bounded 11.60 build must show its refusals\"" in loader_source
# Payload menus only show notify().  Every lowercase "refused" message,
# including the bounded ones, has to go through it.
for source in (loader_source, staging_source):
    for match in re.finditer(r'"11\.60 loader refused', source):
        assert source[: match.start()].rstrip().endswith("notify("), (
            source[match.start() : match.start() + 72]
        )
assert (
    'notify("11.60 #SX stack page 0x%llx is inside the Linux copy range\\n"'
    in hv_defeat_source
)
assert "#define MAX_STAGED_BOOT_FILES_1160 (160ULL * 1024ULL * 1024ULL)" in boot_files_source
assert "static_assert(MAX_COMBINED_MAPPING == MAX_STAGED_BOOT_FILES_1160," in staging_source
assert loader_source.count("check_bzimage_1160(bzimage, bzimage_size, &bz_layout)") == 1
assert loader_source.count("check_initrd_1160(initrd, initrd_size)") == 1
assert "#define MAX_COMBINED_MAPPING (160ULL * 1024ULL * 1024ULL)" in staging_source
assert "#define cave_bzImage cave_linux_info + PAGE_SIZE" in config_source
assert "#define hv_base_rsp (cave + 0x10000000ULL)" in config_source

# The wake copy covers [cave, 0x100009000 + bzImage + initrd).  With the
# 160 MiB staging cap it ends below CPU 0's HV stack and inside the 1-GiB
# identity leaf that maps the cave.
cave_pa = 0x100000000
cave_bzimage_pa = cave_pa + 0x3000 + 0x2000 + 0x4000
wake_copy_cap_end = cave_bzimage_pa + 160 * 1024 * 1024
assert cave_bzimage_pa == 0x100009000
assert wake_copy_cap_end <= cave_pa + 0x10000000 - 0x1000
assert wake_copy_cap_end <= cave_pa + 0x40000000
# The exact Run 15 files: 1 + 776 + 3,319 logical pages, copy end 0x1040048bf.
assert cave_bzimage_pa + 776 * 0x4000 + 54376639 == 0x1040048BF
assert 0x100000 + 792640 * 16 == 0xD18400 <= 0x1000000
assert 0x1000000 + 0x2AC9000 <= 0x3FFFC000

# The exact gates must not reach the bounded ELF, and must stay in the others.
exact_size_immediates = (u32(12702720), u32(54376639))
if bounded:
    for value in exact_size_immediates:
        assert value not in elf, value
else:
    for value in exact_size_immediates:
        assert value in elf, value

# The display-enabled build mirrors Sonic's pre-Linux handoff and must never
# silently regress to the run-7 headless compile.  Its two large MP3 buffers
# live in the checked, retained tail of the linux_info page so the exact
# hardware-proven 0x5000 executable cave is not moved.
assert "SHELLCODE_1160_HEADLESS" not in wake_makefile
assert "PS5_1160_DIAG_CLEAR_MP3_BUFFERS ?= 0" in wake_makefile
assert "-DPS5_1160_DIAG_CLEAR_MP3_BUFFERS=" in wake_makefile

# Match the static Sonic layout exactly inside the retained 0x4000-byte page:
# rsp[1282] at +0x1000, an 0x18-byte gap, then req[1281] at +0x2420.
mp3_rsp_offset = 0x1000
mp3_rsp_size = 1282 * 4
mp3_req_offset = 0x2420
mp3_req_size = 1281 * 4
assert 0xC38 <= mp3_rsp_offset
assert mp3_rsp_offset + mp3_rsp_size == 0x2408
assert mp3_rsp_offset + mp3_rsp_size + 0x18 == mp3_req_offset
assert mp3_req_offset + mp3_req_size == 0x3824
assert mp3_req_offset + mp3_req_size <= 0x4000
for required in (
    "memcpy((void *)PHYS_TO_DMAP(0xC0000), (void *)g_vbios, 0x10000)",
    "dp_enable_link_phy(4, 30)",
    "wait_for_transmitter()",
    "read_tsc() - start <= 349999999ULL",
    "mp3_initialize(0)",
    "mp3_set_hdcp_packet(0, 1)",
    "mp3_enable_output(0, 1)",
    "MP3_RSP_OFFSET 0x1000ULL",
    "MP3_REQ_OFFSET 0x2420ULL",
    "MP3_RSP_WORDS * sizeof(int) + 0x18ULL ==",
    "Sonic MP3 buffers must remain 32-byte aligned",
    "args.linux_info_va + MP3_REQ_OFFSET",
    "args.linux_info_va + MP3_RSP_OFFSET",
):
    assert required in boot_linux_source, required
assert "#if !SHELLCODE_1160_ONLY\n    clear_mp3_buffers();\n#endif" in boot_linux_source
assert u32(349999999) in wake
display_order = (
    "boot_linux();",
    "run_ps5_display_ops_1160();",
    'printf("Linux prepared OK\\n");',
    "smp_rendezvous(",
)
only_1160_main = wake_main_source.split("#if SHELLCODE_1160_ONLY", 2)[2].split(
    "#else", 1
)[0]
cursor = 0
for step in display_order:
    cursor = only_1160_main.index(step, cursor) + len(step)
offsets_present_source = hv_defeat_source.split(
    "static int offsets_present", 1
)[1].split("static int walk_page", 1)[0]
for display_offset in (
    "env_offset.G_VBIOS",
    "env_offset.FUN_TRANSMITTER_CONTROL",
    "env_offset.FUN_MP3_INITIALIZE",
    "env_offset.FUN_MP3_INVOKE",
):
    assert display_offset in offsets_present_source, display_offset

# Sonic uses two semantically different stack pivots.  #DB has no error code,
# whereas #GP/#SX have one extra qword that the pop-rbp pivot must consume.
assert "gate_encode(kg(env_offset.GAD_PIVOT_ADD_RSP28_RET)" in hv_defeat_source
assert hv_defeat_source.count(
    "setidt(13, kg(env_offset.GAD_ADD_RSP_28_POP_RBP_RET), 7);"
) == 1
assert hv_defeat_source.count(
    "setidt(30, kg(env_offset.GAD_ADD_RSP_28_POP_RBP_RET), 7);"
) == 1
assert "setidt(13, kg(env_offset.GAD_PIVOT_ADD_RSP28_RET)" not in hv_defeat_source
assert "setidt(30, kg(env_offset.GAD_PIVOT_ADD_RSP28_RET)" not in hv_defeat_source
for gate_field in (
    "gate.gd_selector = GSEL(GCODE_SEL, SEL_KPL);",
    "gate.gd_type = SDT_SYSIGT;",
    "gate.gd_dpl = SEL_KPL;",
    "gate.gd_p = 1;",
):
    assert hv_defeat_source.count(gate_field) == 1, gate_field
assert hv_defeat_source.count(
    "kwrite64(kg(env_offset.COMMON_TSS) + TSS_IST(7), sx_ist + 0x1000);"
) == 1
assert hv_defeat_source.count(
    "kwrite64(kg(env_offset.ACPIGBL_FACS), kg(env_offset.ACPIGBL_FACS) - 8);"
) == 1

sx_rop_source = hv_defeat_source.split("static int build_sx_rop", 1)[1].split(
    "static void setidt", 1
)[0]
rop_steps = (
    "*p++ = kg(env_offset.GAD_POP_RDI_RET);",
    "*p++ = kg(env_offset.KERNEL_CODE_CAVE);",
    "*p++ = kg(env_offset.GAD_POP_RSI_RET);",
    "*p++ = kernel_cave_shellcode;",
    "*p++ = kg(env_offset.GAD_POP_RDX_RET);",
    "*p++ = shellcode_len;",
    "*p++ = kg(env_offset.FUN_MEMCPY);",
    "*p++ = kg(env_offset.KERNEL_CODE_CAVE);",
)
cursor = 0
for step in rop_steps:
    cursor = sx_rop_source.index(step, cursor) + len(step)


def pivot_distance_from_chain(frame_qwords: int, pops_after_add: int) -> int:
    return -(frame_qwords * 8) + 0x28 + (pops_after_add * 8)


assert pivot_distance_from_chain(5, 0) == 0  # #DB/no-pop reaches the chain.
assert pivot_distance_from_chain(6, 1) == 0  # #GP/#SX/pop reaches the chain.
assert pivot_distance_from_chain(6, 0) == -8  # The run-6 mismatch did not.

# Keep the proven absolute-jump/identity-map sequence and ensure its 25-byte
# transition stub fits entirely in the verified 0x100-byte HV padding window.
assert "mov rax, 0xAAAAAAAA" in boot_linux_source
assert "mov    cr3, rax" in boot_linux_source
assert "sizeof(shellcode_jmp) == 9" in boot_linux_source
assert "sizeof(shellcode_identity_and_jmp) == 25" in boot_linux_source
assert (0x62806F00 & 0xFFF) == 0xF00
assert 0x62806F00 + 25 <= 0x62807000
for identity_entry in (
    "0x0000000000000083",
    "0x0000000040000083",
    "0x0000000080000083",
    "0x00000000C0000083",
    "0x0000000100000083",
):
    assert boot_linux_source.count(identity_entry) == 1, identity_entry
assert "#define cave 0x100000000ULL" in config_source
assert "cave_hv_paging + 0x3000ULL" in config_source

wake_disassembly = tool_output("x86_64-elf-objdump", "-d", "-Mintel", WAKE_ELF)
boot_linux_disassembly = re.search(
    r"<boot_linux>:\n(.*?)(?=\n[0-9a-f]+ <[^>]+>:)",
    wake_disassembly,
    re.DOTALL,
)
assert boot_linux_disassembly
boot_linux_body = boot_linux_disassembly.group(1)


def instruction_position(body: str, pattern: str, start: int = 0) -> int:
    match = re.search(pattern, body[start:])
    assert match, pattern
    return start + match.start()


if diagnostic_build:
    # PRE0 must branch around every display pre-stage while retaining the
    # exact PRE1..PRE5 sequence for later no-UART hardware bisection.
    pre_cursor = instruction_position(
        boot_linux_body, r"<ps5_diag_pre_stage_1160>"
    )
    for gate in (
        r"\btest\s+ebx,ebx",
        r"<g_vbios>",
        r"\bcmp\s+ebx,0x1",
        r"<transmitter_control>",
        r"\bcmp\s+ebx,0x2",
        r"<mp3_initialize>",
        r"<mp3_invoke>",
        r"<ps5_diag_clear_mp3_buffers_1160>",
        r"\bcmp\s+ebx,0x3",
        r"\bmov\s+edi,0x15",
        r"<mp3_invoke>",
        r"\bcmp\s+ebx,0x4",
        r"\bmov\s+edi,0x16",
        r"<mp3_invoke>",
    ):
        pre_cursor = instruction_position(boot_linux_body, gate, pre_cursor + 1)

    # The independently auditable clear flag must branch directly to the
    # zero-argument MP3 initializer, skipping only the two buffer-clear loops.
    clear_bypass = re.search(
        r"<ps5_diag_clear_mp3_buffers_1160>.*?"
        r"\bje\s+([0-9a-f]+)\s+<boot_linux\+.*?\n"
        r".*?^\s*([0-9a-f]+):[^\n]*\bxor\s+edi,edi\n"
        r"^\s*[0-9a-f]+:[^\n]*\bcall\s+rsi\b",
        boot_linux_body,
        re.DOTALL | re.MULTILINE,
    )
    assert clear_bypass
    assert clear_bypass.group(1) == clear_bypass.group(2)

display_loop = re.search(
    r"<run_ps5_display_ops_1160>:\n(.*?)(?=\n[0-9a-f]+ <[^>]+>:)",
    wake_disassembly,
    re.DOTALL,
)
assert display_loop
display_loop_body = display_loop.group(1)
display_leaf = re.search(
    r"<dispatch_ps5_display_op_1160(?:\.[^>]*)?>:\n"
    r"(.*?)(?=\n[0-9a-f]+ <[^>]+>:)",
    wake_disassembly,
    re.DOTALL,
)
assert display_leaf
display_leaf_body = display_leaf.group(1)
leaf_bound = instruction_position(display_leaf_body, r"\bcmp\s+edi,0x1c")
leaf_arg1 = instruction_position(
    display_leaf_body, r"\bmov\s+edi,DWORD PTR \[[^\]]+\+0x8\]"
)
leaf_mode = instruction_position(
    display_leaf_body, r"\bcmp\s+DWORD PTR \[[^\]]+\+0xc\],0x2"
)
leaf_arg2 = instruction_position(
    display_leaf_body, r"\bmov\s+rsi,QWORD PTR \[[^\]]+\+0x10\]"
)
assert leaf_bound < leaf_arg1 < leaf_mode < leaf_arg2
assert not re.search(r"\b(?:push|call)\b|\bsub\s+rsp,", display_leaf_body)
assert not re.search(r"\bcall\b", display_leaf_body)
assert len(re.findall(r"\bjmp\s+(?:QWORD PTR \[[^\]]+\]|r[a-z0-9]+)\b", display_leaf_body)) == 2
leaf_call_pattern = (
    r"\bcall\s+[0-9a-f]+\s+"
    r"<dispatch_ps5_display_op_1160(?:\.[^>]*)?>"
)
assert len(re.findall(leaf_call_pattern, display_loop_body)) == 1
if diagnostic_build:
    limit_compare = instruction_position(
        display_loop_body,
        r"\bcmp\s+[a-z0-9]+,DWORD PTR \[[^\]]+\].*"
        r"<ps5_diag_display_op_limit_1160>",
    )
    conditional_exit = instruction_position(
        display_loop_body,
        r"\bjae\s+[0-9a-f]+\s+<run_ps5_display_ops_1160\+",
        limit_compare + 1,
    )
    leaf_call = instruction_position(
        display_loop_body, leaf_call_pattern
    )
    assert limit_compare < conditional_exit < leaf_call
else:
    assert re.search(r"\bcmp\s+[a-z0-9]+,0x1d", display_loop_body)
patch_hv_disassembly = re.search(
    r"<patch_hv>:\n(.*?)(?=\n[0-9a-f]+ <boot_linux>:)",
    wake_disassembly,
    re.DOTALL,
)
assert patch_hv_disassembly
patch_hv_body = patch_hv_disassembly.group(1)
assert re.search(r"\bmov\s+edx,0x9\b", patch_hv_body)
assert re.search(r"\bmov\s+edx,0x19\b", patch_hv_body)
assert len(re.findall(r"call\s+.*<memcpy>", patch_hv_body)) == 2

# When the local live dumps are supplied, tie the portable structural audit to
# the exact 11.60 bytes used for this release candidate.
ktext_dump_path = os.environ.get("PS5_1160_KTEXT_DUMP")
if release_check:
    assert ktext_dump_path, "release check requires PS5_1160_KTEXT_DUMP"
if ktext_dump_path:
    ktext_dump = Path(ktext_dump_path).read_bytes()
    assert len(ktext_dump) == 0xD30000
    assert hashlib.sha256(ktext_dump).hexdigest() == (
        "0e3439b5b4d249010fede6ad31d8969e01ad56824d3f80554545745a8f7260d5"
    )
    assert ktext_dump[0xA57354 : 0xA5735A] == bytes.fromhex("4883c4285dc3")
    assert ktext_dump[0x2A0EDE : 0x2A0EE4] == bytes.fromhex("4883c428f3c3")

    # Authenticated display handoff offsets.  The VBIOS storage itself lies in
    # kdata, outside this text dump, so resolve it from the exact RIP-relative
    # reference in the 0x10000-byte VBIOS copy loop.
    vbios_copy = ktext_dump[0xC7FD10 : 0xC7FD42]
    assert vbios_copy.startswith(
        bytes.fromhex("554889e5415741564155415453504889fb4885ff741c488d0d")
    )
    assert bytes.fromhex("483d0000010075ee") in vbios_copy
    vbios_disp = int.from_bytes(ktext_dump[0xC7FD29 : 0xC7FD2D], "little", signed=True)
    assert 0xC7FD2D + vbios_disp == 0x3DB7A40
    assert ktext_dump[0xC800C0 : 0xC800DF].startswith(
        bytes.fromhex("554889e54156534189fe488d3d")
    )
    assert ktext_dump[0xA88270 : 0xA8827D] == bytes.fromhex(
        "554889e5535089febf50052105"
    )
    assert ktext_dump[0xA86E70 : 0xA86E85] == bytes.fromhex(
        "554889e54157415641554154534881ec480a000048"
    )

    # Freeze every unique native 11.60 HDMI-operation target to the same
    # authenticated dump used for the structural 13.60 -> 11.60 match.
    display_target_hashes = (
        (0x00362730, 0x24E, "3ec783c9b6b9b6133fae1fc0e7084154116e950bc0c0f67fb81f9b451b16c08f"),
        (0x00362980, 0x11A, "0c7eedf44d576716f88a4b99b0622cc8c4f5d1fd2277792613879a5c28ab770d"),
        (0x00362AD0, 0x158, "3ea96f6dd479ce0a4568e744864616b3da20af7e80f82f3dbe8fe5abacdac1ef"),
        (0x00362C90, 0x00C, "1794941374d37a7da6e3cfcf3bd6273cf554566475c8b448d66d7df64e640345"),
        (0x00C16F70, 0x010, "b7055a771b73e246892e6b770dd938c40c858b735e811617e77b2ab240c6a8c6"),
        (0x00333410, 0x010, "cbf4a75b1b5d477967f04eb7094bb9cd3db1bceb2a5a92b525c1e73eaab3f9ce"),
        (0x00751F20, 0x01E, "d20c572479055595e6d7e88373a9ec26f59f9c299e73f3317f6a76c95b887781"),
        (0x00B01800, 0x010, "5f24b7557edf5d173d2895c1da631d8de196335c3ae576383c011445fafda02d"),
        (0x005381C0, 0x1E3, "6bd98a138bfd654620729b3315153c4e0ca1b73b8cc12d5bb631a0fc39a29c99"),
        (0x005383B0, 0x1C1, "96288b7e10cdca59ac0cd96331a773dc9600f69f9d1537a3e816ca671d8f4d56"),
        (0x00362AA0, 0x00C, "b223afb164de3fddf4711b9f44ef3dbceeafd70019befa2d42ce916f6ce54631"),
        (0x00B88B80, 0x0E2, "24dd2b2fbec6db2710cfb741174345850aed575ecebde752c6d4485d42caeff0"),
        (0x00B896F0, 0x208, "5f79968a1468d733203346db45d5c0d1d1a4fcdb4c2c9cea6f245062795512bb"),
        (0x00B89900, 0x13F, "99232d2ac711f35dc1d2bc8053bfa74ed602cb0b590eb8a5f9570dfd5459f6ce"),
        (0x00B89A40, 0x123, "0b52ba99a030398b2e3ca09df77e9fddba4f7da50f1ea3354d81c3b2b68c68b8"),
        (0x00334460, 0x186, "9ec5255b3a25c6235cd2cbe61481e240c0c1e72ea855ba72a87940001ec5f273"),
        (0x00362CC0, 0x018, "45aac6842559173af08ad49da38e5638b6b9d424d8a2d9be9b58266d7eefa3d9"),
        (0x00538580, 0x17B, "8800618803f998e0fadd4c5c96a6eb2d19898593c84dc35a4339ee3f0ba7a6af"),
        (0x00538700, 0x164, "2d3b0fa96fbc8b9994f77dc276eaf4dde84dfb2273f559759bfc7e30c0811792"),
        (0x00B88C70, 0x13D, "3f87fa35742af07c2f1d64c34a698b6ec593fc9dc0cd3026ddfffd548635f003"),
        (0x007585F0, 0x00C, "e0a7d5ece47661d1ed1afd64d4e58d0acdcba91da5936822974fc43cbac7709a"),
        (0x009DC910, 0x0F2, "54fe8672776dd2c6c7710fff1f712bdbd61467c1867ffb79cab68a1cc57dc0f1"),
        (0x0053D9F0, 0x8C4, "c60f615906e87b8919e8533d1c77615d1586ccb61ce5a6c22de30833a482f051"),
        (0x00539460, 0x254D, "cc48bc84fd46ba6e9a3c7e80219d0341c51644f9612a4848250ac36ed3119727"),
        (0x00538ED0, 0x15B, "f70526de9c0fdc85bd227d46e0a529a3d6d8ced0327988496e2b5938d96d19e6"),
        (0x00538D70, 0x159, "186fa44933eb03ffb74fba976b0877d3f3004c3033e17b7ed4db84fbea978e2c"),
    )
    assert {offset for offset, _, _ in display_target_hashes} == {
        offset for offset, _, _, _ in display_records
    }
    for offset, size, expected_hash in display_target_hashes:
        assert hashlib.sha256(ktext_dump[offset : offset + size]).hexdigest() == expected_hash

    # Operation 26 has a long, firmware-specific cold tail.  Also pin the
    # structurally matched entry prefix through the last instruction before
    # its packet-selection branch so identity remains independently visible.
    assert hashlib.sha256(ktext_dump[0x539460 : 0x539512]).hexdigest() == (
        "6ccf76c082d8918d94905b81ec61ac295299b6265e2cdaaebc7ae68fe31a808a"
    )

hv_dump_path = os.environ.get("PS5_1160_HV_DUMP")
if release_check:
    assert hv_dump_path, "release check requires PS5_1160_HV_DUMP"
if hv_dump_path:
    hv_dump = Path(hv_dump_path).read_bytes()
    assert len(hv_dump) == 0x62000
    assert hashlib.sha256(hv_dump).hexdigest() == (
        "ada1624ce72ef2fe4e9400e13d544116be4050f5187234a1fa19c6bd26988fee"
    )
    assert hv_dump[0x6F00 : 0x7000] == b"\xcc" * 0x100

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

# The official 13.60 loader now quarantines 16 MiB through 1 GiB for DMA.
# Verify the emitted boot_linux instructions, not only the source switch, so a
# stale nested blob cannot accidentally pass the candidate audit.
inner_hv_boot_linux = tool_output(
    "x86_64-elf-objdump", "-d", "-Mintel", "--disassemble=boot_linux", INNER_HV_ELF
)
old_e820_values = ("0x3fefc000", "0x3fffc000")
safe_e820_values = ("0xf00000", "0x1000000", "0x3f000000")


def exact_hex_count(text: str, value: str) -> int:
    return len(re.findall(rf"(?<![0-9a-f]){re.escape(value)}(?![0-9a-f])", text))


if dma_e820_safe:
    for value in safe_e820_values:
        assert exact_hex_count(inner_hv_boot_linux, value) == 1, value
    for value in old_e820_values:
        assert exact_hex_count(inner_hv_boot_linux, value) == 0, value
else:
    for value in old_e820_values:
        assert exact_hex_count(inner_hv_boot_linux, value) == 1, value
    for value in safe_e820_values:
        assert exact_hex_count(inner_hv_boot_linux, value) == 0, value

diag_label = (
    f" diag-pre={diag_pre_stage} diag-ops={diag_op_limit} "
    f"diag-clear-mp3={diag_clear_mp3_buffers}"
    if diagnostic_build
    else ""
)
print(
    f"11.60 audit OK:{diag_label} elf={len(elf)} wake={len(wake)} "
    f"inner_hv={len(inner_hv)} ap={len(ap)} dma-e820-safe={int(dma_e820_safe)}"
    f" visible-refusals={int(visible_refusals)} wifi-fw={int(wifi_fw_enabled)}"
    f" bounded-boot-files={int(bounded)}"
)
