OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(wake_1160_entry)

PHDRS
{
    wake PT_LOAD FLAGS(5); /* PF_R | PF_X */
}

SECTIONS
{
    . = 0;
    .shell_code ALIGN(16) :
    {
        KEEP(*(.entry_point))
        *(.text)
        *(.text.*)
        *(.rodata)
        *(.rodata.*)
    } :wake

    /DISCARD/ :
    {
        *(.data)
        *(.data.*)
        *(.bss)
        *(.bss.*)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note*)
    }

    ASSERT(SIZEOF(.shell_code) <= 0x4000,
           "11.60 wake blob exceeds one 16 KiB page")
}
