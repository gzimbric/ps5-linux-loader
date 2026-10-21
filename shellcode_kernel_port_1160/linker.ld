ENTRY(main)

SECTIONS
{
    . = 0x1000;
    .shell_code :
    {
        *(.entry_point)
        *(.text)
        *(.text.*)
        *(.data*)
        *(.rodata*)
        *(.bss)
        *(.bss.*)
    }
}
