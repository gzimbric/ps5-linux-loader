ENTRY(shellcode)
SECTIONS
{
  . = 0;
  .text : {
    entry.o(.text .text.*)
    census.o(.text .text.*)
  }
  .rodata : { *(.rodata .rodata.*) }
  .data : { *(.data .data.*) }
  ASSERT(. <= 0x800, "census AP payload exceeds 0x800 bytes")
  /DISCARD/ : {
    *(.eh_frame .eh_frame_hdr)
    *(.note .note.*)
    *(.comment)
    *(.bss .bss.*)
  }
}
