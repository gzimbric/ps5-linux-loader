CC      = x86_64-elf-gcc
LD      = x86_64-elf-ld
OBJCOPY = x86_64-elf-objcopy

CFLAGS := -Os -ffreestanding -nostdlib -fno-pic -fno-plt \
	-fno-stack-protector -fno-stack-clash-protection -fomit-frame-pointer \
	-fno-asynchronous-unwind-tables -fcf-protection=none -fno-jump-tables \
	-mgeneral-regs-only -mno-red-zone -Wall -Wextra

EXPECTED_SIZE := 2040
EXPECTED_SHA256 := 6d566791c53a8a02c1c0a944a5285f5f41f683d83f89183bf63c8ddb32718d5e
DUMP := break_hv.h

.PHONY: all check clean

all: check

break_hv.o: break_hv.c
	$(CC) $(CFLAGS) -c $< -o $@

entry.o: entry.S
	$(CC) -c $< -o $@

break_hv.elf: entry.o break_hv.o link.ld
	$(LD) -nostdlib -no-pie -T link.ld entry.o break_hv.o -o $@

break_hv.bin: break_hv.elf
	$(OBJCOPY) -O binary $< $@

$(DUMP): break_hv.bin
	xxd -i -n break_hv break_hv.bin > $@

check: break_hv.bin $(DUMP)
	@test "$$(wc -c < break_hv.bin | tr -d ' ')" -eq "$(EXPECTED_SIZE)"
	@test "$$(shasum -a 256 break_hv.bin | awk '{print $$1}')" = \
		"$(EXPECTED_SHA256)"

clean:
	rm -f entry.o break_hv.o break_hv.elf break_hv.bin $(DUMP)
