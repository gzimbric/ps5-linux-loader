ifneq ($(filter arm64 aarch64,$(shell uname -m)),)
CC      = x86_64-elf-gcc
LD      = x86_64-elf-ld
OBJCOPY = x86_64-elf-objcopy
READELF = x86_64-elf-readelf
NM      = x86_64-elf-nm
else
CC      = gcc
LD      = ld
OBJCOPY = objcopy
READELF = readelf
NM      = nm
endif

CFLAGS = -Os -ffreestanding -nostdlib -fno-pic -fno-plt \
	-fno-stack-protector -fno-stack-clash-protection -fomit-frame-pointer \
	-fno-asynchronous-unwind-tables -fcf-protection=none -fno-jump-tables \
	-mgeneral-regs-only -mno-red-zone -Wa,--noexecstack \
	-Wall -Wextra -Wcast-qual -Werror
TARGET = census.elf
TEXT_BIN = census.bin
DUMP = census.h
OBJ = entry.o census.o

.PHONY: all clean check
.DELETE_ON_ERROR:

all: $(DUMP) check

entry.o: entry.S
	$(CC) -c $< -o $@

census.o: census.c census_params.h check-safety.sh
	sh check-safety.sh
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ) link.ld
	$(READELF) -rW $(OBJ) >/dev/null
	! $(READELF) -rW $(OBJ) | grep R_X86_64_ | grep -v -E 'R_X86_64_(PC32|PLT32) '
	$(LD) -nostdlib -no-pie -Map=census.map -T link.ld $(OBJ) -o $@

$(TEXT_BIN): $(TARGET)
	$(OBJCOPY) -O binary $< $@

$(DUMP): $(TEXT_BIN)
	xxd -i $< > $@

check: $(TARGET)
	sh check-safety.sh $(NM) $(TARGET)
	! grep -E 'shellcode_break_hv/|break_hv\.(o|c)' census.map

clean:
	rm -f $(OBJ) $(TARGET) $(TEXT_BIN) $(DUMP) census.map
