CC      = x86_64-elf-gcc
OBJCOPY = x86_64-elf-objcopy
READELF = x86_64-elf-readelf

CFLAGS := -O2 -fomit-frame-pointer -fno-stack-protector -ffreestanding \
	-nostdlib -fPIE -fno-plt -fcf-protection=none -mno-sse -mno-sse2 -m64 \
	-ffunction-sections -fdata-sections -DSHELLCODE_HV_1160=1
LDFLAGS := -pie -T linker.ld -Wl,--gc-sections

TARGET   := shellcode_hv_port_1160.elf
TEXT_BIN := shellcode_hv_port_1160.bin
DUMP     := shellcode_hv_port_1160.h
OBJ      := main.o utils.o boot_linux.o

.PHONY: all check clean

all: $(DUMP)

main.o: ../shellcode_hv/main.c
	$(CC) $(CFLAGS) -c $< -o $@

utils.o: ../shellcode_hv/utils.c
	$(CC) $(CFLAGS) -c $< -o $@

boot_linux.o: ../shellcode_hv/boot_linux.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ) linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $@

$(TEXT_BIN): $(TARGET)
	$(OBJCOPY) -O binary -j .shell_code $< $@

$(DUMP): $(TEXT_BIN)
	xxd -i -n shellcode_hv_port_1160_bin $(TEXT_BIN) > $@

check: $(DUMP)
	@test "$$(wc -c < $(TEXT_BIN) | tr -d ' ')" -le 8192
	@$(READELF) -h $(TARGET) | grep -Eq 'Type:[[:space:]]+DYN'
	@$(READELF) -r $(TARGET) | grep -q 'There are no relocations in this file.'
	@python3 -c 'from pathlib import Path; p=Path("$(TEXT_BIN)").read_bytes(); assert (0x980000000).to_bytes(8, "little") in p; assert (0xc0115110).to_bytes(4, "little") in p; assert (0xfffffdff).to_bytes(4, "little") in p'

clean:
	rm -f $(OBJ) $(TARGET) $(TEXT_BIN) $(DUMP)
