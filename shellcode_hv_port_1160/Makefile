CC      = x86_64-elf-gcc
OBJCOPY = x86_64-elf-objcopy
READELF = x86_64-elf-readelf
PS5_1160_DMA_E820_SAFE ?= 0

ifneq ($(PS5_1160_DMA_E820_SAFE),0)
ifneq ($(PS5_1160_DMA_E820_SAFE),1)
$(error PS5_1160_DMA_E820_SAFE must be 0 or 1)
endif
endif

CFLAGS := -O2 -fomit-frame-pointer -fno-stack-protector -ffreestanding \
	-nostdlib -fPIE -fno-plt -fcf-protection=none -mno-sse -mno-sse2 -m64 \
	-ffunction-sections -fdata-sections -DSHELLCODE_HV_1160=1 \
	-DPS5_1160_DMA_E820_SAFE=$(PS5_1160_DMA_E820_SAFE)
LDFLAGS := -pie -T linker.ld -Wl,--gc-sections

TARGET   := shellcode_hv_port_1160.elf
TEXT_BIN := shellcode_hv_port_1160.bin
DUMP     := shellcode_hv_port_1160.h
OBJ      := main.o utils.o boot_linux.o
BUILD_CONFIG := .build-config

.PHONY: all check clean FORCE

all: $(DUMP)

FORCE:

$(BUILD_CONFIG): FORCE
	@printf '%s\n' \
		'PS5_1160_DMA_E820_SAFE=$(PS5_1160_DMA_E820_SAFE)' \
		> $(BUILD_CONFIG).tmp
	@if ! cmp -s $(BUILD_CONFIG).tmp $(BUILD_CONFIG); then \
		mv $(BUILD_CONFIG).tmp $(BUILD_CONFIG); \
	else \
		rm -f $(BUILD_CONFIG).tmp; \
	fi

$(OBJ): $(BUILD_CONFIG)

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
	rm -f $(OBJ) $(TARGET) $(TEXT_BIN) $(DUMP) \
		$(BUILD_CONFIG) $(BUILD_CONFIG).tmp
