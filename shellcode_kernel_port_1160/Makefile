CC      = x86_64-elf-gcc
OBJCOPY = x86_64-elf-objcopy
NM      = x86_64-elf-nm
READELF = x86_64-elf-readelf

PS5_1160_DIAGNOSTIC ?= 1
PS5_1160_DIAG_PRE_STAGE ?= 5
PS5_1160_DIAG_OP_LIMIT ?= 29
PS5_1160_DIAG_CLEAR_MP3_BUFFERS ?= 0

CFLAGS := -Os -fomit-frame-pointer -fno-stack-protector -ffreestanding \
	-nostdlib -fPIE -fno-plt -fcf-protection=none -mno-sse -mno-sse2 -m64 \
	-ffunction-sections -fdata-sections -DSHELLCODE_1160_ONLY=1 \
	-I../shellcode_kernel -I../include

ifeq ($(PS5_1160_DIAGNOSTIC),1)
CFLAGS += -DSHELLCODE_1160_DIAGNOSTIC=1 \
	-DPS5_1160_DIAG_PRE_STAGE=$(PS5_1160_DIAG_PRE_STAGE) \
	-DPS5_1160_DIAG_OP_LIMIT=$(PS5_1160_DIAG_OP_LIMIT) \
	-DPS5_1160_DIAG_CLEAR_MP3_BUFFERS=$(PS5_1160_DIAG_CLEAR_MP3_BUFFERS)
endif
LDFLAGS := -pie -T linker.ld -Wl,--gc-sections

TARGET   := shellcode_kernel_port_1160.elf
TEXT_BIN := shellcode_kernel_port_1160.bin
DUMP     := shellcode_kernel_port_1160.h
OBJ      := main.o boot_linux.o display_ops_1160.o utils.o
BUILD_CONFIG := .build-config

.PHONY: all check clean FORCE

all: $(DUMP)

FORCE:

$(BUILD_CONFIG): FORCE
	@printf '%s\n' \
		'PS5_1160_DIAGNOSTIC=$(PS5_1160_DIAGNOSTIC)' \
		'PS5_1160_DIAG_PRE_STAGE=$(PS5_1160_DIAG_PRE_STAGE)' \
		'PS5_1160_DIAG_OP_LIMIT=$(PS5_1160_DIAG_OP_LIMIT)' \
		'PS5_1160_DIAG_CLEAR_MP3_BUFFERS=$(PS5_1160_DIAG_CLEAR_MP3_BUFFERS)' \
		> $(BUILD_CONFIG).tmp
	@if ! cmp -s $(BUILD_CONFIG).tmp $(BUILD_CONFIG); then \
		mv $(BUILD_CONFIG).tmp $(BUILD_CONFIG); \
	else \
		rm -f $(BUILD_CONFIG).tmp; \
	fi

$(OBJ): $(BUILD_CONFIG)

main.o: ../shellcode_kernel/main.c ../shellcode_kernel/main.h \
	../shellcode_kernel/shellcode_kernel_args_validate.h \
	../shellcode_kernel/resume_result_1160_validate.h \
	../shellcode_kernel/display_ops_1160.h
	$(CC) $(CFLAGS) -c $< -o $@

boot_linux.o: ../shellcode_kernel/boot_linux.c \
	../shellcode_kernel/boot_linux.h ../shellcode_kernel/utils.h \
	../shellcode_kernel/shellcode_kernel_args_validate.h \
	../include/config.h ../include/linux.h \
	../shellcode_hv_port_1160/shellcode_hv_port_1160.h
	$(CC) $(CFLAGS) -c $< -o $@

display_ops_1160.o: ../shellcode_kernel/display_ops_1160.c \
	../shellcode_kernel/display_ops_1160.h \
	../shellcode_kernel/shellcode_kernel_args.h ../shellcode_kernel/utils.h
	$(CC) $(CFLAGS) -c $< -o $@

utils.o: ../shellcode_kernel/utils.c ../shellcode_kernel/utils.h
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ) linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $@

$(TEXT_BIN): $(TARGET)
	$(OBJCOPY) -O binary -j .shell_code $< $@

$(DUMP): $(TEXT_BIN)
	xxd -i -n shellcode_kernel_port_1160_bin $(TEXT_BIN) > $(DUMP)

check: $(DUMP)
	@test "$$(wc -c < $(TEXT_BIN) | tr -d ' ')" -le 20480
	@python3 -c 'from pathlib import Path; p=Path("$(TEXT_BIN)").read_bytes(); assert p.count(bytes.fromhex("aa11aa11aa11aa11")) == 1'
	@$(READELF) -h $(TARGET) | grep -Eq 'Type:[[:space:]]+DYN'
	@$(READELF) -r $(TARGET) | grep -q 'There are no relocations in this file.'
	@! $(NM) -u $(TARGET) | grep -Eq 'hv_defeat_0304|mp3_|transmitter'

clean:
	rm -f $(OBJ) $(TARGET) $(TEXT_BIN) $(DUMP) \
		$(BUILD_CONFIG) $(BUILD_CONFIG).tmp
