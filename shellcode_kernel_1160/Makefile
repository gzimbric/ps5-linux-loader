.PHONY: all check clean

ifneq ($(shell command -v x86_64-elf-gcc 2>/dev/null),)
CC = x86_64-elf-gcc
OBJCOPY = x86_64-elf-objcopy
READELF = x86_64-elf-readelf
NM = x86_64-elf-nm
else
CC = gcc
OBJCOPY = objcopy
READELF = readelf
NM = nm
endif

CFLAGS := -std=c11 -Os -Wall -Wextra -Werror -ffreestanding -nostdlib \
	-fno-stack-protector -fcf-protection=none -fno-pic -fno-pie \
	-fno-asynchronous-unwind-tables -fno-unwind-tables -mno-sse -mno-sse2 \
	-m64 -I../shellcode_kernel
LDFLAGS := -nostdlib -static -no-pie -Wl,--build-id=none \
	-Wl,--fatal-warnings -Wl,-T,linker.ld

TARGET := shellcode_kernel_1160.elf
BIN := shellcode_kernel_1160.bin
OBJ := main.o

all: $(BIN)

$(OBJ): main.c ../shellcode_kernel/shellcode_kernel_args.h \
	../shellcode_kernel/shellcode_kernel_args_validate.h
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ) linker.ld
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $@

$(BIN): $(TARGET)
	$(OBJCOPY) -O binary -j .shell_code $(TARGET) $(BIN)
	@size=$$(wc -c < $(BIN)); test "$$size" -le $$((0x4000))

check: $(BIN)
	@size=$$(wc -c < $(BIN)); test "$$size" -le $$((0x4000))
	@markers=$$(xxd -p $(BIN) | tr -d '\n' | grep -o \
		'aa11aa11aa11aa11' | wc -l | tr -d ' '); test "$$markers" -eq 1
	@$(READELF) -r $(TARGET) | grep -q 'There are no relocations'
	@! $(NM) --defined-only $(TARGET) | grep -Eiq \
		'(hv_defeat|boot_linux|uart|vbios|transmitter|mp3|printf|smp|vmmcall)'
	@$(READELF) -lW $(TARGET) | grep -Eq 'LOAD.*R E'
	@! $(READELF) -lW $(TARGET) | grep -Eq 'LOAD.*RWE'

clean:
	rm -f $(OBJ) $(TARGET) $(BIN)
