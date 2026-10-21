.PHONY: all clean wake-1160 stage2a-1160 stage2a-1160-check \
	linux-1160 linux-1160-check linux-1160-dma-e820 \
	linux-1160-dma-e820-check break-hv-1160-check FORCE_1160_HV \
	FORCE_1160_WAKE FORCE_1160_DMA_E820

# Run 15, the hardware-validated 11.60 Linux/display build, was compiled with
# the diagnostic gates present and set to the complete Sonic path.  Keep that
# exact configuration as the recursive-build default and export it so the
# audit evaluates the same mode that the wake sub-build compiled.
PS5_1160_DIAGNOSTIC ?= 1
PS5_1160_DIAG_PRE_STAGE ?= 5
PS5_1160_DIAG_OP_LIMIT ?= 29
PS5_1160_DIAG_CLEAR_MP3_BUFFERS ?= 0
export PS5_1160_DIAGNOSTIC PS5_1160_DIAG_PRE_STAGE
export PS5_1160_DIAG_OP_LIMIT PS5_1160_DIAG_CLEAR_MP3_BUFFERS

# The E820 gate follows the target name.  A command-line value would also be
# forwarded to the nested HV build through MAKEFLAGS and could put the DMA map
# into the Run 15 file name, so it is rejected here.  An environment value is
# ignored: the global value is forced to 0 and only the DMA targets set it.
ifeq ($(origin PS5_1160_DMA_E820_SAFE),command line)
$(error use linux-1160-dma-e820 instead of setting PS5_1160_DMA_E820_SAFE)
endif
override PS5_1160_DMA_E820_SAFE := 0
export PS5_1160_DMA_E820_SAFE

# The DMA E820 A/B build shares the nested HV and wake blobs with the Run 15
# build, so one make invocation can only produce one of them correctly.
DMA_E820_GOALS := linux-1160-dma-e820 linux-1160-dma-e820-check
ifneq ($(filter $(DMA_E820_GOALS),$(MAKECMDGOALS)),)
ifneq ($(filter-out $(DMA_E820_GOALS),$(MAKECMDGOALS)),)
$(error build $(DMA_E820_GOALS) in a separate make invocation)
endif
endif

# The exact standalone wake-1160 goal has no SDK inputs. Default, ordinary,
# and mixed-goal builds retain the existing SDK include and behavior.
ifneq ($(MAKECMDGOALS),wake-1160)
    ifndef PS5_PAYLOAD_SDK
        PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
    endif

    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
endif

BIN := bin/ps5-linux-loader.elf
SRC := $(filter-out source/hv_defeat_1160.c,$(wildcard source/*.c))
OBJS := $(SRC:.c=.o)
STAGE2A_BIN := bin/ps5-linux-loader-1160-stage2a.elf
STAGE2A_SRC := source/main.c source/offsets.c source/prepare_resume.c source/utils.c
STAGE2A_OBJS := $(patsubst source/%.c,build/stage2a/%.o,$(STAGE2A_SRC))
STAGE2A_NM ?= x86_64-elf-nm
HOSTCC ?= cc
PORT_1160_BIN := bin/ps5-linux-loader-1160.elf
PORT_1160_DMA_E820_BIN := bin/ps5-linux-loader-1160-dma-e820.elf
PORT_1160_SRC := $(filter-out source/hv_defeat_0304.c \
	source/hv_defeat_0506.c source/hv_defeat_0607.c \
	source/hv_defeat_13xx.c source/khook.c source/shellcode_1360.c,\
	$(wildcard source/*.c))
PORT_1160_OBJS := $(patsubst source/%.c,build/1160/%.o,$(PORT_1160_SRC))
PORT_1160_DMA_E820_OBJS := $(patsubst source/%.c,build/1160-dma-e820/%.o,$(PORT_1160_SRC))

CFLAGS  := -std=c23 -Wall -Iinclude -Ishellcode_hv -Ishellcode_kernel
LDFLAGS := -Wl,--build-id=sha1

SC_0607_H := shellcode_0607/shellcode_0607.h
SC_HV_H := shellcode_hv/shellcode_hv.h
SC_HV_PORT_1160_H := shellcode_hv_port_1160/shellcode_hv_port_1160.h
SC_K_H  := shellcode_kernel/shellcode_kernel.h
SC_K_1160_H := shellcode_kernel_1160/shellcode_kernel_1160.h
SC_K_PORT_1160_H := shellcode_kernel_port_1160/shellcode_kernel_port_1160.h
SC_BREAK_1160_H := shellcode_break_hv/break_hv.h
SC_K_13XX_H := shellcode_kernel_13xx/shellcode_kernel_13xx.h

all: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_K_13XX_H) $(BIN)

# Opt-in inert 11.60 wake blob. This is deliberately not part of `all`.
wake-1160:
	$(MAKE) -C shellcode_kernel_1160 check

# Bounded 11.60 integration test: stage and verify the inert wake page, then
# keep its user-backed storage alive.  This target does not fetch Linux, arm a
# resume hook, touch the hypervisor, or enter rest mode.
stage2a-1160: $(SC_K_1160_H) $(STAGE2A_BIN)

stage2a-1160-check: stage2a-1160
	$(MAKE) -C shellcode_kernel_1160 check
	@test "$$(wc -c < shellcode_kernel_1160/shellcode_kernel_1160.bin)" \
		-eq 240
	@command -v $(STAGE2A_NM) >/dev/null
	@symbols=$$(mktemp); trap 'rm -f "$$symbols"' EXIT; \
		$(STAGE2A_NM) -an $(STAGE2A_BIN) > "$$symbols" && \
		! grep -Eiq \
		'(hv_defeat|enter_rest|fetch_linux|boot_linux|remove_xotext|kernel_pmap_invalidate)' \
		"$$symbols"
	@command -v strings >/dev/null
	@strings -a $(STAGE2A_BIN) | grep -q \
		'no hook/HV/rest/Linux action was taken'

# Full 11.60 port: official loader flow and Sonic's high-firmware resume
# architecture, with the already hardware-proven 11.60 startup-AP payload.
break-hv-1160-check:
	$(MAKE) -C shellcode_break_hv check

# The Run 15 release name always carries the original E820 map.
linux-1160 linux-1160-check: override PS5_1160_DMA_E820_SAFE = 0
linux-1160: break-hv-1160-check $(SC_BREAK_1160_H) \
	$(SC_HV_PORT_1160_H) $(SC_K_PORT_1160_H) $(PORT_1160_BIN)

linux-1160-dma-e820 linux-1160-dma-e820-check: override PS5_1160_DMA_E820_SAFE = 1
linux-1160-dma-e820: break-hv-1160-check $(SC_BREAK_1160_H) \
	$(SC_HV_PORT_1160_H) $(SC_K_PORT_1160_H) $(PORT_1160_DMA_E820_BIN)

linux-1160-check: linux-1160
	$(MAKE) -C shellcode_hv_port_1160 check
	$(MAKE) -C shellcode_kernel_port_1160 check
	@$(NM) -an $(PORT_1160_BIN) | grep -q ' hv_defeat_1160$$'
	@strings -a $(PORT_1160_BIN) | grep -q \
		'11.60 Sonic-style Linux wake chain armed'
	@python3 -c 'from pathlib import Path; p=Path("shellcode_kernel_port_1160/shellcode_kernel_port_1160.bin").read_bytes(); assert p.count(bytes.fromhex("aa11aa11aa11aa11")) == 1'
	@test "$$(wc -c < shellcode_kernel_port_1160/shellcode_kernel_port_1160.bin | tr -d ' ')" -le 20480
	@mkdir -p build/tests
	@$(HOSTCC) -std=c11 -Wall -Wextra -Werror \
		tests/test_shellcode_kernel_args.c -o build/tests/test_shellcode_kernel_args
	@build/tests/test_shellcode_kernel_args
	@PS5_1160_RELEASE_CHECK=1 PS5_1160_ELF=$(PORT_1160_BIN) python3 tests/audit_1160_port.py

# Controlled A/B build for the low-memory DMA reservation used by the official
# 13.60 loader.  It has its own output name and does not satisfy the Run 15
# release hash gate.
linux-1160-dma-e820-check: linux-1160-dma-e820
	$(MAKE) -C shellcode_hv_port_1160 check
	$(MAKE) -C shellcode_kernel_port_1160 check
	@$(NM) -an $(PORT_1160_DMA_E820_BIN) | grep -q ' hv_defeat_1160$$'
	@strings -a $(PORT_1160_DMA_E820_BIN) | grep -q \
		'11.60 Sonic-style Linux wake chain armed'
	@python3 -c 'from pathlib import Path; p=Path("shellcode_kernel_port_1160/shellcode_kernel_port_1160.bin").read_bytes(); assert p.count(bytes.fromhex("aa11aa11aa11aa11")) == 1'
	@test "$$(wc -c < shellcode_kernel_port_1160/shellcode_kernel_port_1160.bin | tr -d ' ')" -le 20480
	@mkdir -p build/tests
	@$(HOSTCC) -std=c11 -Wall -Wextra -Werror \
		tests/test_shellcode_kernel_args.c -o build/tests/test_shellcode_kernel_args
	@build/tests/test_shellcode_kernel_args
	@PS5_1160_ELF=$(PORT_1160_DMA_E820_BIN) python3 tests/audit_1160_port.py
	@sha256sum $(PORT_1160_DMA_E820_BIN)

$(SC_0607_H):
	$(MAKE) -C shellcode_0607

$(SC_HV_H):
	$(MAKE) -C shellcode_hv

FORCE_1160_HV:

$(SC_HV_PORT_1160_H): FORCE_1160_HV
	$(MAKE) -C shellcode_hv_port_1160

$(SC_BREAK_1160_H):
	$(MAKE) -C shellcode_break_hv $(notdir $@)

$(SC_K_H):
	$(MAKE) -C shellcode_kernel

$(SC_K_1160_H):
	$(MAKE) -C shellcode_kernel_1160 shellcode_kernel_1160.h

FORCE_1160_WAKE:

$(SC_K_PORT_1160_H): $(SC_HV_PORT_1160_H) FORCE_1160_WAKE
	$(MAKE) -C shellcode_kernel_port_1160
$(SC_K_13XX_H): $(SC_HV_H) shellcode_kernel/main.c \
		shellcode_kernel/boot_linux.c shellcode_kernel/utils.c \
		shellcode_kernel/main.h shellcode_kernel/boot_linux.h \
		shellcode_kernel/utils.h shellcode_kernel/shellcode_kernel_args.h \
		shellcode_kernel/linker.ld include/config.h include/linux.h \
		shellcode_kernel_13xx/Makefile
	$(MAKE) -C shellcode_kernel_13xx

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(STAGE2A_OBJS): build/stage2a/%.o: source/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -DSTAGE2A_1160=1 -ffunction-sections -fdata-sections \
		-c -o $@ $<

# The 11.60 objects embed the nested HV and wake blobs, which change with the
# E820 gate.  make 3.81 compares mtimes to the whole second, so always rebuild.
$(PORT_1160_OBJS): build/1160/%.o: source/%.c $(SC_HV_PORT_1160_H) \
	$(SC_K_PORT_1160_H) $(SC_BREAK_1160_H) FORCE_1160_WAKE
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -DFW_1160_PORT=1 -ffunction-sections \
		-fdata-sections -c -o $@ $<

$(PORT_1160_DMA_E820_OBJS): build/1160-dma-e820/%.o: source/%.c \
	$(SC_HV_PORT_1160_H) $(SC_K_PORT_1160_H) $(SC_BREAK_1160_H) FORCE_1160_WAKE
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -DFW_1160_PORT=1 -ffunction-sections \
		-fdata-sections -c -o $@ $<

source/prepare_resume.o: $(SC_K_13XX_H)

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

$(STAGE2A_BIN): $(STAGE2A_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(STAGE2A_OBJS) $(LDFLAGS) -Wl,--gc-sections -o $@

$(PORT_1160_BIN): $(PORT_1160_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(PORT_1160_OBJS) $(LDFLAGS) -Wl,--gc-sections -o $@

FORCE_1160_DMA_E820:
	@rm -f $(PORT_1160_DMA_E820_BIN)

$(PORT_1160_DMA_E820_BIN): FORCE_1160_DMA_E820 $(PORT_1160_DMA_E820_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(PORT_1160_DMA_E820_OBJS) $(LDFLAGS) -Wl,--gc-sections -o $@

clean:
	rm -f $(BIN) $(STAGE2A_BIN) $(PORT_1160_BIN) $(PORT_1160_DMA_E820_BIN) \
		$(OBJS) $(STAGE2A_OBJS) $(PORT_1160_OBJS) $(PORT_1160_DMA_E820_OBJS)
	rm -f build/tests/test_shellcode_kernel_args
	$(MAKE) -C shellcode_0607 clean
	$(MAKE) -C shellcode_hv clean
	$(MAKE) -C shellcode_hv_port_1160 clean
	$(MAKE) -C shellcode_kernel clean
	$(MAKE) -C shellcode_kernel_1160 clean
	$(MAKE) -C shellcode_kernel_port_1160 clean
	$(MAKE) -C shellcode_break_hv clean
	$(MAKE) -C shellcode_kernel_13xx clean
