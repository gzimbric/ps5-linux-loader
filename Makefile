.PHONY: all clean wake-1160 stage2a-1160 stage2a-1160-check

# The exact standalone wake-1160 goal has no SDK inputs. Default, ordinary,
# and mixed-goal builds retain the existing SDK include and behavior.
ifneq ($(MAKECMDGOALS),wake-1160)
    ifndef PS5_PAYLOAD_SDK
        PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
    endif

    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
endif

BIN := bin/ps5-linux-loader.elf
SRC := $(wildcard source/*.c)
OBJS := $(SRC:.c=.o)
STAGE2A_BIN := bin/ps5-linux-loader-1160-stage2a.elf
STAGE2A_SRC := source/main.c source/offsets.c source/prepare_resume.c source/utils.c
STAGE2A_OBJS := $(patsubst source/%.c,build/stage2a/%.o,$(STAGE2A_SRC))
STAGE2A_NM ?= x86_64-elf-nm

CFLAGS  := -std=c23 -Wall -Iinclude -Ishellcode_hv -Ishellcode_kernel
LDFLAGS := -Wl,--build-id=sha1

SC_0607_H := shellcode_0607/shellcode_0607.h
SC_HV_H := shellcode_hv/shellcode_hv.h
SC_K_H  := shellcode_kernel/shellcode_kernel.h
SC_K_1160_H := shellcode_kernel_1160/shellcode_kernel_1160.h

all: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(BIN)

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

$(SC_0607_H):
	$(MAKE) -C shellcode_0607

$(SC_HV_H):
	$(MAKE) -C shellcode_hv

$(SC_K_H):
	$(MAKE) -C shellcode_kernel

$(SC_K_1160_H):
	$(MAKE) -C shellcode_kernel_1160 shellcode_kernel_1160.h

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(STAGE2A_OBJS): build/stage2a/%.o: source/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -DSTAGE2A_1160=1 -ffunction-sections -fdata-sections \
		-c -o $@ $<

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

$(STAGE2A_BIN): $(STAGE2A_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(STAGE2A_OBJS) $(LDFLAGS) -Wl,--gc-sections -o $@

clean:
	rm -f $(BIN) $(STAGE2A_BIN) $(OBJS) $(STAGE2A_OBJS)
	$(MAKE) -C shellcode_0607 clean
	$(MAKE) -C shellcode_hv clean
	$(MAKE) -C shellcode_kernel clean
	$(MAKE) -C shellcode_kernel_1160 clean
