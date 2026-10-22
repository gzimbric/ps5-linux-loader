.PHONY: all clean pro-census clean-pro-census

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := bin/ps5-linux-loader.elf
SRC := $(wildcard source/*.c)
OBJS := $(SRC:.c=.o)

CFLAGS  := -std=c23 -Wall -Iinclude -Ishellcode_hv -Ishellcode_kernel
LDFLAGS :=

SC_0607_H := shellcode_0607/shellcode_0607.h
SC_HV_H := shellcode_hv/shellcode_hv.h
SC_K_H  := shellcode_kernel/shellcode_kernel.h
SC_K_13XX_H := shellcode_kernel_13xx/shellcode_kernel_13xx.h
SC_K_1160_H := shellcode_kernel_1160/shellcode_kernel_1160.h
SC_BREAK_HV_H := shellcode_break_hv/break_hv.h
CENSUS_AP_H := shellcode_break_hv_census/census.h
CENSUS_REGULAR_OBJ := build/pro-census/main-regular.o
CENSUS_PRO_OBJ := build/pro-census/main-pro.o
CENSUS_REGULAR_BIN := bin/ps5-linux-loader-1160-regular-census.elf
CENSUS_PRO_BIN := bin/ps5-linux-loader-1160-pro-census.elf
CENSUS_BINS := $(CENSUS_REGULAR_BIN) $(CENSUS_PRO_BIN)
CENSUS_CFLAGS := -std=c23 -O2 -Wall -Wextra -Werror -Iinclude \
	-Ishellcode_break_hv_census

all: $(SC_0607_H) $(SC_HV_H) $(SC_K_H) $(SC_K_13XX_H) $(SC_K_1160_H) \
	$(SC_BREAK_HV_H) $(BIN)

$(SC_0607_H):
	$(MAKE) -C shellcode_0607

$(SC_HV_H):
	$(MAKE) -C shellcode_hv

$(SC_K_H):
	$(MAKE) -C shellcode_kernel

$(SC_K_13XX_H): $(SC_HV_H) shellcode_kernel/main.c \
		shellcode_kernel/boot_linux.c shellcode_kernel/utils.c \
		shellcode_kernel/main.h shellcode_kernel/boot_linux.h \
		shellcode_kernel/utils.h shellcode_kernel/shellcode_kernel_args.h \
		shellcode_kernel/linker.ld include/config.h include/linux.h \
		shellcode_kernel_13xx/Makefile
	$(MAKE) -C shellcode_kernel_13xx

$(SC_K_1160_H): $(SC_HV_H) shellcode_kernel/main.c \
		shellcode_kernel/boot_linux.c shellcode_kernel/utils.c \
		shellcode_kernel/main.h shellcode_kernel/boot_linux.h \
		shellcode_kernel/utils.h shellcode_kernel/shellcode_kernel_args.h \
		shellcode_kernel/linker.ld include/config.h include/linux.h \
		shellcode_kernel_1160/Makefile shellcode_kernel_1160/display_ops_1160.c \
		shellcode_kernel_1160/display_ops_1160.h \
		shellcode_kernel_1160/shellcode_kernel_args_validate.h
	$(MAKE) -C shellcode_kernel_1160

$(SC_BREAK_HV_H): shellcode_break_hv/break_hv.c \
		shellcode_break_hv/break_hv_params.h shellcode_break_hv/entry.S \
		shellcode_break_hv/link.ld shellcode_break_hv/Makefile
	$(MAKE) -C shellcode_break_hv

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

source/prepare_resume.o: $(SC_K_13XX_H) $(SC_K_1160_H)
source/hv_defeat_1160.o: $(SC_BREAK_HV_H)

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -f $(BIN) $(OBJS)
	$(MAKE) -C shellcode_0607 clean
	$(MAKE) -C shellcode_hv clean
	$(MAKE) -C shellcode_kernel clean
	$(MAKE) -C shellcode_kernel_13xx clean
	$(MAKE) -C shellcode_kernel_1160 clean
	$(MAKE) -C shellcode_break_hv clean

# Bounded 11.60 data probes for testers (probe/README.md). Neither is part of
# "all"; they share no code with the loader.
.PHONY: probe probe-map
probe:
	$(MAKE) -C probe

probe-map:
	$(MAKE) -C probe map

# Opt-in, read-only 11.60 VMCB census pair. Both variants are intentionally
# outside "all" and link neither the production loader nor shellcode_break_hv.
# The regular-control and Pro binaries exact-match different hardware/regions;
# neither artifact auto-detects or falls back to the other variant.
pro-census: $(CENSUS_BINS)

$(CENSUS_AP_H): shellcode_break_hv_census/entry.S \
		shellcode_break_hv_census/census.c \
		shellcode_break_hv_census/census_params.h \
		shellcode_break_hv_census/link.ld \
		shellcode_break_hv_census/check-safety.sh \
		shellcode_break_hv_census/Makefile
	$(MAKE) -C shellcode_break_hv_census

$(CENSUS_REGULAR_OBJ): pro-census/main.c $(CENSUS_AP_H) \
		shellcode_break_hv_census/census_params.h
	@mkdir -p $(dir $@)
	$(CC) $(CENSUS_CFLAGS) -DCENSUS_VARIANT_PRO=0 -c -o $@ $<

$(CENSUS_PRO_OBJ): pro-census/main.c $(CENSUS_AP_H) \
		shellcode_break_hv_census/census_params.h
	@mkdir -p $(dir $@)
	$(CC) $(CENSUS_CFLAGS) -DCENSUS_VARIANT_PRO=1 -c -o $@ $<

$(CENSUS_REGULAR_BIN): $(CENSUS_REGULAR_OBJ) pro-census/check-build.sh
	@mkdir -p $(dir $@)
	$(CC) $(CENSUS_REGULAR_OBJ) -lkernel_sys -Wl,--build-id=sha1 \
		-Wl,-Map,build/pro-census/census-loader-regular.map -o $@
	sh pro-census/check-build.sh $(NM) $@ \
		shellcode_break_hv_census/census.elf \
		build/pro-census/census-loader-regular.map \
		$(CENSUS_REGULAR_OBJ) ps5-1160-regular-census

$(CENSUS_PRO_BIN): $(CENSUS_PRO_OBJ) pro-census/check-build.sh
	@mkdir -p $(dir $@)
	$(CC) $(CENSUS_PRO_OBJ) -lkernel_sys -Wl,--build-id=sha1 \
		-Wl,-Map,build/pro-census/census-loader-pro.map -o $@
	sh pro-census/check-build.sh $(NM) $@ \
		shellcode_break_hv_census/census.elf \
		build/pro-census/census-loader-pro.map \
		$(CENSUS_PRO_OBJ) ps5-1160-pro-census

clean-pro-census:
	rm -rf build/pro-census $(CENSUS_BINS)
	$(MAKE) -C shellcode_break_hv_census clean
