.PHONY: all clean

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := ../bin/ps5-1160-probe.elf
MAP_BIN := ../bin/ps5-1160-map-probe.elf
SRC := probe.c hash.c
OBJS := $(SRC:.c=.o)
MAP_OBJS := probe-map.o hash-map.o

CFLAGS  := -std=c23 -Wall -Werror -O2
# A content-derived build ID keeps identical source/toolchain builds
# byte-for-byte reproducible on both macOS and Linux hosts.
LDFLAGS := -lkernel_sys -Wl,--build-id=sha1

all: $(BIN)

# check-readonly.sh runs on the sources before every compile and on the
# objects' imports before the link, so a write primitive fails the build.
$(OBJS): %.o: %.c hash.h check-readonly.sh
	sh check-readonly.sh
	$(CC) $(CFLAGS) -c -o $@ $<

$(BIN): $(OBJS) check-readonly.sh
	sh check-readonly.sh $(NM) $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

.PHONY: map
map: $(MAP_BIN)

probe-map.o: probe.c hash.h check-readonly.sh
	sh check-readonly.sh
	$(CC) $(CFLAGS) -DPROBE_MAP_ONLY=1 -c -o $@ $<

hash-map.o: hash.c hash.h check-readonly.sh
	sh check-readonly.sh
	$(CC) $(CFLAGS) -DPROBE_MAP_ONLY=1 -c -o $@ $<

$(MAP_BIN): $(MAP_OBJS) check-readonly.sh
	sh check-readonly.sh $(NM) $(MAP_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(MAP_OBJS) $(LDFLAGS) -o $@

clean:
	rm -f $(BIN) $(MAP_BIN) $(OBJS) $(MAP_OBJS)
