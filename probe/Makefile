.PHONY: all clean

ifndef PS5_PAYLOAD_SDK
    PS5_PAYLOAD_SDK = /opt/ps5-payload-sdk/
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BIN := ../bin/ps5-1160-probe.elf
SRC := probe.c hash.c
OBJS := $(SRC:.c=.o)

CFLAGS  := -std=c23 -Wall -Werror -O2
LDFLAGS := -lkernel_sys

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

clean:
	rm -f $(BIN) $(OBJS)
