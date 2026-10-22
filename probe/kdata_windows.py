#!/usr/bin/env python3
"""Masked 64-KiB window hashes of an 11.60 kernel data dump.

    kdata_windows.py DUMP              print the "win" lines the probe writes
    kdata_windows.py DUMP REPORT       compare DUMP against a probe report

Each window is FNV-1a 64 over little-endian qwords, with any qword whose top
16 bits are 0xffff (a kernel or DMAP pointer) replaced by zero. This matches
fnv64_masked() in hash.c, so a report can be compared with a dump without
sharing the dump.
"""
import struct
import sys

WINDOW = 0x10000
FNV_INIT = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK64 = (1 << 64) - 1


def window_hash(data):
    masked = bytearray(data)
    for i, (q,) in enumerate(struct.iter_unpack("<Q", data)):
        if q >> 48 == 0xFFFF:
            masked[i * 8:i * 8 + 8] = bytes(8)
    h = FNV_INIT
    for b in masked:
        h = ((h ^ b) * FNV_PRIME) & MASK64
    return h


def dump_windows(path):
    with open(path, "rb") as f:
        data = f.read()
    return {off: window_hash(data[off:off + WINDOW])
            for off in range(0, len(data) - WINDOW + 1, WINDOW)}


def report_windows(path):
    found = {}
    with open(path, "r", encoding="ascii", errors="replace") as f:
        for line in f:
            parts = line.split()
            if not parts or parts[0] != "win":
                continue
            for off, h in zip(parts[1::2], parts[2::2]):
                found[int(off, 16)] = int(h, 16)
    return found


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    dump = dump_windows(sys.argv[1])
    if len(sys.argv) == 2:
        offs = sorted(dump)
        for i in range(0, len(offs), 4):
            print("win " + " ".join("%07x %016x" % (o, dump[o])
                                    for o in offs[i:i + 4]))
        return
    rep = report_windows(sys.argv[2])
    same = [o for o in rep if o in dump and rep[o] == dump[o]]
    diff = sorted(o for o in rep if o in dump and rep[o] != dump[o])
    print("windows: %d in report, %d in dump, %d same, %d differ"
          % (len(rep), len(dump), len(same), len(diff)))
    for o in diff:
        print("  differs: kdata+%#09x (ktext+%#x)" % (o, o + 0xD30000))


if __name__ == "__main__":
    main()
