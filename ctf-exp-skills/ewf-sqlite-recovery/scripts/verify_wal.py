# -*- coding: utf-8 -*-
"""Verify WAL cumulative frame checksums (SQLite WAL spec)."""
from ewf_reader import EWFReader
import struct

ewf = EWFReader([r'commit.E0%d' % i for i in (1, 2, 3)])
START = 0x28201000

def wal_checksum(data, s1, s2, big_endian):
    fmt = '>I' if big_endian else '<I'
    n = len(data) // 4
    vals = struct.unpack_from('>%dI' % n, data) if False else None
    # unpack in the chosen word order
    ints = struct.unpack('%d%s' % (n, fmt[1]), data) if fmt[1] in 'IH' else None
    # simpler: unpack native chunks
    words = struct.unpack('%dI' % n, data)
    if big_endian:
        words = struct.unpack('>%dI' % n, data)
    else:
        words = struct.unpack('<%dI' % n, data)
    for i in range(0, n, 2):
        s1 = (s1 + words[i] + s2) & 0xFFFFFFFF
        s2 = (s2 + words[i+1] + s1) & 0xFFFFFFFF
    return s1, s2

hdr = ewf.read(START, 32)
magic, ver, psz, ckpt, s1, s2, c1, c2 = struct.unpack('>8I', hdr)
big = bool(magic & 1)
print('magic', hex(magic), 'big_endian_words', big)
# verify header checksum: over first 24 bytes
h1, h2 = wal_checksum(hdr[:24], 0, 0, big)
print('header cksum valid:', (h1, h2) == (c1, c2), (hex(h1), hex(h2)), (hex(c1), hex(c2)))

s1c, s2c = c1, c2
off = START + 32
idx = 0
while True:
    fh = ewf.read(off, 24)
    pgno, dbsize, fs1, fs2, fc1, fc2 = struct.unpack('>6I', fh)
    if fs1 != s1 or fs2 != s2:
        break
    page = ewf.read(off + 24, psz)
    s1c, s2c = wal_checksum(fh[:8], s1c, s2c, big)
    s1c, s2c = wal_checksum(page, s1c, s2c, big)
    ok = (s1c, s2c) == (fc1, fc2)
    print(f'frame {idx}: pgno={pgno} dbsize={dbsize} cksum_ok={ok}')
    if not ok:
        break
    idx += 1
    off += 24 + psz
