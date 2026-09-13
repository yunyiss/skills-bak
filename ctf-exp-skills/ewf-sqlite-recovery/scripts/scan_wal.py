# -*- coding: utf-8 -*-
"""Full-disk scan for SQLite WAL headers."""
from ewf_reader import EWFReader
import struct

ewf = EWFReader([r'commit.E0%d' % i for i in (1, 2, 3)])
pats = (b'\x37\x7f\x06\x82', b'\x37\x7f\x06\x83')
CH = 1 << 24
off = 0
found = []
while off < ewf.media_size:
    blob = ewf.read(off, min(CH, ewf.media_size - off))
    for pat in pats:
        i = blob.find(pat)
        while i != -1:
            o = off + i
            hdr = ewf.read(o, 32)
            mg, ver, psz, ckpt, s1, s2, c1, c2 = struct.unpack('>8I', hdr)
            if psz == 4096 and s1 and s2:
                found.append((o, mg, ckpt, s1, s2))
            i = blob.find(pat, i + 1)
    off += len(blob)
for o, mg, ckpt, s1, s2 in found:
    print(hex(o), hex(mg), 'ckpt', ckpt, 'salt', hex(s1), hex(s2))
