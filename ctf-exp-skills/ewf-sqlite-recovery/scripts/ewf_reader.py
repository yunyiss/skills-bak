# -*- coding: utf-8 -*-
"""Pure-Python EWF (E01) reader + pytsk3 filesystem browser."""
import struct, zlib, sys
import pytsk3

class EWFReader:
    """Seekable read-only reader over a set of E01 segment files."""
    CHUNK_CACHE_MAX = 512

    def __init__(self, segpaths):
        self.segs = segpaths
        self._seg_files = [open(p, 'rb') for p in segpaths]
        self._seg_sizes = [f.seek(0, 2) or f.tell() for f in self._seg_files]
        self.sector_size = 512
        self.sectors_per_chunk = 64
        self.chunk_size = 512 * 64
        self.media_size = None
        self.md5 = None
        # chunk lookup: absolute chunk index -> (seg_idx, file_offset, compressed, explicit_len or None)
        self.chunks = []
        self._cache = {}
        self._cache_order = []
        self._parse_all()

    def _sections(self, f, seg_size):
        off = 13  # skip EVF file header
        while off + 76 <= seg_size:
            f.seek(off)
            desc = f.read(76)
            if len(desc) < 76:
                break
            stype = desc[0:16].split(b'\x00')[0].decode('ascii', 'replace')
            nxt, size = struct.unpack('<QQ', desc[16:32])
            checksum = struct.unpack('<I', desc[72:76])[0]
            yield stype, off + 76, size, off
            if nxt == 0 or nxt <= off:
                break
            off = nxt

    def _parse_all(self):
        for si, f in enumerate(self._seg_files):
            seg_size = self._seg_sizes[si]
            last_sectors_start = None
            last_sectors_size = 0
            for stype, doff, size, descoff in self._sections(f, seg_size):
                if stype in ('volume', 'disk'):
                    f.seek(doff)
                    data = f.read(size)
                    if stype == 'volume':
                        nchunks = struct.unpack_from('<I', data, 4)[0]
                        spc = struct.unpack_from('<I', data, 8)[0]
                        ssize = struct.unpack_from('<I', data, 12)[0]
                        total_sectors = struct.unpack_from('<I', data, 16)[0]
                        media_size = total_sectors * ssize
                    else:  # disk
                        nchunks, ssize = struct.unpack('<II', data[0:8])
                        media_size = struct.unpack('<Q', data[8:16])[0]
                        spc = 64
                    self.sector_size = ssize
                    self.sectors_per_chunk = spc
                    self.chunk_size = ssize * spc
                    self.media_size = media_size
                elif stype == 'sectors':
                    last_sectors_start = doff
                    last_sectors_size = size
                elif stype == 'table':
                    f.seek(doff)
                    hdr = f.read(24)
                    n_entries = struct.unpack_from('<Q', hdr, 0)[0]
                    base_offset = struct.unpack_from('<Q', hdr, 8)[0]
                    need = 24 + n_entries * 4
                    blob = f.read(n_entries * 4)
                    assert len(blob) == n_entries * 4
                    for i in range(n_entries):
                        ent = struct.unpack_from('<I', blob, i * 4)[0]
                        comp = bool(ent & 0x80000000)
                        rel = ent & 0x7FFFFFFF
                        self.chunks.append((si, base_offset + rel, comp))
                elif stype == 'table2':
                    pass  # duplicate index
                elif stype == 'hash':
                    f.seek(doff)
                    data = f.read(size)
                    for j in range(0, len(data) - 4, 4):
                        if data[j:j+4] == b'MD5':
                            self.md5 = data[j+5:j+21].hex()
                            break
                elif stype == 'done':
                    pass
        if self.media_size is None:
            # fallback: compute from chunk count
            self.media_size = len(self.chunks) * self.chunk_size
        # trim last chunk to media size
        n_full = self.media_size // self.chunk_size
        if len(self.chunks) > n_full:
            self.chunks = self.chunks[:n_full + 1]

    def _read_chunk(self, idx):
        if idx in self._cache:
            return self._cache[idx]
        si, off, comp = self.chunks[idx]
        f = self._seg_files[si]
        f.seek(off)
        if comp:
            # compressed: read until decompress yields chunk (read a generous blob)
            blob = f.read(self.chunk_size * 2 + 4096)
            d = zlib.decompressobj()
            data = d.decompress(blob, self.chunk_size)
        else:
            data = f.read(self.chunk_size)
        # last chunk may exceed media size
        start = idx * self.chunk_size
        if start + len(data) > self.media_size:
            data = data[:self.media_size - start]
        self._cache[idx] = data
        self._cache_order.append(idx)
        if len(self._cache_order) > self.CHUNK_CACHE_MAX:
            old = self._cache_order.pop(0)
            self._cache.pop(old, None)
        return data

    def read(self, offset, size):
        out = bytearray()
        end = min(offset + size, self.media_size)
        while offset < end:
            ci = offset // self.chunk_size
            chunk = self._read_chunk(ci)
            co = offset - ci * self.chunk_size
            take = min(end - offset, len(chunk) - co)
            if take <= 0:
                break
            out += chunk[co:co + take]
            offset += take
        return bytes(out)

    def close(self):
        for f in self._seg_files:
            f.close()


class TSKImg(pytsk3.Img_Info):
    def __init__(self, ewf):
        self._ewf = ewf
        super().__init__(url='', type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
    def get_size(self):
        return self._ewf.media_size
    def read(self, offset, size):
        return self._ewf.read(offset, size)
    def close(self):
        self._ewf.close()

if __name__ == '__main__':
    import pytsk3
    base = r'C:\Users\wbai\Downloads\Compressed\committed\commit.E0'
    ewf = EWFReader([base + str(i) for i in (1, 2, 3)])
    print('media_size:', ewf.media_size, 'chunk_size:', ewf.chunk_size, 'chunks:', len(ewf.chunks))
    print('md5:', ewf.md5)
    img = TSKImg(ewf)
    # try to find partition table first
    try:
        vol = pytsk3.Vol_Info(img)
        print('Partition table:')
        for part in vol:
            print(f'  {part.addr:>4}  start={part.start:<12} len={part.len:<12} desc={part.desc.decode() if isinstance(part.desc, bytes) else part.desc}')
    except Exception as e:
        print('no partition table:', e)
