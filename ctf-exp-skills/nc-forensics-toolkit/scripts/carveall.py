import struct, socket, glob

TUPLES = [
    (("172.20.199.159", 48302), ("47.238.112.123", 50001), "c2_50001"),
    (("172.20.199.159", 33096), ("47.238.112.123", 8084), "c2_33096"),
]

def read_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        return None, b"", None
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    return linktype, data[24:], endian

bufs = {t[2]: [b'', b''] for t in TUPLES}
for path in sorted(glob.glob("/var/log/pcap/*.pcap")):
    linktype, blob, endian = read_pcap(path)
    if linktype is None:
        continue
    off = 0
    while off + 16 <= len(blob):
        _, _, incl_len, _ = struct.unpack(endian + 'IIII', blob[off:off+16])
        off += 16
        if off + incl_len > len(blob):
            break
        frame = blob[off:off+incl_len]
        off += incl_len
        if linktype == 276:
            if len(frame) < 20: continue
            if struct.unpack('>H', frame[0:2])[0] != 0x0800: continue
            ip = frame[20:]
        elif linktype == 1:
            if len(frame) < 14: continue
            if struct.unpack('>H', frame[12:14])[0] != 0x0800: continue
            ip = frame[14:]
        else:
            continue
        if len(ip) < 20 or ip[9] != 6: continue
        ihl = (ip[0] & 0xF) * 4
        src = socket.inet_ntoa(ip[12:16]); dst = socket.inet_ntoa(ip[16:20])
        sport, dport = struct.unpack('>HH', ip[ihl:ihl+4])
        doff = ((ip[ihl+12] >> 4) * 4) if len(ip) >= ihl+13 else 20
        pay = ip[ihl+doff:]
        if not pay: continue
        for A, B, tag in TUPLES:
            if (src, sport) == A and (dst, dport) == B:
                bufs[tag][0] += pay
            elif (src, sport) == B and (dst, dport) == A:
                bufs[tag][1] += pay

def strings(raw, minlen=5, limit=250):
    out = []; cur = []
    for ch in raw:
        if 32 <= ch < 127:
            cur.append(chr(ch))
        else:
            if len(cur) >= minlen:
                out.append(''.join(cur))
                if len(out) >= limit: return out
            cur = []
    if len(cur) >= minlen and len(out) < limit:
        out.append(''.join(cur))
    return out

for A, B, tag in TUPLES:
    for idx in (0, 1):
        raw = bufs[tag][idx]
        print("==== %s dir%d len=%d" % (tag, idx, len(raw)))
        if not raw:
            continue
        open("/tmp/%s_dir%d.raw" % (tag, idx), "wb").write(raw)
        for k in (0x55, 0x99, 0xCC):
            d = bytes(b ^ k for b in raw)
            idxs = []
            i = d.find(b'\x7fELF')
            while i != -1 and len(idxs) < 5:
                idxs.append(i); i = d.find(b'\x7fELF', i+1)
            open("/tmp/%s_dir%d.x%02x" % (tag, idx, k), "wb").write(d)
            if idxs:
                print("  ELF under key %02x at %s" % (k, idxs))
        # strings from XOR 0x55 view and raw
        for label, d in (("x55", bytes(b ^ 0x55 for b in raw)), ("raw", raw)):
            ss = strings(d, 6, 60)
            print("  -- strings[%s]:" % label)
            for s in ss[:40]:
                print("     ", s[:170])
print("CARVEALL_DONE")
