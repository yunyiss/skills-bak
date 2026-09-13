import struct, socket, glob

A = ("172.20.199.159", 33068); B = ("47.238.112.123", 8084)

def read_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        return None, b"", None
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    return linktype, data[24:], endian

bufs = [b'', b'']
for path in sorted(glob.glob("/var/log/pcap/*.pcap")):
    linktype, blob, endian = read_pcap(path)
    if linktype is None: continue
    off = 0
    while off + 16 <= len(blob):
        _, _, incl_len, _ = struct.unpack(endian + 'IIII', blob[off:off+16])
        off += 16
        if off + incl_len > len(blob): break
        frame = blob[off:off+incl_len]; off += incl_len
        if linktype == 276:
            if len(frame) < 20: continue
            if struct.unpack('>H', frame[0:2])[0] != 0x0800: continue
            ip = frame[20:]
        elif linktype == 1:
            if len(frame) < 14: continue
            if struct.unpack('>H', frame[12:14])[0] != 0x0800: continue
            ip = frame[14:]
        else: continue
        if len(ip) < 20 or ip[9] != 6: continue
        ihl = (ip[0] & 0xF) * 4
        src = socket.inet_ntoa(ip[12:16]); dst = socket.inet_ntoa(ip[16:20])
        sport, dport = struct.unpack('>HH', ip[ihl:ihl+4])
        doff = ((ip[ihl+12] >> 4) * 4) if len(ip) >= ihl+13 else 20
        pay = ip[ihl+doff:]
        if not pay: continue
        if (src, sport) == A and (dst, dport) == B: bufs[0] += pay
        elif (src, sport) == B and (dst, dport) == A: bufs[1] += pay

for idx in (0, 1):
    raw = bufs[idx]
    print("== dir%d len=%d" % (idx, len(raw)))
    open("/tmp/big_dir%d.raw" % idx, "wb").write(raw)
    if idx != 1: continue
    for k in (0x55, 0x99, 0xCC):
        d = bytes(b ^ k for b in raw)
        open("/tmp/big_dir1.x%02x" % k, "wb").write(d)
        for magic, name in ((b'\x7fELF', 'ELF'), (b'#!/', 'SHEBANG')):
            i = d.find(magic)
            hits = []
            while i != -1 and len(hits) < 8:
                hits.append(i); i = d.find(magic, i+1)
            if hits:
                print("  key %02x %s at %s" % (k, name, hits))
                h = hits[0]
                print("    ctx:", d[h:h+96])
print("BIG_DONE")
