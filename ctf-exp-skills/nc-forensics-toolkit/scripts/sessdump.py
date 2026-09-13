import struct, socket, glob

# reassemble small :8084 HTTP sessions from attacker -> victim (responses)
SESS = [
    ("172.20.199.159", 42174), ("172.20.199.159", 33070),
    ("172.20.199.159", 49718), ("172.20.199.159", 42758),
    ("172.20.199.159", 33056), ("172.20.199.159", 33086),
]
ATT = ("47.238.112.123", 8084)

def read_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        return None, b"", None
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    return linktype, data[24:], endian

bufs = {s: [b'', b''] for s in SESS}
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
        for s in SESS:
            if (src, sport) == s and (dst, dport) == ATT:
                bufs[s][0] += pay
            elif (src, sport) == ATT and (dst, dport) == s:
                bufs[s][1] += pay

def printable(b):
    return ''.join(chr(c) if 32 <= c < 127 else ('\n' if c == 10 else '.') for c in b)

for s in SESS:
    req, resp = bufs[s]
    print("== session %s:%d  req=%d resp=%d" % (s[0], s[1], len(req), len(resp)))
    if resp:
        print(printable(resp[:3500])[:3500])
print("SESS_DONE")
