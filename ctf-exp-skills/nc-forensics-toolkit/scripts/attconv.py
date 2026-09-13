import struct, socket, glob, re
from collections import defaultdict

ATT = "47.238.112.123"

def read_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    return linktype, data[24:], endian

conv = defaultdict(lambda: [0, 0, [], []])  # key -> pkts, bytes, first_ts, [sample payloads]
files = sorted(glob.glob("/var/log/pcap/*.pcap"))
for path in files:
    linktype, blob, endian = read_pcap(path)
    sll2 = (linktype == 276)
    off = 0
    while off + 16 <= len(blob):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', blob[off:off+16])
        off += 16
        pkt = blob[off:off+incl_len]
        off += incl_len
        try:
            if sll2:
                if struct.unpack('>H', pkt[0:2])[0] != 0x0800: continue
                ip = pkt[20:]
            else:
                if pkt[12:14] != b'\x08\x00': continue
                ip = pkt[14:]
            if len(ip) < 20: continue
            ihl = (ip[0] & 0xf) * 4
            src = socket.inet_ntoa(ip[12:16]); dst = socket.inet_ntoa(ip[16:20])
            if ATT not in (src, dst): continue
            if ip[9] != 6: continue
            doff = ((ip[ihl+12] >> 4) & 0xf) * 4
            payload = ip[ihl+doff:]
            key = (src, dst, struct.unpack('>H', ip[ihl:ihl+2])[0], struct.unpack('>H', ip[ihl+2:ihl+4])[0])
            c = conv[key]
            c[0] += 1; c[1] += len(payload)
            if c[2] == []: c[2] = [ts_sec]
            if payload and len(c[3]) < 3:
                c[3].append(payload[:200])
        except Exception:
            continue

for key, c in sorted(conv.items(), key=lambda kv: kv[1][2]):
    print(key, "pkts=%d bytes=%d t0=%s" % (c[0], c[1], c[2]))
    for p in c[3][:2]:
        print("   ", p[:160])
