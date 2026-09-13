import struct, socket, glob
from collections import defaultdict

ATT = "47.238.112.123"
TARGET_PORTS = {(49782, 80), (49718, 80), (42758, 80), (58040, 80), (44634, 80)}

def read_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    return linktype, data[24:], endian

streams = defaultdict(list)  # (src,dst,sport,dport) -> [(seq, payload)]
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
            if ip[9] != 6: continue
            src = socket.inet_ntoa(ip[12:16]); dst = socket.inet_ntoa(ip[16:20])
            sport = struct.unpack('>H', ip[ihl:ihl+2])[0]
            dport = struct.unpack('>H', ip[ihl+2:ihl+4])[0]
            if ATT not in (src, dst): continue
            if (sport, dport) not in TARGET_PORTS and (dport, sport) not in TARGET_PORTS: continue
            doff = ((ip[ihl+12] >> 4) & 0xf) * 4
            payload = ip[ihl+doff:]
            if not payload: continue
            seq = struct.unpack('>I', ip[ihl+4:ihl+8])[0]
            streams[(src, dst, sport, dport)].append((seq, payload, ts_sec))
        except Exception:
            continue

out = open('/tmp/rce_streams.txt', 'wb')
for key, segs in sorted(streams.items()):
    segs.sort()
    buf = b''
    expect = None
    for seq, p, ts in segs:
        if expect is None: expect = seq
        if seq == expect:
            buf += p; expect = seq + len(p)
        elif seq > expect:
            buf += b'\n[--- GAP %d bytes ---]\n' % (seq - expect); buf += p; expect = seq + len(p)
        # seq < expect: retransmit, skip
    hdr = b'\n===== ' + ('%s -> %s sport=%d dport=%d (%d bytes)' % (key[0], key[1], key[2], key[3], len(buf))).encode() + b' =====\n'
    out.write(hdr + buf)
out.close()
print("done")
