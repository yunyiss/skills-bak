import sys, struct, socket, glob, os
from collections import defaultdict

ATT = "47.238.112.123"
out = open("/tmp/conv.txt", "w")

def read_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        return None, b"", None
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    return linktype, data[24:], endian

conv = defaultdict(lambda: [0, 0, None, None])  # key -> pkts, bytes, t0, t1

files = sorted(glob.glob("/var/log/pcap/*.pcap"))
out.write("files=%d\n" % len(files))
for path in files:
    linktype, blob, endian = read_pcap(path)
    if linktype is None:
        out.write("%s: not classic pcap\n" % path)
        continue
    off = 0
    while off + 16 <= len(blob):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', blob[off:off+16])
        off += 16
        if off + incl_len > len(blob):
            break
        frame = blob[off:off+incl_len]
        off += incl_len
        eth_off = 0
        if linktype == 276:
            if len(frame) < 20: continue
            etype = struct.unpack('>H', frame[0:2])[0]
            eth_off = 20
        elif linktype == 1:
            if len(frame) < 14: continue
            etype = struct.unpack('>H', frame[12:14])[0]
            eth_off = 14
        else:
            continue
        if etype != 0x0800: continue
        ip = frame[eth_off:]
        if len(ip) < 20: continue
        if ip[9] != 6: continue
        ihl = (ip[0] & 0xF) * 4
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        if ATT not in (src, dst):
            continue
        sport, dport = struct.unpack('>HH', ip[ihl:ihl+4])
        key = tuple(sorted([(src, sport), (dst, dport)]))
        paylen = max(0, len(ip) - ihl - 20)  # rough: no option handling on tcp hdr
        doff = (ip[ihl+12] >> 4) * 4 if len(ip) >= ihl + 13 else 20
        paylen = max(0, len(ip) - ihl - doff)
        rec = conv[key]
        rec[0] += 1
        rec[1] += paylen
        t = ts_sec + ts_usec / 1e6
        if rec[2] is None or t < rec[2]: rec[2] = t
        if rec[3] is None or t > rec[3]: rec[3] = t

import time
for key, (n, by, t0, t1) in sorted(conv.items(), key=lambda kv: -kv[1][1]):
    out.write("%s <-> %s  pkts=%d bytes=%d  %s -> %s\n" % (
        key[0][0]+":"+str(key[0][1]), key[1][0]+":"+str(key[1][1]), n, by,
        time.strftime('%m-%d %H:%M:%S', time.gmtime(t0)),
        time.strftime('%m-%d %H:%M:%S', time.gmtime(t1))))
out.write("DONE\n")
out.close()
open("/tmp/conv.done", "w").write("ok")
