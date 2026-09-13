#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal pcap file analyzer: global header, per-packet IPv4/TCP/UDP summary.
Usage: python3 pca.py <file.pcap> ..."""
import sys, struct, socket
from collections import Counter

def read_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] != b'\xd4\xc3\xb2\xa1' and data[:4] != b'\xa1\xb2\xc3\xd4':
        return None, data, None
    endian = '<' if data[:4] == b'\xd4\xc3\xb2\xa1' else '>'
    magic, vmaj, vmin, tz, sig, snaplen, linktype = struct.unpack(endian + 'IHHiIII', data[:24])
    return linktype, data[24:], endian

def parse(linktype, blob, endian):
    pkts = []
    off = 0
    n = 0
    while off + 16 <= len(blob):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', blob[off:off+16])
        off += 16
        if off + incl_len > len(blob):
            break
        frame = blob[off:off+incl_len]
        off += incl_len
        n += 1
        # linktype 1 = Ethernet ; 276 = Linux cooked v2 (SLL2)
        eth_off = 0
        etype = None
        if linktype == 1:
            if len(frame) < 14: continue
            etype = struct.unpack('>H', frame[12:14])[0]
            eth_off = 14
            if etype == 0x8100:  # VLAN
                etype = struct.unpack('>H', frame[16:18])[0]
                eth_off = 18
        elif linktype == 276:
            if len(frame) < 20: continue
            etype = struct.unpack('>H', frame[0:2])[0]
            eth_off = 20
        elif linktype == 101:  # raw IP
            eth_off = 0
        else:
            continue
        if etype is not None and etype != 0x0800:
            continue
        ip = frame[eth_off:]
        if len(ip) < 20: continue
        ver = ip[0] >> 4
        if ver != 4: continue
        ihl = (ip[0] & 0xF) * 4
        proto = ip[9]
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        if proto == 6 and len(ip) >= ihl + 4:
            sport, dport = struct.unpack('>HH', ip[ihl:ihl+4])
            payload = ip[ihl+4:]
            pkts.append(('TCP', ts_sec, src, sport, dst, dport, payload))
        elif proto == 17 and len(ip) >= ihl + 4:
            sport, dport = struct.unpack('>HH', ip[ihl:ihl+4])
            payload = ip[ihl+4:]
            pkts.append(('UDP', ts_sec, src, sport, dst, dport, payload))
        elif proto == 1:
            pkts.append(('ICMP', ts_sec, src, 0, dst, 0, ip[ihl:]))
    return pkts

def summarize(path):
    linktype, blob, endian = read_pcap(path)
    if linktype is None:
        print(path, ': not classic pcap', blob[:8])
        return
    pkts = parse(linktype, blob, endian)
    print('==== %s linktype=%d pkts=%d ====' % (path, linktype, len(pkts)))
    # conversation counter (proto, src.ip, src.port, dst.ip, dst.port)
    conv = Counter()
    for p in pkts:
        proto, ts, src, sp, dst, dp, pay = p
        conv[(proto, src, sp, dst, dp)] += 1
    top = conv.most_common(25)
    for (proto, src, sp, dst, dp), c in top:
        label = ''
        if proto == 'TCP':
            if dp == 80: label = 'HTTP'
            elif dp == 443: label = 'HTTPS'
            elif dp == 22: label = 'SSH'
            elif dp == 3306: label = 'MySQL'
            elif dp == 6379: label = 'REDIS'
            elif sp == 80: label = 'HTTP-resp'
            elif sp == 443: label = 'HTTPS-resp'
            elif sp == 22: label = 'SSH-resp'
            elif dp == 53 or sp == 53: label = 'DNS'
        print('%-4s %-16s %-6s -> %-16s %-6s  %6d  %s' % (proto, src, sp, dst, dp, c, label))

if __name__ == '__main__':
    for p in sys.argv[1:]:
        try:
            summarize(p)
        except Exception as e:
            print(p, 'ERR', e)
