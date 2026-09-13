import time
from Crypto.Cipher import AES

data = open(r"C:\Users\wbai\Downloads\Compressed\TinyNTRU\big_local.bin", "rb").read()
n = len(data)
print("scanning", n)

def validate(key, iv, ct):
    """full decrypt, unpad, check for config markers; return pt or None"""
    for L in (256, 512, 1024, 2048):
        c = ct[:L]
        if len(c) < 32 or len(c) % 16:
            continue
        try:
            pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(c)
        except Exception:
            return None
        pad = pt[-1]
        if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad:
            pt2 = pt[:-pad]
        else:
            pt2 = pt
        if b'"salt"' in pt2 or b'"server"' in pt2 or b'"vkey"' in pt2:
            return pt2
    return None

t0 = time.time()
found = []
for i in range(0, n - 64):
    # layout B: iv=0
    p0 = AES.new(data[i:i+16], AES.MODE_ECB).decrypt(data[i+16:i+32])
    if p0[0:1] == b'{':
        pt = validate(data[i:i+16], b"\x00"*16, data[i+16:])
        if pt: found.append((i, 'B', pt))
    # layout A: iv=key
    pa = bytes(a ^ b for a, b in zip(p0, data[i:i+16]))
    if pa[0:1] == b'{':
        pt = validate(data[i:i+16], data[i:i+16], data[i+16:])
        if pt: found.append((i, 'A', pt))
    # layout C: key=d[i:i+16], iv=d[i+16:i+32], ct=d[i+32:]
    p1 = AES.new(data[i:i+16], AES.MODE_ECB).decrypt(data[i+32:i+48])
    pc = bytes(a ^ b for a, b in zip(p1, data[i+16:i+32]))
    if pc[0:1] == b'{':
        pt = validate(data[i:i+16], data[i+16:i+32], data[i+32:])
        if pt: found.append((i, 'C', pt))
    if i % 1000000 == 0:
        print("...%d (%.0fs)" % (i, time.time()-t0))
print("elapsed", time.time()-t0)
print("found:", [(i, k) for i, k, _ in found])
for i, k, pt in found:
    print("=== %d %s ===" % (i, k))
    print(pt[:800].decode('utf-8', 'replace'))
if not found:
    print("NO CONFIG FOUND with CBC layouts")
