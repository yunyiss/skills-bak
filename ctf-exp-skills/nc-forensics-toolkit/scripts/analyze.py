import re

def strings(raw, minlen=6):
    out = []; cur = []
    for ch in raw:
        if 32 <= ch < 127:
            cur.append(chr(ch))
        else:
            if len(cur) >= minlen:
                out.append(''.join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append(''.join(cur))
    return out

# 1) big implant strings, save all
big = open("/tmp/big_dir1.x99", "rb").read()
ss = strings(big, 6)
open("/tmp/big_strings.txt", "w").write("\n".join(ss))
print("big strings:", len(ss))
kw = ["salt", "pass", "secret", "token", "mysql", "mariadb", "dump", ".sql",
      "rm -", "/bin/rm", "remove", "uninstall", "47.238", "8084", "50001",
      "admin", "bcrypt", "hash", "CWD", "l64", "fexec", "/tmp/log"]
seen = set()
for s in ss:
    ls = s.lower()
    for k in kw:
        if k.lower() in ls and s not in seen:
            seen.add(s)
            print("  KW[%s]: %s" % (k, s[:180]))
            break

# 2) interactive session 33096 attacker->victim dir1, xor 0x99
d1 = open("/tmp/c2_33096_dir1.raw", "rb").read()
print("\n== 33096 dir1 len", len(d1))
dec = bytes(b ^ 0x99 for b in d1)
ss1 = strings(dec, 6)
print("strings(x99):", len(ss1))
for s in ss1[:80]:
    print("   ", s[:170])

# 3) exfil upload 50001 victim->attacker dir0
up = open("/tmp/c2_50001_dir0.raw", "rb").read()
print("\n== 50001 dir0 len", len(up))
for k in (0x99, 0x55):
    d = bytes(b ^ k for b in up)
    magics = []
    for magic, name in ((b'\x7fELF','ELF'), (b'\x1f\x8b','gzip'), (b'SQLite','sqlite'),
                        (b'INSERT','SQL'), (b'CREATE TABLE','SQL2'), (b'-- MySQL','SQL3'),
                        (b'PK\x03\x04','zip'), (b'#!/','shebang')):
        i = d.find(magic)
        if i != -1:
            magics.append((name, i))
    print("  key %02x magics:" % k, magics[:8])
dec99 = bytes(b ^ 0x99 for b in up)
ss2 = strings(dec99, 8)
print("  strings(x99):", len(ss2))
for s in ss2[:60]:
    print("   ", s[:170])
print("ANZ_DONE")
