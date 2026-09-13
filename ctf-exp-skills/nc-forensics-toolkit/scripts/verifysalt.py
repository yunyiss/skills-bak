import base64, hashlib, json
from Crypto.Cipher import AES

salt = "Vqskm0sjD1PWmqjhUpbQ"
key = hashlib.md5(salt.encode()).hexdigest().encode()  # 32-byte ASCII hex
assert len(key) == 32
print("key =", key)

data = base64.b64decode(open("tmp_c2frames.b64", "rb").read())
# frames are concatenated: [4B LE len][12B nonce][ct][16B tag], len covers nonce+ct+tag
off, n, ok = 0, 0, 0
while off + 4 <= len(data):
    ln = int.from_bytes(data[off:off+4], "little")
    if not (28 <= ln <= len(data) - off - 4):
        print("bad len", ln, "at", off); break
    body = data[off+4:off+4+ln]
    nonce, ct, tag = body[:12], body[12:-16], body[-16:]
    try:
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        pt = c.decrypt_and_verify(ct, tag)
        ok += 1
        print(f"[{n}] OK len={ln} plaintext ({len(pt)}B): {pt[:120]!r}")
    except ValueError as e:
        print(f"[{n}] TAG FAIL len={ln} {e}")
    n += 1
    off += 4 + ln
print(f"total {n} frames, {ok} verified")
