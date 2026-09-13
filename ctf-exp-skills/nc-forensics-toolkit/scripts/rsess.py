#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Robust remote terminal client with session-level retries."""
import socket, sys, time, re

HOST = "8.147.132.32"
PORT = 21053

def connect():
    for i in range(15):
        try:
            return socket.create_connection((HOST, PORT), timeout=30)
        except Exception as e:
            sys.stderr.write(f"[retry {i+1}] {e}\n"); sys.stderr.flush()
            time.sleep(6)
    raise RuntimeError("connect failed")

def read_until(s, pat, timeout=600, idle_break=25):
    s.settimeout(2.0)
    buf = b""
    start = last = time.time()
    while time.time() - start < timeout:
        try:
            d = s.recv(65536)
            if not d:
                time.sleep(0.3); continue
            buf += d
            last = time.time()
            if pat in buf[-200000:]:
                time.sleep(0.4)
                try:
                    while True:
                        d2 = s.recv(65536)
                        if not d2: break
                        buf += d2
                except socket.timeout:
                    pass
                return buf, True
        except socket.timeout:
            if time.time() - last > idle_break:
                return buf, False
            continue
        except Exception:
            return buf, False
    return buf, False

def clean(b):
    text = b.decode("utf-8", "replace")
    text = re.sub(r'\x1b\[[0-9;?]*[a-zA-Z]', '', text)
    text = re.sub(r'\x1b\][^\x07]*\x07', '', text)
    text = text.replace('\r', '')
    return text

def run_once(cmd, timeout=600):
    """One fresh session, one command. Returns (body_or_None, raw).
    Markers are built via shell vars so the echoed command never contains them."""
    s = connect()
    try:
        read_until(s, b"\x1b[?2004h", 300)
        time.sleep(1.5)
        line = 'A=SH;B=START;echo $A$B; ' + cmd + '; echo $A"END"'
        s.sendall(line.encode() + b"\n")
        b, ok = read_until(s, b"SHEND", timeout)
        if not ok:
            return None, b
        # execution output starts after the bracketed-paste-off escape
        k = b.rfind(b"\x1b[?2004l")
        if k == -1:
            return None, b
        exec_out = b[k:]
        text = clean(exec_out)
        i = text.find("SHSTART")
        if i == -1:
            return None, b
        j = text.find("SHEND", i + 7)
        if j == -1:
            return None, b
        return text[i + 7:j].strip("\n"), b
    finally:
        try:
            s.close()
        except Exception:
            pass

def run(cmd, timeout=600, tries=6):
    for t in range(tries):
        body, raw = run_once(cmd, timeout)
        if body is not None:
            if t:
                sys.stderr.write("[recovered on try %d]\n" % (t + 1))
            return body
        time.sleep(2)
    return None

if __name__ == "__main__":
    out = run(sys.argv[1])
    print(out if out is not None else "[ALL RETRIES FAILED]")
