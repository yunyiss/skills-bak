#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Send ONE command to remote, wait for next prompt, capture output until prompt."""
import socket, sys, time, re

HOST = "8.147.132.32"
PORT = 21053
PROMPT_RE = re.compile(rb"user@prod-01:[^\$]*\$ ")

def connect(retries=15, delay=6):
    for i in range(retries):
        try:
            return socket.create_connection((HOST, PORT), timeout=30)
        except Exception as e:
            sys.stderr.write(f"[retry {i+1}] {e}\n"); sys.stderr.flush()
            time.sleep(delay)
    raise RuntimeError("connect failed")

def recv_all(s, timeout=3.0):
    s.settimeout(timeout)
    out = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            out += d
        except socket.timeout:
            break
    return out

def wait_prompt(s, total=300):
    s.settimeout(1.0)
    buf = b""
    start = time.time()
    while time.time() - start < total:
        try:
            d = s.recv(65536)
            if not d:
                time.sleep(0.5); continue
            buf += d
            sys.stdout.buffer.write(d); sys.stdout.buffer.flush()
            if PROMPT_RE.search(buf):
                return True
        except socket.timeout:
            continue
        except Exception:
            break
    return False

def main():
    cmd = sys.argv[1]
    s = connect()
    ready = wait_prompt(s, 300)
    if not ready:
        sys.stderr.write("[!] no prompt seen\n")
    s.sendall(cmd.encode() + b"\n")
    # keep reading until prompt appears again (up to N sec)
    s.settimeout(2.0)
    buf = b""
    start = time.time()
    last = time.time()
    while time.time() - start < 540:
        try:
            d = s.recv(65536)
            if not d:
                time.sleep(0.3); continue
            buf += d
            sys.stdout.buffer.write(d); sys.stdout.buffer.flush()
            if PROMPT_RE.search(buf):
                # drain trailing
                time.sleep(0.3)
                try:
                    while True:
                        d2 = s.recv(65536)
                        if not d2: break
                        sys.stdout.buffer.write(d2); sys.stdout.buffer.flush()
                except socket.timeout:
                    pass
                break
            last = time.time()
        except socket.timeout:
            if time.time() - last > 20:
                break
            continue
        except Exception:
            break
    s.close()

if __name__ == "__main__":
    main()
