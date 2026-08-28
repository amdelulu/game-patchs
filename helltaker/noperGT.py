#!/usr/bin/env python3
"""
Helltaker (Linux) code patch: disable the "dec eax" that decrements the
value stored at [r15+0x154], by overwriting it with two NOPs.

This has to re-find the instruction every launch because Mono JIT-compiles
the method fresh into a new memory address each run - there's nothing
fixed in the .exe file to edit once and for all.

Requires root:
    sudo python3 helltaker_nop_patch.py
"""

import struct
import subprocess
import sys

PROCESS_NAME = "helltaker_lnx.x86_64"

# bytes for: mov [r15+0x154], eax   (41 89 87 54 01 00 00)
MOV_PATTERN = bytes.fromhex("41898754010000")
# the 2 bytes immediately before it should be: dec eax (FF C8)
DEC_EAX = bytes.fromhex("FFC8")
NOP_NOP = bytes.fromhex("9090")


def find_pid(name):
    try:
        out = subprocess.check_output(["pgrep", "-f", name]).decode().split()
    except subprocess.CalledProcessError:
        print(f"No process found matching '{name}'. Is the game running?")
        sys.exit(1)
    candidates = []
    for pid_str in out:
        pid = int(pid_str)
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
        except FileNotFoundError:
            continue
        if comm == name[:15]:
            candidates.append(pid)
    if not candidates:
        print("Could not identify the real game process among:", out)
        sys.exit(1)
    return max(candidates)


def executable_regions(pid):
    regions = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            parts = line.split()
            addr_range, perms = parts[0], parts[1]
            if "x" not in perms:
                continue
            start_s, end_s = addr_range.split("-")
            start, end = int(start_s, 16), int(end_s, 16)
            if end - start > 512 * 1024 * 1024:
                continue
            regions.append((start, end))
    return regions


def find_pattern(pid, pattern):
    """Return list of addresses where `pattern` occurs in executable memory."""
    hits = []
    with open(f"/proc/{pid}/mem", "rb") as mem:
        for start, end in executable_regions(pid):
            size = end - start
            try:
                mem.seek(start)
                data = mem.read(size)
            except (OSError, ValueError):
                continue
            offset = 0
            while True:
                idx = data.find(pattern, offset)
                if idx == -1:
                    break
                hits.append(start + idx)
                offset = idx + 1
    return hits


def hexdump(b):
    """Format bytes like '41 89 87 54 01 00 00'."""
    return " ".join(f"{byte:02X}" for byte in b)


def patch_bytes(pid, addr, new_bytes):
    with open(f"/proc/{pid}/mem", "r+b") as mem:
        mem.seek(addr)
        mem.write(new_bytes)


def banner():
    print(r"""
Ultimate Health Hell-Taker Patch
By - amdelulu""")


def main():
    banner()
    pid = find_pid(PROCESS_NAME)
    print(f"[+] Attached to PID {pid}")
    print(f"[+] Target pattern (mov [r15+0x154], eax): {hexdump(MOV_PATTERN)}")

    print("[*] Scanning executable memory for the target instruction sequence...")
    mov_hits = find_pattern(pid, MOV_PATTERN)
    print(f"[+] Found {len(mov_hits)} occurrence(s) of the mov pattern.")

    if not mov_hits:
        print("[!] Pattern not found. The game may not have JIT-compiled this "
              "method yet - trigger the relevant game action once, then rerun.")
        sys.exit(1)

    patched = 0
    with open(f"/proc/{pid}/mem", "rb") as mem:
        for mov_addr in mov_hits:
            dec_addr = mov_addr - 2
            mem.seek(dec_addr)
            full_before = mem.read(2 + len(MOV_PATTERN))  # dec eax + mov pattern
            two_bytes = full_before[:2]
            if two_bytes == DEC_EAX:
                print(f"\n[>] Found target at {hex(dec_addr)}")
                print(f"    before : {hexdump(full_before)}")
                patch_bytes(pid, dec_addr, NOP_NOP)

                mem.seek(dec_addr)
                full_after = mem.read(2 + len(MOV_PATTERN))
                print(f"    after  : {hexdump(full_after)}")
                patched += 1

    if patched == 0:
        print("[!] Found the mov pattern but no matching 'dec eax' right before "
              "it - the surrounding code may differ from what we expect. "
              "Send a fresh disassembler screenshot to double check the bytes.")
        sys.exit(1)

    print(f"\n[+] Done. Patched {patched} location(s).")
    print("[i] This lasts until the game process is closed - rerun this "
          "script after every relaunch.")


if __name__ == "__main__":
    main()
