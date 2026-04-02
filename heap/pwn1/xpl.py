from pwn import *

elf = context.binary = ELF("./pwn1_ff_patched")
libc = ELF("libc.2.23.so")

gs = '''
start
b main
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

p = start()


