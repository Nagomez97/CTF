from pwn import *

p = process(["./ld-2.27.so", "./penpal_world"], env={"LD_PRELOAD":"./libc-2.27.so"})

p.interactive()