from pwn import *
elf = ELF('./digiheap')

#Nulify alarm function
elf.asm(elf.symbols['alarm'], 'ret')
elf.save('./digiheap_noalarm')
