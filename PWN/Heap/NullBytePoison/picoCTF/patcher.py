from pwn import *
elf = ELF('./ghostdiary')

#Nulify alarm function
elf.asm(elf.symbols['alarm'], 'ret')
elf.save('./ghostdiary_noalarm')