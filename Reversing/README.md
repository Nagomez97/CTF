# Reversing

# Radare

Para lanzar el debugger con output
```
## open a new terminal and type 'tty' to get
tty ; clear ; sleep 999999
#/dev/ttyS010

# Copiar en profile.rr2
#!/usr/bin/rarun2
stdio=/dev/ttys010

# Ejecutar
r2 -e dbg.profile=foo.rr2 -d [ejecutable]
```

### Comandos radare
```
aaa 			# Analiza binario
afl 			# Muestra funciones
s <fun name>		# Selecciona funcion
VV 			# Graph
Vpp			# Modo disassembler con stack
```
Una vez se entra al modo disassembler, se pueden usar los siguientes comandos (modo debugger)
```
S			# Step over
s			# stepi
:			# Comandos de radare
: db 0x<memory offset>	# Set breakpoint
: dc			# Continue execution
: do			# Restart execution
p			# change view
: afvd			# show local variables
```
TODO rellenar con comandos para editar variables, opcodes...


