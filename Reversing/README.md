# Reversing

## Radare
Ejecución normal:
```
aaa # Analizar funciones
afl # Mostrar funciones
s [funcion] # Seleccionar funcion
VV  # Ver grafo
Vpp # Ver codigo
```

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
