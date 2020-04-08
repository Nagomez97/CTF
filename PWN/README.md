#Correr binarios como procesos con SOCAT para simular entorno de challenge
```
sudo socat TCP-LISTEN:1337,nodealy,reuseaddr,fork EXEC:"stdbuf -i0 -o0 -e0 ./<binary>"
```
Asi podremos buscar el pid del proceso y hacer attach de debuggers

#Radare para PWN
Puede resultar util debuggear con radare un binario para analizar su comportamiento y poder explotarlo. En muchas ocasiones, querremos usar Radare junto a pwntools o herramientas similares. Podemos ejecutar el exploit con un raw_input('Start exploit?') que quede a la espera de pulsar enter. De ese modo, podremos attachear un debugger al proceso que este corriendo y simular el exploit en un entorno similar al del challenge (que normalmente sera un servicio accesible por nc).
Para attachear radare a un proceso:
```
r2 -d `pidof <binary_name>`
```
Tambien es posible hacer esto mismo usando un perfil para tener output en otra terminal.
