# PWN

Nice info for exploiting.

## How to load specific libc version
When loading specific libc versions, we will need to use the same **libc** version loader. For example, to load **libc-2.27.so** you'll need **ld-2.27.so**.

**IMPORTANT** 
When loading a binary from the loader (ld.smthg), you will not be able to access debugging symbols during runtime. So it is recommended to write down important functions' offsets to set breakpoints.

### Running the binary patching the ELF
```bash
cp ld-2.27.so /tmp/
patchelf --set-interpreter /tmp/ld-2.27.so ./binary
export LD_PRELOAD=./libc-2.27.so
./binary

# You can use unset LD_PRELOAD after you finish
```
We can now check in /proc/pid/maps that the binary is loading our libc version.

### Running the binary using pwnlib
```python
from pwn import *

p = process(["./ld-2.27.so", "./binary"], env={"LD_PRELOAD":"./libc-2.27.so"})
```

# DEBUGGING


## Debugging exploits with custom libc

When debugging an exploit which is using LD to load binaries with custom libc libraries, we can use:

```python
gdb.attach(p, 'add-symbol-file {}'.format(BINARY))
```

GDB does not know about the symbols when it is attached, but we can use **add-symbol-file ./binary** and load its symbols at runtime.





## Run binaries with SOCAT to emulate challenges
```
sudo socat TCP-LISTEN:1337,nodealy,reuseaddr,fork EXEC:"stdbuf -i0 -o0 -e0 ./<binary>"
```
We can find the process PID and attach a debugger

## PWN Dockers
Some interesting containers for PWN challenges are:

[pwndocker]: https://github.com/skysider/pwndocker
[pwn-ubuntu]: https://github.com/stavhaygn/pwn-ubuntu