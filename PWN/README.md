# TOC
- [PWN](#pwn)
  * [How to load specific libc version](#how-to-load-specific-libc-version)
    + [PWNINIT ftw!](#pwninit-ftw-)
    + [Running the binary patching the ELF](#running-the-binary-patching-the-elf)
    + [Running the binary using pwnlib](#running-the-binary-using-pwnlib)
    + [Best way of loading custom libc](#best-way-of-loading-custom-libc)
- [DEBUGGING](#debugging)
  * [Debugging exploits with custom libc](#debugging-exploits-with-custom-libc)
- [Running binaries with nc](#running-binaries-with-nc)
  * [Run binaries with SOCAT to emulate challenges](#run-binaries-with-socat-to-emulate-challenges)
  * [PWN Dockers](#pwn-dockers)

---
# PWN

Nice info for exploiting.

## How to load specific libc versiona
When loading specific libc versions, we will need to use the same **libc** version loader. For example, to load **libc-2.27.so** you'll need **ld-2.27.so**.

To get the loader, you can use [pwninit](https://github.com/io12/pwninit), which will detect the libc version, strip the library and download the ld file.

**IMPORTANT** 
When loading a binary from the loader (ld.smthg), you will not be able to access debugging symbols during runtime. So it is recommended to write down important functions' offsets to set breakpoints.

### PWNINIT ftw!
[pwninit](https://github.com/io12/pwninit) is a wonderful tool which will detect the libc version used by your challenge, download the proper linker and unstrip the libc library, all in one!

```
pwninit --bin <binary> --libc libc.so.6
```

### Running the binary patching the ELF
```bash
cp ld-2.27.so /tmp/
patchelf --set-interpreter /tmp/ld-2.27.so ./binary
export LD_PRELOAD=./libc-2.27.so
./binary

# You can use unset LD_PRELOAD after you finish
```
We can now check in __/proc/pid/maps__ that the binary is loading our libc version.

### Running the binary using pwnlib
```python
from pwn import *

p = process(["./ld-2.27.so", "./binary"], env={"LD_PRELOAD":"./libc-2.27.so"})
```

However, this method does not manages the heap properly, since it will be loaded at a base far located from the data segment.

### Best way of loading custom libc

The best way I have found is using the following Python script:

```python

import click
import lief
import pathlib


@click.command(
    help="Change the linked glibc of an ELF binary."
)
@click.argument("bin", type=click.Path(exists=True))
@click.argument("libc", type=click.Path(exists=True, resolve_path=True))
@click.argument("ld", type=click.Path(exists=True, resolve_path=True))
@click.argument("out", type=click.Path())
def cli(bin, libc, ld, out):
    binary = lief.parse(bin)

    libc_name = None
    for i in binary.libraries:
        if "libc.so.6" in i:
            libc_name = i
            break

    if libc_name is None:
        click.echo("No libc linked. Exiting.")

    click.echo("Current ld.so:")
    click.echo("Path: {}".format(binary.interpreter))
    click.echo()

    libc_path = str(pathlib.Path(str(libc)).parent)

    binary.interpreter = str(ld)
    click.echo("New ld.so:")
    click.echo("Path: {}".format(binary.interpreter))
    click.echo()

    binary += lief.ELF.DynamicEntryRunPath(libc_path)
    click.echo("Adding RUNPATH:")
    click.echo("Path: {}".format(libc_path))
    click.echo()

    click.echo("Writing new binary {}".format(out))
    click.echo("Please rename {} to {}/libc.so.6.".format(
        libc, libc_path
    ))
    binary.write(out)


if __name__ == "__main__":
    cli()
```

It will modify the RUNPATH of the binary to point to our custom libc, and the interpreter to point to our ld loader.

# DEBUGGING


## Debugging exploits with custom libc

When debugging an exploit which is using LD to load binaries with custom libc libraries, we can use:

```python
gdb.attach(p, 'add-symbol-file {}'.format(BINARY))
```

GDB does not know about the symbols when it is attached, but we can use **add-symbol-file ./binary** and load its symbols at runtime.

```python
p = gdb.debug([LD, BINARY],'''
			add-symbol-file {}
			b menu
			b add_player
			b delete_player
			'''.format(BINARY), env={"LD_PRELOAD":LIBC})
```

Moreover, we want to have access to libc's symbols in order to execute commands like pwndbg's **heap**. So it is strongly recommended to use [pwninit](https://github.com/io12/pwninit) in order to strip the library, so our debugger works perfectly.

# Running binaries with nc

```
nc -vc ./vuln -kl localhost 10000
```





## Run binaries with SOCAT to emulate challenges
```
sudo socat TCP-LISTEN:1337,nodealy,reuseaddr,fork EXEC:"stdbuf -i0 -o0 -e0 ./<binary>"
```
We can find the process PID and attach a debugger

## PWN Dockers
Some interesting containers for PWN challenges are:

[pwndocker]: https://github.com/skysider/pwndocker
[pwn-ubuntu]: https://github.com/stavhaygn/pwn-ubuntu