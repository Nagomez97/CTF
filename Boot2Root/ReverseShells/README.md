## How to upgrade shells on every OS
There is a tool called rlwrap. It helps upgrading the reverse shell on netcat. Simply use rlwrap nc -nlvp <port> and done!

## Manual upgrade to TTY on Linux
Run the following lines:

```
python -c 'import pty; pty.spawn("/bin/bash")'

export TERM=xterm
```

