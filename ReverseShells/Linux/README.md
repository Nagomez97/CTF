## Tip on interactive shell
To aquire a fully interactive shell:
```
python -c 'import pty;pty.spawn("/bin/bash");'
```
After that, CTRL+Z to background nc. Enter
```
stty raw -echo
```
And run fg to bring the shell back. Now you can use sudo, nano...
