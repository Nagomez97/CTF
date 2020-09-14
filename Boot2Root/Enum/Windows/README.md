# LDAP
```
nmap --script ldap-search
enum4linux <ip>
```

# Kerberos
Podemos obtener TGT con el hash del user para aquellos users que tengan la propiedad 'Do not require Kerberos preauthentication'. La salida esta lista para john
```
python3 /usr/share/doc/python3-impacket/examples/GetNPUsers.py <domain name>/<userame> -dc-ip <ip> -no-pass
```
