from Crypto.Util.number import *
from secret import root

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def generate_keys(nbit):
    p, q, r = [ getPrime(nbit) for _ in range(3)]
    
    n = p * q * r
    
    phi = (p-1)*(q-1)*(r-1)
    
    d = getPrime(1 << 8)
    e = modinv(d, phi)
    a = getPrime(2*nbit)
    while True:
        g = getRandomRange(2, a)
        if pow(g, 2, a) != 1 and pow(g, a//2, a) != 1:
            break

    pub_key = (n, e, a, g)

    priv_key = (n, d, a, g)

    return pub_key, priv_key


def encrypt(m, pub_key):
    n, e, a, g = pub_key
    k = getRandomRange(2, a)
    K = pow(g, k, a)
    c1, c2 = pow(k, e, n), (m * K) % a
    return c1, c2

password = bytes_to_long(root)
pub_key, priv_key = generate_keys(1024)

c1, c2 = encrypt(password, pub_key)

f = open('your_last_hope.txt', 'w')
f.write('n: ' + hex(pub_key[0]) + '\n')
f.write('e: ' + hex(pub_key[1]) + '\n')
f.write('a: ' + hex(pub_key[2]) + '\n')
f.write('g: ' + hex(pub_key[3]) + '\n')

f.write('c1: ' + hex(c1) + '\n')
f.write('c2: ' + hex(c2) + '\n')
f.write('DROP US some ETH if you know what\'s good:\n0x7b1cA37A0ad47B14e55a1E0d9d882999c0DF1Ee0\n')
f.close()