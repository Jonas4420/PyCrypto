#!/usr/bin/env python

class Salsa20:
    def __init__(self, key, nonce):
        if not len(key) in [ 16, 32 ]:
            raise Salsa20Error("Key length should be 16 or 32 bytes")

        if not len(nonce) in [ 8 ]:
            raise Salsa20Error("Nonce should be 8 bytes")

        self._k = [ k for k in key ]
        self._v = [ n for n in nonce] + [ 0 for i in range(8) ]

        self._msg_sz = 0

        self._buffer = Salsa20._expand(self._k, self._v)
        self._buffer_sz = 0

    def encrypt(self, plaintext):
        ciphertext = [ p for p in plaintext ]

        self._msg_sz += len(plaintext)
        if self._msg_sz > 2**70:
            raise Salsa20Error("Maximum message length has been reached")

        for i in range(len(ciphertext)):
            ciphertext[i] ^= self._buffer[self._buffer_sz]
            self._buffer_sz += 1

            if 64 == self._buffer_sz:
                for i in range(8, 16):
                    self._v[i] = (self._v[i] + 1) % 256
                    if self._v[i] != 0:
                        break

                self._buffer = Salsa20._expand(self._k, self._v)
                self._buffer_sz = 0

        return bytes(ciphertext)

    @staticmethod
    def _quaterround(y):
        z = [ 0 for i in range(4) ]

        z[1] = y[1] ^ Salsa20._ROL((y[0] + y[3]) & 0xffffffff,  7)
        z[2] = y[2] ^ Salsa20._ROL((z[1] + y[0]) & 0xffffffff,  9)
        z[3] = y[3] ^ Salsa20._ROL((z[2] + z[1]) & 0xffffffff, 13)
        z[0] = y[0] ^ Salsa20._ROL((z[3] + z[2]) & 0xffffffff, 18)

        return z

    @staticmethod
    def _ROL(n, s):
        return ((n << s) & 0xffffffff) | (n >> (32 - s))

    @staticmethod
    def _rowround(y):
        z = [ 0 for i in range(16) ]

        (z[ 0], z[ 1], z[ 2], z[ 3]) = Salsa20._quaterround([ y[ 0], y[ 1], y[ 2], y[ 3] ])
        (z[ 5], z[ 6], z[ 7], z[ 4]) = Salsa20._quaterround([ y[ 5], y[ 6], y[ 7], y[ 4] ])
        (z[10], z[11], z[ 8], z[ 9]) = Salsa20._quaterround([ y[10], y[11], y[ 8], y[ 9] ])
        (z[15], z[12], z[13], z[14]) = Salsa20._quaterround([ y[15], y[12], y[13], y[14] ])

        return z

    @staticmethod
    def _columnround(x):
        y = [ 0 for i in range(16) ]

        (y[ 0], y[ 4], y[ 8], y[12]) = Salsa20._quaterround([ x[ 0], x[ 4], x[ 8], x[12] ])
        (y[ 5], y[ 9], y[13], y[ 1]) = Salsa20._quaterround([ x[ 5], x[ 9], x[13], x[ 1] ])
        (y[10], y[14], y[ 2], y[ 6]) = Salsa20._quaterround([ x[10], x[14], x[ 2], x[ 6] ])
        (y[15], y[ 3], y[ 7], y[11]) = Salsa20._quaterround([ x[15], x[ 3], x[ 7], x[11] ])

        return y

    @staticmethod
    def _doubleround(x):
        return Salsa20._rowround(Salsa20._columnround(x))

    @staticmethod
    def _hash(x):
        x = [ Salsa20._littleendian(x[i*4:(i+1)*4]) for i in range(16) ]

        z = x[:]
        for i in range(10):
            z = Salsa20._doubleround(z)

        res = [ ]
        for i in range(16):
            res += Salsa20._inv_littleendian((z[i] + x[i]) & 0xffffffff)

        return res

    @staticmethod
    def _littleendian(b):
        return (b[0] + (b[1] << 8) + (b[2] << 16) + (b[3] << 24)) & 0xffffffff

    @staticmethod
    def _inv_littleendian(x):
        return [ x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff ]

    @staticmethod
    def _expand(k, n):
        if 16 == len(k):
            k = k + k
            o = [ ord(x) for x in [ 'e', 'x', 'p', 'a', 'n', 'd', ' ', '1', '6', '-', 'b', 'y', 't', 'e', ' ', 'k' ] ]
        else:
            o = [ ord(x) for x in [ 'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k' ] ]

        return Salsa20._hash(o[0:4] + k[0:16] + o[4:8] + n + o[8:12] + k[16:32] + o[12:16])

if __name__ == "__main__":
    key = b"\x80" + b"\x00" * 15
    iv = b"\x00" * 8
    plaintext = b"\x00" * 64
    expected = [
            b"\x4d\xfa\x5e\x48\x1d\xa2\x3e\xa0\x9a\x31\x02\x20\x50\x85\x99\x36\xda\x52\xfc\xee\x21\x80\x05\x16\x4f\x26\x7c\xb6\x5f\x5c\xfd\x7f"
            + b"\x2b\x4f\x97\xe0\xff\x16\x92\x4a\x52\xdf\x26\x95\x15\x11\x0a\x07\xf9\xe4\x60\xbc\x65\xef\x95\xda\x58\xf7\x40\xb7\xd1\xdb\xb0\xaa",
            b"\xda\x9c\x15\x81\xf4\x29\xe0\xa0\x0f\x7d\x67\xe2\x3b\x73\x06\x76\x78\x3b\x26\x2e\x8e\xb4\x3a\x25\xf5\x5f\xb9\x0b\x3e\x75\x3a\xef"
            + b"\x8c\x67\x13\xec\x66\xc5\x18\x81\x11\x15\x93\xcc\xb3\xe8\xcb\x8f\x8d\xe1\x24\x08\x05\x01\xee\xeb\x38\x9c\x4b\xcb\x69\x77\xcf\x95"
            ]

    # Perform encryption
    salsa20_ctx = Salsa20(key, iv)
    ciphertext = salsa20_ctx.encrypt(plaintext)
    print(ciphertext == expected[0])

    ciphertext = salsa20_ctx.encrypt(plaintext)
    ciphertext = salsa20_ctx.encrypt(plaintext)
    ciphertext = salsa20_ctx.encrypt(plaintext)
    print(ciphertext == expected[1])

    exit(0)
