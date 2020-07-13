#!/usr/bin/env python

import os
import time

class RijndaelError(Exception):
   pass

class Rijndael:
    def __init__(self, key):
        if not len(key) in [ 16, 24, 32 ]:
            raise RijndaelError("Key length not supported")

        self._w = Rijndael._KeyExpansion(key)

    def encrypt(self, plain):
        if len(plain) != 16:
            raise RijndaelError("Block length must by 16 bytes")

        s = [ p for p in plain ]
        nr = len(self._w) - 1

        s = Rijndael._AddRoundKey(s, self._w[0])

        for r in range(1, nr):
            s = Rijndael._SubBytes(s)
            s = Rijndael._ShiftRows(s)
            s = Rijndael._MixColumns(s)
            s = Rijndael._AddRoundKey(s, self._w[r])

        s = Rijndael._SubBytes(s)
        s = Rijndael._ShiftRows(s)
        s = Rijndael._AddRoundKey(s, self._w[nr])

        return bytes(s)

    def decrypt(self, cipher):
        if len(cipher) != 16:
            raise RijndaelError("Block length must by 16 bytes")

        s = [ c for c in cipher ]
        nr = len(self._w) - 1

        s = Rijndael._InvAddRoundKey(s, self._w[nr])

        for r in range(1, nr):
            s = Rijndael._InvShiftRows(s)
            s = Rijndael._InvSubBytes(s)
            s = Rijndael._InvAddRoundKey(s, self._w[nr - r])
            s = Rijndael._InvMixColumns(s)

        s = Rijndael._InvShiftRows(s)
        s = Rijndael._InvSubBytes(s)
        s = Rijndael._InvAddRoundKey(s, self._w[0])

        return bytes(s)

    @staticmethod
    def _KeyExpansion(key):
        (nk, nr) = (len(key) // 4, [ 10, 12, 14 ][(len(key) // 16) - 1])

        Rcon = [ 0  for i in range(nr + 1) ]
        Rcon[1] = 1
        for i in range(2, nr + 1):
            Rcon[i] = Rijndael._MultGF8(Rcon[i - 1], 0x02)

        w = [ k for k in key ] + [ 0 for i in range(16 * (nr + 1) - len(key)) ]

        for i in range(nk, 4 * (nr + 1)):
            temp = w[4 * (i-1) : 4 * i]
            if (i % nk) == 0:
                temp = temp[1 : 4] + [ temp[0] ]
                temp = [ Rijndael._SBox(temp[i]) for i in range(4) ]
                temp[0] = temp[0] ^ Rcon[i // nk]
            elif (nk > 6) and ((i % nk) == 4):
                temp = temp[1 : 4] + [ temp[0] ]
            w[4 * i : 4 * (i+1)] = [ w[4 * (i-nk) + j] ^ temp[j] for j in range(4) ]

        return [ w[i * 16 : (i+1) * 16] for i in range(nr + 1) ]

    @staticmethod
    def _AddRoundKey(s, k):
        return [ s[i] ^ k[i] for i in range(16) ]

    @staticmethod
    def _InvAddRoundKey(s, kr):
        return Rijndael._AddRoundKey(s, kr)

    @staticmethod
    def _SubBytes(s):
        return [ Rijndael._SBox(s[i]) for i in range(16) ]

    @staticmethod
    def _InvSubBytes(s):
        return [ Rijndael._InvSBox(s[i]) for i in range(16) ]

    @staticmethod
    def _ShiftRows(s):
        return [ s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3], s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11] ]

    @staticmethod
    def _InvShiftRows(s):
        return [ s[0], s[13], s[10], s[7], s[4], s[1], s[14], s[11], s[8], s[5], s[2], s[15], s[12], s[9], s[6], s[3] ]

    @staticmethod
    def _MixColumns(s):
        m = [
                [ 0x02, 0x03, 0x01, 0x01 ],
                [ 0x01, 0x02, 0x03, 0x01 ],
                [ 0x01, 0x01, 0x02, 0x03 ],
                [ 0x03, 0x01, 0x01, 0x02 ]
                ]

        s_ = [ 0 for i in range(16) ]

        for i in range(4):
            for j in range(4):
                acc = 0
                for k in range(4):
                    acc ^= Rijndael._MultGF8(m[i][k], s[4 * j + k])
                s_[i + (4*j)] = acc

        return s_

    @staticmethod
    def _InvMixColumns(s):
        m = [
                [ 0x0e, 0x0b, 0x0d, 0x09 ],
                [ 0x09, 0x0e, 0x0b, 0x0d ],
                [ 0x0d, 0x09, 0x0e, 0x0b ],
                [ 0x0b, 0x0d, 0x09, 0x0e ]
                ]

        s_ = [ 0 for i in range(16) ]

        for i in range(4):
            for j in range(4):
                acc = 0
                for k in range(4):
                    acc ^= Rijndael._MultGF8(m[i][k], s[4 * j + k])
                s_[i + (4*j)] = acc

        return s_

    @staticmethod
    def _SBox(x):
        m = [
                [ 1, 0, 0, 0, 1, 1, 1, 1 ],
                [ 1, 1, 0, 0, 0, 1, 1, 1 ],
                [ 1, 1, 1, 0, 0, 0, 1, 1 ],
                [ 1, 1, 1, 1, 0, 0, 0, 1 ],
                [ 1, 1, 1, 1, 1, 0, 0, 0 ],
                [ 0, 1, 1, 1, 1, 1, 0, 0 ],
                [ 0, 0, 1, 1, 1, 1, 1, 0 ],
                [ 0, 0, 0, 1, 1, 1, 1, 1 ]
                ]
        c = [ 1, 1, 0, 0, 0, 1, 1, 0 ]

        if 0 == x:
            inv_x = 0
        else:
            inv_x = Rijndael._InvGF8(x)
        b = [ ((inv_x & (1 << i)) >> i) for i in range(8) ]

        b_ = [ 0 for i in range(8) ]
        for i in range(8):
            for j in range(8):
                b_[i] ^= b[j] * m[i][j]
        b_  = [ b_[i] ^ c[i] for i in range(8) ]

        return sum(b_[i] * (2 ** i) for i in range(8))

    @staticmethod
    def _InvSBox(y):
        m = [
                [ 0, 0, 1, 0, 0, 1, 0, 1 ],
                [ 1, 0, 0, 1, 0, 0, 1, 0 ],
                [ 0, 1, 0, 0, 1, 0, 0, 1 ],
                [ 1, 0, 1, 0, 0, 1, 0, 0 ],
                [ 0, 1, 0, 1, 0, 0, 1, 0 ],
                [ 0, 0, 1, 0, 1, 0, 0, 1 ],
                [ 1, 0, 0, 1, 0, 1, 0, 0 ],
                [ 0, 1, 0, 0, 1, 0, 1, 0 ]
                ]
        c = [ 1, 0, 1, 0, 0, 0, 0, 0 ]

        b = [ ((y & (1 << i)) >> i) for i in range(8) ]

        b_ = [ 0 for i in range(8) ]
        for i in range(8):
            for j in range(8):
                b_[i] ^= b[j] * m[i][j]
        b_ = [ b_[i] ^ c[i] for i in range(8) ]

        inv_x = sum(b_[i] * (2 ** i) for i in range(8))
        if 0 == inv_x:
            x = 0
        else:
            x = Rijndael._InvGF8(inv_x)

        return x

    @staticmethod
    def _MultGF8(a, b):
        c = 0
        for i in range(8):
            if (b >> i) & 1:
                p = a
                for j in range(i):
                    p <<= 1
                    if p & 0x100:
                        p ^= 0x11b
                c ^= p
        return c

    @staticmethod
    def _InvGF8(x):
        if 0 == x:
            return 0
        for i in range(1, 256):
            if 1 == Rijndael._MultGF8(x, i):
                return i

if __name__ == "__main__":
    # Test vectors
    key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
    plain = b"\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34"
    expected = b"\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32"

    tests = [ os.urandom(16) for i in range(16) ]

    # Perform encryption
    start = time.time_ns()

    rijndael_ctx = Rijndael(key)
    cipher = rijndael_ctx.encrypt(plain)
    decipher = rijndael_ctx.decrypt(cipher)
    res_test = (cipher == expected) and (plain == decipher)

    for test in tests:
        cipher = rijndael_ctx.encrypt(test)
        decipher = rijndael_ctx.decrypt(cipher)
        res_test = res_test and (test == decipher)

    end = time.time_ns()
    elapsed_time = (end - start) / (10 ** 9)

    # Check tests
    print("Slow version")
    print("Test: ", res_test)
    print("Time: ", elapsed_time, "s")

    exit(0)
