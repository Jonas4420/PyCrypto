#!/usr/bin/env python

import os
import time

class TwofishError(Exception):
    pass

class Twofish:
    def __init__(self, key):
        if len(key) > 32:
            raise TwofishError("Key length not supported")

        (self._K, self._S) = Twofish._KeySchedule(key)

    def encrypt(self, plaintext):
        P = [ int.from_bytes(plaintext[i*4:(i+1)*4], byteorder="little") for i in range(4) ]

        # Input whitening
        R = [ P[i] ^ self._K[i] for i in range(4) ]

        # 16 Rounds
        for r in range(16):
            F = Twofish._F(R[0], R[1], self._K[2*r+8], self._K[2*r+9], self._S)
            (R[0], R[1], R[2], R[3]) = (Twofish._ROR(R[2] ^ F[0], 1), Twofish._ROL(R[3], 1) ^ F[1], R[0], R[1])

        # Undo last swap and output whitening
        C = [ R[(i+2) % 4] ^ self._K[i+4] for i in range(4) ]

        ciphertext = b"".join([ C[i].to_bytes(4, byteorder="little") for i in range(4) ])

        return ciphertext

    def decrypt(self, ciphertext):
        C = [ int.from_bytes(ciphertext[i*4:(i+1)*4], byteorder="little") for i in range(4) ]

        # Reverse output whitening and do last swap
        R = [ C[(i+2) % 4] ^ self._K[((i+2) % 4) + 4] for i in range(4) ]

        # Reverse 16 Rounds
        for r in range(16):
            F = Twofish._F(R[2], R[3], self._K[2*(15-r)+8], self._K[2*(15-r)+9], self._S)
            (R[0], R[1], R[2], R[3]) = (R[2], R[3], Twofish._ROL(R[0], 1) ^ F[0], Twofish._ROR(R[1] ^ F[1], 1))

        # Reverse input whitening
        P = [ R[i] ^ self._K[i] for i in range(4) ]

        plaintext = b"".join([ P[i].to_bytes(4, byteorder="little") for i in range(4) ])

        return plaintext

    @staticmethod
    def _KeySchedule(m):
        N = 16 if (len(m) <= 16) else (24 if (len(m) <= 24) else 32)
        k = N // 8

        m += b"\x00" * (N - len(m))
        M = [ int.from_bytes(m[i*4:(i+1)*4], byteorder="little") for i in range(2*k) ]

        Me = M[0::2]
        Mo = M[1::2]
        S = [ 0 for i in range(k) ]

        for i in range(k):
            s = Twofish._MultRS(key[i*8:(i+1)*8])
            S[k-i-1] = s[0] + (s[1] << 8) + (s[2] << 16) + (s[3] << 24)

        # Expanded Key Words Kj
        p = (1 << 24) + (1 << 16) + (1 << 8) + 1
        A = [ Twofish._h(2*i*p, Me) for i in range(20) ]
        B = [ Twofish._ROL(Twofish._h((2*i+1) * p, Mo), 8) for i in range(20) ]
        K = [ 0 for i in range(40) ]
        for i in range(20):
            K[2*i] = (A[i] + B[i]) & 0xffffffff
            K[2*i+1] = Twofish._ROL((A[i] + 2*B[i]) & 0xffffffff, 9)

        return (K, S)

    @staticmethod
    def _h(X, L):
        y = [ (X >> (8 * i)) & 0xff for i in range(4) ]
        k = len(L)

        # Build q0 and q1
        q = [ [ 0 for i in range(256) ] for i in range(2) ]
        t = [
                # Permutations for q0
                [
                    [ 0x8, 0x1, 0x7, 0xd, 0x6, 0xf, 0x3, 0x2, 0x0, 0xb, 0x5, 0x9, 0xe, 0xc, 0xa, 0x4 ],
                    [ 0xe, 0xc, 0xb, 0x8, 0x1, 0x2, 0x3, 0x5, 0xf, 0x4, 0xa, 0x6, 0x7, 0x0, 0x9, 0xd ],
                    [ 0xb, 0xa, 0x5, 0xe, 0x6, 0xd, 0x9, 0x0, 0xc, 0x8, 0xf, 0x3, 0x2, 0x4, 0x7, 0x1 ],
                    [ 0xd, 0x7, 0xf, 0x4, 0x1, 0x2, 0x6, 0xe, 0x9, 0xb, 0x3, 0x0, 0x8, 0x5, 0xc, 0xa ]
                    ],
                # Permutations for q1
                [
                    [ 0x2, 0x8, 0xb, 0xd, 0xf, 0x7, 0x6, 0xe, 0x3, 0x1, 0x9, 0x4, 0x0, 0xa, 0xc, 0x5 ],
                    [ 0x1, 0xe, 0x2, 0xb, 0x4, 0xc, 0x3, 0x7, 0x6, 0xd, 0xa, 0x5, 0xf, 0x9, 0x0, 0x8 ],
                    [ 0x4, 0xc, 0x7, 0x5, 0x1, 0x6, 0x9, 0xa, 0x0, 0xe, 0xd, 0x8, 0x2, 0xb, 0x3, 0xf ],
                    [ 0xb, 0x9, 0x5, 0x1, 0xc, 0x3, 0xd, 0xe, 0x6, 0x4, 0x7, 0xf, 0x2, 0x0, 0x8, 0xa ]
                    ]
                ]

        for i in range(2):
            for x in range(256):
                (a0, b0) = ((x >> 4) & 0xf, x & 0xf)
                a1 = a0 ^ b0
                b1 = a0 ^ Twofish._ROR4(b0, 1) ^ ((a0 << 3) & 0xf)
                (a2, b2) = (t[i][0][a1], t[i][1][b1])
                a3 = a2 ^ b2
                b3 = a2 ^ Twofish._ROR4(b2, 1) ^ ((a2 << 3) & 0xf)
                (a4, b4) = (t[i][2][a3], t[i][3][b3])
                q[i][x] = (b4 << 4) | a4

        # actual H function
        if k >= 4:
            y = [ q[1][y[0]], q[0][y[1]], q[0][y[2]], q[1][y[3]] ]
            l = [ (L[3] >> (8*i)) & 0xff for i in range(4) ]
            y = [ y[i] ^ l[i] for i in range(4) ]

        if k >= 3:
            y = [ q[1][y[0]], q[1][y[1]], q[0][y[2]], q[0][y[3]] ]
            l = [ (L[2] >> (8*i)) & 0xff for i in range(4) ]
            y = [ y[i] ^ l[i] for i in range(4) ]

        y = [ q[0][y[0]], q[1][y[1]], q[0][y[2]], q[1][y[3]] ]
        l = [ (L[1] >> (8*i)) & 0xff for i in range(4) ]
        y = [ y[i] ^ l[i] for i in range(4) ]

        y = [ q[0][y[0]], q[0][y[1]], q[1][y[2]], q[1][y[3]] ]
        l = [ (L[0] >> (8*i)) & 0xff for i in range(4) ]
        y = [ y[i] ^ l[i] for i in range(4) ]

        y = [ q[1][y[0]], q[0][y[1]], q[1][y[2]], q[0][y[3]] ]

        z = Twofish._MultMDS(y)
        Z = z[0] + (z[1] << 8) + (z[2] << 16) + (z[3] << 24)

        return Z

    @staticmethod
    def _MultMDS(y):
        MDS = [
                [ 0x01, 0xef, 0x5b, 0x5b ],
                [ 0x5b, 0xef, 0xef, 0x01 ],
                [ 0xef, 0x5b, 0x01, 0xef ],
                [ 0xef, 0x01, 0xef, 0x5b ]
                ]
        z = [ 0 for i in range(4) ]

        for i in range(4):
            for j in range(4):
                z[i] ^= Twofish._MultGF8(MDS[i][j], y[j], 0b01101001)

        return z

    @staticmethod
    def _MultRS(m):
        RS = [
                [ 0x01, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e ],
                [ 0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5 ],
                [ 0x02, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19 ],
                [ 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 0x03 ]
                ]

        s = [ 0 for i in range(4) ]

        for i in range(4):
            for j in range(8):
                s[i] ^= Twofish._MultGF8(RS[i][j], m[j], 0b01001101)

        return s

    @staticmethod
    def _F(R0, R1, K0, K1, S):
        T0 = Twofish._g(R0, S)
        T1 = Twofish._g(Twofish._ROL(R1, 8), S)
        F0 = (T0 + T1 + K0) & 0xffffffff
        F1 = (T0 + 2 * T1 + K1) & 0xffffffff

        return [ F0, F1 ]

    @staticmethod
    def _g(X, S):
        return Twofish._h(X, S)

    @staticmethod
    def _MultGF8(a, b, v):
        c = 0
        for i in range(8):
            if (b >> i) & 0x01:
                p = a
                for j in range(i):
                    p <<= 1
                    if p & 0x100:
                        p = (p ^ v) & 0xff
                c ^= p
        return c

    @staticmethod
    def _ROL(n, s):
        return ((n << s) & 0xffffffff) | (n >> (32 - s))

    @staticmethod
    def _ROR(n, s):
        return (n >> s) | ((n << (32 - s)) & 0xffffffff)

    @staticmethod
    def _ROR4(n, s):
        return (n >> s) | ((n << (4 - s)) & 0xf)

if __name__ == "__main__":
    # Test vectors
    key = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    plain = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    expected = b"\x9f\x58\x9f\x5c\xf6\x12\x2c\x32\xb6\xbf\xec\x2f\x2a\xe8\xc3\x5a"

    tests = [ os.urandom(16) for i in range(16) ]

    # Perform encryption
    start = time.time_ns()

    twofish_ctx = Twofish(key)
    cipher = twofish_ctx.encrypt(plain)
    decipher = twofish_ctx.decrypt(cipher)
    res_test = (cipher == expected) and (plain == decipher)

    key = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10\x00\x11\x22\x33\x44\x55\x66\x77"
    plain = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    expected = b"\xcf\xd1\xd2\xe5\xa9\xbe\x9c\xdf\x50\x1f\x13\xb8\x92\xbd\x22\x48"

    twofish_ctx = Twofish(key)
    cipher = twofish_ctx.encrypt(plain)
    decipher = twofish_ctx.decrypt(cipher)
    res_test = res_test and (cipher == expected) and (plain == decipher)

    for test in tests:
        cipher = twofish_ctx.encrypt(test)
        decipher = twofish_ctx.decrypt(cipher)
        res_test = res_test and (test == decipher)

    end = time.time_ns()
    elapsed_time = (end - start) / (10 ** 9)

    # Check tests
    print("Slow version")
    print("Test: ", res_test)
    print("Time: ", elapsed_time, "s")

    exit(0)
