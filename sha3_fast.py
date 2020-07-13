#!/usr/bin/env python

import os
import time

class SHA3Error(Exception):
    pass

class SHA3:
    _RC = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
            0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
            0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
            0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
            0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
            ]

    def __init__(self, digest_sz):
        if not digest_sz in [ 224, 256, 384, 512 ]:
            raise SHA3Error("Digest size is not supported")

        self._digest_sz = digest_sz // 8
        self._r = 200 - (2 * self._digest_sz)

        self._S = [ 0 for i in range(25) ]
        self._buffer_sz = 0

        self.reset()

    def update(self, data):
        if (None == data) or (b"" == data):
            pass

        while len(data) >= (self._r - self._buffer_sz):
            fill_sz = self._r - self._buffer_sz
            self._absorb(data[:fill_sz])

            self._S = SHA3._keccakf(self._S)
            self._buffer_sz = 0

            data = data[fill_sz:]

        if len(data) > 0:
            self._absorb(data[:])
            self._buffer_sz = len(data)

    def finish(self):
        pad_sz = self._r - self._buffer_sz

        pad = [ 0 for i in range(pad_sz) ]
        pad[0] = 0x06
        pad[pad_sz - 1] ^= 0x80

        self.update(bytes(pad))

        digest = b""
        digest_sz = self._digest_sz
        idx = 0

        while digest_sz > 0:
            to_copy = (8 if digest_sz > 8 else digest_sz)

            digest += self._S[idx].to_bytes(8, byteorder="little")[:to_copy]
            digest_sz -= to_copy
            idx += 1

        self.reset()

        return digest

    def reset(self):
        for i in range(25):
            self._S[i] = 0
        self._buffer_sz = 0

    def _absorb(self, data):
        while (len(data) > 0) and (0 != (self._buffer_sz % 8)):
            qw = int.from_bytes(data[:1], byteorder="little") << (8 * (self._buffer_sz % 8))
            self._S[self._buffer_sz // 8] ^= qw

            data = data[1:]
            self._buffer_sz += 1

        while len(data) >= 8:
            qw = int.from_bytes(data[:8], byteorder="little")
            self._S[self._buffer_sz // 8] ^= qw

            data = data[8:]
            self._buffer_sz += 8

        while len(data) > 0:
            qw = int.from_bytes(data[:1], byteorder="little") << (8 * (self._buffer_sz % 8))
            self._S[self._buffer_sz // 8] ^= qw

            data = data[1:]
            self._buffer_sz += 1

    @ staticmethod
    def _keccakf(S):
        (A_00, A_01, A_02, A_03, A_04) = (S[0], S[5], S[10], S[15], S[20])
        (A_10, A_11, A_12, A_13, A_14) = (S[1], S[6], S[11], S[16], S[21])
        (A_20, A_21, A_22, A_23, A_24) = (S[2], S[7], S[12], S[17], S[22])
        (A_30, A_31, A_32, A_33, A_35) = (S[3], S[8], S[13], S[18], S[23])
        (A_40, A_41, A_42, A_43, A_44) = (S[4], S[9], S[14], S[19], S[24])

        for r in range(24):
            # Theta
            C_0 = A_00 ^ A_01 ^ A_02 ^ A_03 ^ A_04
            C_1 = A_10 ^ A_11 ^ A_12 ^ A_13 ^ A_14
            C_2 = A_20 ^ A_21 ^ A_22 ^ A_23 ^ A_24
            C_3 = A_30 ^ A_31 ^ A_32 ^ A_33 ^ A_35
            C_4 = A_40 ^ A_41 ^ A_42 ^ A_43 ^ A_44

            D_0 = C_4 ^ SHA3._ROL(C_1, 1)
            A_00 ^= D_0; A_01 ^= D_0; A_02 ^= D_0; A_03 ^= D_0; A_04 ^= D_0
            D_1 = C_0 ^ SHA3._ROL(C_2, 1)
            A_10 ^= D_1; A_11 ^= D_1; A_12 ^= D_1; A_13 ^= D_1; A_14 ^= D_1
            D_2 = C_1 ^ SHA3._ROL(C_3, 1)
            A_20 ^= D_2; A_21 ^= D_2; A_22 ^= D_2; A_23 ^= D_2; A_24 ^= D_2
            D_3 = C_2 ^ SHA3._ROL(C_4, 1)
            A_30 ^= D_3; A_31 ^= D_3; A_32 ^= D_3; A_33 ^= D_3; A_35 ^= D_3
            D_4 = C_3 ^ SHA3._ROL(C_0, 1)
            A_40 ^= D_4; A_41 ^= D_4; A_42 ^= D_4; A_43 ^= D_4; A_44 ^= D_4

            # Rho and Pi
            E_00 =           A_00
            E_01 = SHA3._ROL(A_30, 28)
            E_02 = SHA3._ROL(A_10,  1)
            E_03 = SHA3._ROL(A_40, 27)
            E_04 = SHA3._ROL(A_20, 62)
            E_10 = SHA3._ROL(A_11, 44)
            E_11 = SHA3._ROL(A_41, 20)
            E_12 = SHA3._ROL(A_21,  6)
            E_13 = SHA3._ROL(A_01, 36)
            E_14 = SHA3._ROL(A_31, 55)
            E_20 = SHA3._ROL(A_22, 43)
            E_21 = SHA3._ROL(A_02,  3)
            E_22 = SHA3._ROL(A_32, 25)
            E_23 = SHA3._ROL(A_12, 10)
            E_24 = SHA3._ROL(A_42, 39)
            E_30 = SHA3._ROL(A_33, 21)
            E_31 = SHA3._ROL(A_13, 45)
            E_32 = SHA3._ROL(A_43,  8)
            E_33 = SHA3._ROL(A_23, 15)
            E_34 = SHA3._ROL(A_03, 41)
            E_40 = SHA3._ROL(A_44, 14)
            E_41 = SHA3._ROL(A_24, 61)
            E_42 = SHA3._ROL(A_04, 18)
            E_43 = SHA3._ROL(A_35, 56)
            E_44 = SHA3._ROL(A_14,  2)

            # Chi and Iota
            A_00 = E_00 ^ ((E_10 ^ 0xffffffffffffffff) & E_20) ^ SHA3._RC[r]
            A_01 = E_01 ^ ((E_11 ^ 0xffffffffffffffff) & E_21)
            A_02 = E_02 ^ ((E_12 ^ 0xffffffffffffffff) & E_22)
            A_03 = E_03 ^ ((E_13 ^ 0xffffffffffffffff) & E_23)
            A_04 = E_04 ^ ((E_14 ^ 0xffffffffffffffff) & E_24)
            A_10 = E_10 ^ ((E_20 ^ 0xffffffffffffffff) & E_30)
            A_11 = E_11 ^ ((E_21 ^ 0xffffffffffffffff) & E_31)
            A_12 = E_12 ^ ((E_22 ^ 0xffffffffffffffff) & E_32)
            A_13 = E_13 ^ ((E_23 ^ 0xffffffffffffffff) & E_33)
            A_14 = E_14 ^ ((E_24 ^ 0xffffffffffffffff) & E_34)
            A_20 = E_20 ^ ((E_30 ^ 0xffffffffffffffff) & E_40)
            A_21 = E_21 ^ ((E_31 ^ 0xffffffffffffffff) & E_41)
            A_22 = E_22 ^ ((E_32 ^ 0xffffffffffffffff) & E_42)
            A_23 = E_23 ^ ((E_33 ^ 0xffffffffffffffff) & E_43)
            A_24 = E_24 ^ ((E_34 ^ 0xffffffffffffffff) & E_44)
            A_30 = E_30 ^ ((E_40 ^ 0xffffffffffffffff) & E_00)
            A_31 = E_31 ^ ((E_41 ^ 0xffffffffffffffff) & E_01)
            A_32 = E_32 ^ ((E_42 ^ 0xffffffffffffffff) & E_02)
            A_33 = E_33 ^ ((E_43 ^ 0xffffffffffffffff) & E_03)
            A_35 = E_34 ^ ((E_44 ^ 0xffffffffffffffff) & E_04)
            A_40 = E_40 ^ ((E_00 ^ 0xffffffffffffffff) & E_10)
            A_41 = E_41 ^ ((E_01 ^ 0xffffffffffffffff) & E_11)
            A_42 = E_42 ^ ((E_02 ^ 0xffffffffffffffff) & E_12)
            A_43 = E_43 ^ ((E_03 ^ 0xffffffffffffffff) & E_13)
            A_44 = E_44 ^ ((E_04 ^ 0xffffffffffffffff) & E_14)

        (S[0], S[5], S[10], S[15], S[20]) = (A_00, A_01, A_02, A_03, A_04)
        (S[1], S[6], S[11], S[16], S[21]) = (A_10, A_11, A_12, A_13, A_14)
        (S[2], S[7], S[12], S[17], S[22]) = (A_20, A_21, A_22, A_23, A_24)
        (S[3], S[8], S[13], S[18], S[23]) = (A_30, A_31, A_32, A_33, A_35)
        (S[4], S[9], S[14], S[19], S[24]) = (A_40, A_41, A_42, A_43, A_44)

        return S

    @staticmethod
    def _ROL(n, s):
        return ((n << s) & 0xffffffffffffffff) | (n >> (64 - s))

if __name__ == "__main__":
    # Test vectors
    test_vectors = [
            {
                "data" : b"",
                "expected" : {
                    224 : b"\x6b\x4e\x03\x42\x36\x67\xdb\xb7\x3b\x6e\x15\x45\x4f\x0e\xb1\xab"
                        + b"\xd4\x59\x7f\x9a\x1b\x07\x8e\x3f\x5b\x5a\x6b\xc7",
                    256 : b"\xa7\xff\xc6\xf8\xbf\x1e\xd7\x66\x51\xc1\x47\x56\xa0\x61\xd6\x62"
                        + b"\xf5\x80\xff\x4d\xe4\x3b\x49\xfa\x82\xd8\x0a\x4b\x80\xf8\x43\x4a",
                    384 : b"\x0c\x63\xa7\x5b\x84\x5e\x4f\x7d\x01\x10\x7d\x85\x2e\x4c\x24\x85"
                        + b"\xc5\x1a\x50\xaa\xaa\x94\xfc\x61\x99\x5e\x71\xbb\xee\x98\x3a\x2a"
                        + b"\xc3\x71\x38\x31\x26\x4a\xdb\x47\xfb\x6b\xd1\xe0\x58\xd5\xf0\x04",
                    512 : b"\xa6\x9f\x73\xcc\xa2\x3a\x9a\xc5\xc8\xb5\x67\xdc\x18\x5a\x75\x6e"
                        + b"\x97\xc9\x82\x16\x4f\xe2\x58\x59\xe0\xd1\xdc\xc1\x47\x5c\x80\xa6"
                        + b"\x15\xb2\x12\x3a\xf1\xf5\xf9\x4c\x11\xe3\xe9\x40\x2c\x3a\xc5\x58"
                        + b"\xf5\x00\x19\x9d\x95\xb6\xd3\xe3\x01\x75\x85\x86\x28\x1d\xcd\x26",
                    }
                },
            {
                "data" : b"abc",
                "expected" : {
                    224 : b"\xe6\x42\x82\x4c\x3f\x8c\xf2\x4a\xd0\x92\x34\xee\x7d\x3c\x76\x6f"
                        + b"\xc9\xa3\xa5\x16\x8d\x0c\x94\xad\x73\xb4\x6f\xdf",
                    256 : b"\x3a\x98\x5d\xa7\x4f\xe2\x25\xb2\x04\x5c\x17\x2d\x6b\xd3\x90\xbd"
                        + b"\x85\x5f\x08\x6e\x3e\x9d\x52\x5b\x46\xbf\xe2\x45\x11\x43\x15\x32",
                    384 : b"\xec\x01\x49\x82\x88\x51\x6f\xc9\x26\x45\x9f\x58\xe2\xc6\xad\x8d"
                        + b"\xf9\xb4\x73\xcb\x0f\xc0\x8c\x25\x96\xda\x7c\xf0\xe4\x9b\xe4\xb2"
                        + b"\x98\xd8\x8c\xea\x92\x7a\xc7\xf5\x39\xf1\xed\xf2\x28\x37\x6d\x25",
                    512 : b"\xb7\x51\x85\x0b\x1a\x57\x16\x8a\x56\x93\xcd\x92\x4b\x6b\x09\x6e"
                        + b"\x08\xf6\x21\x82\x74\x44\xf7\x0d\x88\x4f\x5d\x02\x40\xd2\x71\x2e"
                        + b"\x10\xe1\x16\xe9\x19\x2a\xf3\xc9\x1a\x7e\xc5\x76\x47\xe3\x93\x40"
                        + b"\x57\x34\x0b\x4c\xf4\x08\xd5\xa5\x65\x92\xf8\x27\x4e\xec\x53\xf0",
                    }
                },
            {
                "data" : b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "expected" : {
                    224 : b"\x8a\x24\x10\x8b\x15\x4a\xda\x21\xc9\xfd\x55\x74\x49\x44\x79\xba"
                        + b"\x5c\x7e\x7a\xb7\x6e\xf2\x64\xea\xd0\xfc\xce\x33",
                    256 : b"\x41\xc0\xdb\xa2\xa9\xd6\x24\x08\x49\x10\x03\x76\xa8\x23\x5e\x2c"
                        + b"\x82\xe1\xb9\x99\x8a\x99\x9e\x21\xdb\x32\xdd\x97\x49\x6d\x33\x76",
                    384 : b"\x99\x1c\x66\x57\x55\xeb\x3a\x4b\x6b\xbd\xfb\x75\xc7\x8a\x49\x2e"
                        + b"\x8c\x56\xa2\x2c\x5c\x4d\x7e\x42\x9b\xfd\xbc\x32\xb9\xd4\xad\x5a"
                        + b"\xa0\x4a\x1f\x07\x6e\x62\xfe\xa1\x9e\xef\x51\xac\xd0\x65\x7c\x22",
                    512 : b"\x04\xa3\x71\xe8\x4e\xcf\xb5\xb8\xb7\x7c\xb4\x86\x10\xfc\xa8\x18"
                        + b"\x2d\xd4\x57\xce\x6f\x32\x6a\x0f\xd3\xd7\xec\x2f\x1e\x91\x63\x6d"
                        + b"\xee\x69\x1f\xbe\x0c\x98\x53\x02\xba\x1b\x0d\x8d\xc7\x8c\x08\x63"
                        + b"\x46\xb5\x33\xb4\x9c\x03\x0d\x99\xa2\x7d\xaf\x11\x39\xd6\xe7\x5e",
                    }
                },
            {
                "data" : b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "expected" : {
                    224 : b"\x54\x3e\x68\x68\xe1\x66\x6c\x1a\x64\x36\x30\xdf\x77\x36\x7a\xe5"
                        + b"\xa6\x2a\x85\x07\x0a\x51\xc1\x4c\xbf\x66\x5c\xbc",
                    256 : b"\x91\x6f\x60\x61\xfe\x87\x97\x41\xca\x64\x69\xb4\x39\x71\xdf\xdb"
                        + b"\x28\xb1\xa3\x2d\xc3\x6c\xb3\x25\x4e\x81\x2b\xe2\x7a\xad\x1d\x18",
                    384 : b"\x79\x40\x7d\x3b\x59\x16\xb5\x9c\x3e\x30\xb0\x98\x22\x97\x47\x91"
                        + b"\xc3\x13\xfb\x9e\xcc\x84\x9e\x40\x6f\x23\x59\x2d\x04\xf6\x25\xdc"
                        + b"\x8c\x70\x9b\x98\xb4\x3b\x38\x52\xb3\x37\x21\x61\x79\xaa\x7f\xc7",
                    512 : b"\xaf\xeb\xb2\xef\x54\x2e\x65\x79\xc5\x0c\xad\x06\xd2\xe5\x78\xf9"
                        + b"\xf8\xdd\x68\x81\xd7\xdc\x82\x4d\x26\x36\x0f\xee\xbf\x18\xa4\xfa"
                        + b"\x73\xe3\x26\x11\x22\x94\x8e\xfc\xfd\x49\x2e\x74\xe8\x2e\x21\x89"
                        + b"\xed\x0f\xb4\x40\xd1\x87\xf3\x82\x27\x0c\xb4\x55\xf2\x1d\xd1\x85",
                    }
                }
            ]

    res_test = True
    elapsed_time = 0

    # Perform hashing
    for test_vector in test_vectors:
        for digest_sz in test_vector["expected"]:
            start = time.time_ns()

            sha3_ctx = SHA3(digest_sz)
            sha3_ctx.update(test_vector["data"])
            digest = sha3_ctx.finish()

            end = time.time_ns()
            elapsed_time += ((end - start) / (10 ** 9))

            res_test = res_test and (digest == test_vector["expected"][digest_sz])

    # Check tests
    print("Fast version")
    print("Test: ", res_test)
    print("Time: ", elapsed_time, "s")

    exit(0)
