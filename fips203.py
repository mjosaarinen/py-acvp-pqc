#   fips203.py
#   2024-08-15  Markku-Juhani O. Saarinen <mjos@iki.fi> See LICENSE.
#   === FIPS 203 implementation https://doi.org/10.6028/NIST.FIPS.203
#   ML-KEM / Module-Lattice-Based Key-Encapsulation Mechanism Standard

#   test_mlkem is only used by the unit test in the end
from test_mlkem import test_mlkem

from Crypto.Hash import SHAKE128, SHAKE256, SHA3_256, SHA3_512

#   Table 2. Approved parameter sets for ML-KEM
#   (k, eta1, eta2, du, dv)

ML_KEM_PARAM = {
    "ML-KEM-512"  : ( 2, 3, 2, 10, 4 ),
    "ML-KEM-768"  : ( 3, 2, 2, 10, 4 ),
    "ML-KEM-1024" : ( 4, 2, 2, 11, 5 )
}

#   Appendix A -- Precomputed Values for the NTT

#   The following 128 numbers are the values of zeta^BitRev7(i) mod q
#   for i in {0, ... , 127}. These numbers are used in Algs. 9 and 10.

ML_KEM_ZETA_NTT = [
    1,      1729,   2580,   3289,   2642,   630,    1897,   848,
    1062,   1919,   193,    797,    2786,   3260,   569,    1746,
    296,    2447,   1339,   1476,   3046,   56,     2240,   1333,
    1426,   2094,   535,    2882,   2393,   2879,   1974,   821,
    289,    331,    3253,   1756,   1197,   2304,   2277,   2055,
    650,    1977,   2513,   632,    2865,   33,     1320,   1915,
    2319,   1435,   807,    452,    1438,   2868,   1534,   2402,
    2647,   2617,   1481,   648,    2474,   3110,   1227,   910,
    17,     2761,   583,    2649,   1637,   723,    2288,   1100,
    1409,   2662,   3281,   233,    756,    2156,   3015,   3050,
    1703,   1651,   2789,   1789,   1847,   952,    1461,   2687,
    939,    2308,   2437,   2388,   733,    2337,   268,    641,
    1584,   2298,   2037,   3220,   375,    2549,   2090,   1645,
    1063,   319,    2773,   757,    2099,   561,    2466,   2594,
    2804,   1092,   403,    1026,   1143,   2150,   2775,   886,
    1722,   1212,   1874,   1029,   2110,   2935,   885,    2154 ]

#   When implementing Algorithm 11, the values zeta^{2*BitRev7(i)+1} mod q
#   need to be computed. The following array contains these values for
#   i in {0, ... , 127}:

ML_KEM_ZETA_MUL = [
    17,     -17,    2761,   -2761,  583,    -583,   2649,   -2649,
    1637,   -1637,  723,    -723,   2288,   -2288,  1100,   -1100,
    1409,   -1409,  2662,   -2662,  3281,   -3281,  233,    -233,
    756,    -756,   2156,   -2156,  3015,   -3015,  3050,   -3050,
    1703,   -1703,  1651,   -1651,  2789,   -2789,  1789,   -1789,
    1847,   -1847,  952,    -952,   1461,   -1461,  2687,   -2687,
    939,    -939,   2308,   -2308,  2437,   -2437,  2388,   -2388,
    733,    -733,   2337,   -2337,  268,    -268,   641,    -641,
    1584,   -1584,  2298,   -2298,  2037,   -2037,  3220,   -3220,
    375,    -375,   2549,   -2549,  2090,   -2090,  1645,   -1645,
    1063,   -1063,  319,    -319,   2773,   -2773,  757,    -757,
    2099,   -2099,  561,    -561,   2466,   -2466,  2594,   -2594,
    2804,   -2804,  1092,   -1092,  403,    -403,   1026,   -1026,
    1143,   -1143,  2150,   -2150,  2775,   -2775,  886,    -886,
    1722,   -1722,  1212,   -1212,  1874,   -1874,  1029,   -1029,
    2110,   -2110,  2935,   -2935,  885,    -885,   2154,   -2154 ]

"""
#   to generate equivalent tables
def bitrev7(x):
    y = 0
    for i in range(7):
        y += ((x >> i) & 1) << (6 - i)
    return y
ML_KEM_ZETA_NTT = [ (17 ** bitrev7(i)) % self.q for i in range(128) ]
ML_KEM_ZETA_MUL = [ (17 ** (2*bitrev7(i) + 1)) % self.q for i in range(128) ]
"""

class ML_KEM:

    def __init__(self, param='ML-KEM-768'):
        """ Initialize the class with parameters."""
        if param not in ML_KEM_PARAM:
            raise ValueError
        self.q = 3329
        self.n = 256
        (self.k, self.eta1, self.eta2, self.du, self.dv) = ML_KEM_PARAM[param]

    #   4.1 Cryptographic Functions

    def h(self, x):
        return SHA3_256.new(x).digest()

    def g(self, x):
        h = SHA3_512.new(x).digest()
        return ( h[0:32], h[32:64] )

    def j(self, s):
        return SHAKE256.new(s).read(32)

    def prf(self, eta, s, b):
        return SHAKE256.new(s + b.to_bytes()).read(64*eta)

    #   4.2.1 Conversion and Compression Algorithms

    #   rounding is floor(x+1/2)
    def compress(self, d, xv):
        return [ ( ((x << d) + (self.q-1)//2 ) // self.q ) % (1 << d)
                    for x in xv ]

    def decompress(self, d, yv):
        return [ (self.q*y + (1 << (d - 1))) >> d for y in yv ]

    #   Algorithm 3, BitsToBytes(b)

    def bits_to_bytes(self, b):
        l = len(b)
        a = bytearray(l // 8)
        for i in range(0, l, 8):
            x = 0
            for j in range(8):
                x += b[i + j] << j
            a[i // 8] = x
        return a

    #   Algorithm 4, BytesToBits(B)

    def bytes_to_bits(self, b):
        l = len(b)
        a = bytearray(8*l)
        for i in range(0, 8*l, 8):
            x = b[i // 8]
            for j in range(8):
                a[i + j] = (x >> j) & 1
        return a

    #   Algorithm 5, ByteEncode_d(F)

    def byte_encode(self, d, f):
        if type(f[0]) == list:
            b = b''
            for x in f:
                b += self.byte_encode(d, x)
            return b
        if d < 12:
            m = 1 << d
        else:
            m = self.q
        b = bytearray(256*d)
        for i in range(256):
            a = f[i] % m
            for j in range(d):
                b[i*d + j] = a % 2
                a //= 2
        b = self.bits_to_bytes(b)
        return b

    #   Algorithm 6, ByteDecode_d(B)

    def byte_decode(self, d, b):
        if d < 12:
            m = 1 << d
        else:
            m = self.q
        b = self.bytes_to_bits(b)
        f = [];
        for i  in range(256):
            x = 0
            for j in range(d):
                x += b[i*d + j] << j
            f += [ x % m ]
        return f

    #   Algorithm 7, SampleNTT(B)

    def sample_ntt(self, b):
        xof = SHAKE128.new(b)
        j   = 0
        a   = []
        while j < 256:
            c   = xof.read(3)
            d1  = c[0] + 256*(c[1] % 16)
            d2  = (c[1] // 16) + 16*c[2]
            if d1 < self.q:
                a += [ d1 ]
                j += 1
            if d2 < self.q and j < 256:
                a += [ d2 ]
                j += 1
        return a

    #   Algorithm 8, SamplePolyCBD_eta(B)

    def sample_poly_cbd(self, eta, b):
        b = self.bytes_to_bits(b)
        f = [0]*256
        for i in range(256):
            x = sum(b[2*i*eta:(2*i + 1)*eta])
            y = sum(b[(2*i + 1)*eta:(2*i + 2)*eta])
            f[i] = (x - y) % self.q
        return f


    #   Algorithm 9, NTT(f)

    def ntt(self, f):
        f   = f.copy()
        i   = 1
        le  = 128
        while le >= 2:
            for st in range(0, 256, 2*le):
                ze = ML_KEM_ZETA_NTT[i]
                i += 1
                for j in range(st, st + le):
                    t           = (ze*f[j + le]) % self.q
                    f[j + le]   = (f[j] - t) % self.q
                    f[j]        = (f[j] + t) % self.q
            le //= 2
        return f

    #   Algorithm 10, NTT^{−1}(~f)

    def ntt_inverse(self, f):
        f   = f.copy()
        i   = 127
        le  = 2
        while le <= 128:
            for st in range(0, 256, 2*le):
                ze = ML_KEM_ZETA_NTT[i]
                i -= 1
                for j in range(st, st + le):
                    t           =   f[j]
                    f[j]        =   (t + f[j + le]) % self.q
                    f[j + le]   =   (ze*(f[j + le] - t)) % self.q
            le  *= 2
        f   = [ (x*3303) % self.q for x in f ]
        return f

    #   Algorithm 11, MultiplyNTTs(~f, ~g)

    def multiply_ntts(self, f, g):
        h = []
        for ii in range(0, 256, 2):
            h += self.best_case_multiply(f[ii], f[ii+1], g[ii], g[ii+1],
                                            ML_KEM_ZETA_MUL[ii//2])
        return h

    #   Algorithm 12, BaseCaseMultiply(a0, a1, b0, b1, gamma)

    def best_case_multiply(self, a0, a1, b0, b1, gam):
        c0  = (a0*b0 + a1*b1*gam) % self.q
        c1  = (a0*b1 + a1*b0) % self.q
        return [ c0, c1 ]

    #   (Helper functions -- not in spec.)

    def poly_add(self, f, g):
        return [ (f[i] + g[i]) % self.q for i in range(256) ]

    def poly_sub(self, f, g):
        return [ (f[i] - g[i]) % self.q for i in range(256) ]

    #   Algorithm 13, K-PKE.KeyGen(d)

    def k_pke_keygen(self, d):
        (rho, sig) = self.g(d + self.k.to_bytes())
        # print('# rho:', rho.hex())
        # print('# sigma:', sig.hex())
        n   = 0

        a   = [ [None]*self.k for _ in range(self.k) ]
        for i in range(self.k):
            for j in range(self.k):
                a[i][j] = self.sample_ntt(rho + j.to_bytes() + i.to_bytes())
        # print('# aHat:', a)
        s   = [None]*self.k
        for i in range(self.k):
            s[i] = self.sample_poly_cbd(self.eta1, self.prf(self.eta1, sig, n))
            n   += 1
        # print('# s:', s)
        e   = [None]*self.k
        for i in range(self.k):
            e[i] = self.sample_poly_cbd(self.eta1, self.prf(self.eta1, sig, n))
            n   += 1
        # print('# e:', e)
        s   = [ self.ntt(v) for v in s ]
        # print('# sHat:', s)
        e   = [ self.ntt(v) for v in e ]
        # print('# eHat:', e)
        t   = e
        for i in range(self.k):
            for j in range(self.k):
                t[i] = self.poly_add(t[i], self.multiply_ntts(a[i][j], s[j]))
        # print('# tHat:', t)
        ek_pke = self.byte_encode(12, t) + rho
        dk_pke = self.byte_encode(12, s)
        return (ek_pke, dk_pke)

    #   Algorithm 14, K-PKE.Encrypt(ek_PKE, m, r)

    def k_pke_encrypt(self, ek_pke, m, r):
        n   = 0
        t   = [ self.byte_decode(12, ek_pke[384*i:384*(i+1)]) for i in range(self.k) ]
        # print('# tHat:"', t)
        rho = ek_pke[384*self.k : 384*self.k + 32]
        a   = [ [None]*self.k for _ in range(self.k) ]
        for i in range(self.k):
            for j in range(self.k):
                a[i][j] = self.sample_ntt(rho + j.to_bytes() + i.to_bytes())

        # print('# aHat:"', a)
        y = [None]*self.k
        for i in range(self.k):
            y[i] = self.sample_poly_cbd(self.eta1, self.prf(self.eta1, r, n))
            n   += 1
        # print('# y:"', y)
        e1 = [None]*self.k
        for i in range(self.k):
            e1[i] = self.sample_poly_cbd(self.eta2, self.prf(self.eta2, r, n))
            n += 1
        # print('# e1:"', e1)
        e2 = self.sample_poly_cbd(self.eta2, self.prf(self.eta2, r, n))
        # print('# e2:"', e2)
        y   = [ self.ntt(v) for v in y ]
        # print('# yHat:"', y)
        u   = [ [0]*256 for _ in range(self.k) ]
        for i in range(self.k):
            for j in range(self.k):
                u[i] = self.poly_add(u[i], self.multiply_ntts(a[j][i], y[j]))
        # print('# AHat^T*yHat:"', u)
        for i in range(self.k):
            u[i] = self.ntt_inverse(u[i])
            u[i] = self.poly_add(u[i], e1[i])
        # print('# u:', u);

        mu  = self.decompress(1, self.byte_decode(1, m))
        # print('# mu:', mu);

        v   = [0]*256
        for i in range(self.k):
            v = self.poly_add(v, self.multiply_ntts(t[i], y[i]))
        # print('# tHat^T*yHat:', v)
        v   = self.ntt_inverse(v)
        # print('# NTTInverse(tHat^T*yHat):', v)
        v   = self.poly_add(v, e2)
        v   = self.poly_add(v, mu)
        # print('# v:', v)
        c1  = b''
        for i in range(self.k):
            c1 += self.byte_encode(self.du, self.compress(self.du, u[i]))
        c2  = self.byte_encode(self.dv, self.compress(self.dv, v))
        c   = c1 + c2
        return c

    #   Algorithm 15, K-PKE.Decrypt(dk_PKE, c)

    def k_pke_decrypt(self, dk_pke, c):
        c1 = c[0 : 32*self.du*self.k]
        c2 = c[32*self.du*self.k : 32*(self.du*self.k + self.dv)]
        up = [ self.decompress(self.du,
                self.byte_decode(self.du, c1[32*self.du*i : 32*self.du*(i+1)]))
                    for i in range(self.k) ]
        # print('# u:', up)
        vp = self.decompress(self.dv, self.byte_decode(self.dv, c2))
        # print('# v:', vp)
        s  = [ self.byte_decode(12, dk_pke[384*i:384*(i+1)])
                for i in range(self.k) ]
        # print('# sHat:', s)
        w   = [0]*256
        for i in range(self.k):
            w = self.poly_add(w, self.multiply_ntts(s[i],
                                    self.ntt(up[i])))
        w   = self.poly_sub(vp, self.ntt_inverse(w))
        # print('# w:', w)
        m   = self.byte_encode(1, self.compress(1, w))
        # print('# mPrime:', m.hex())
        return m

    #   Algorithm 16, ML-KEM.KeyGen_internal(d, z)

    def keygen_internal(self, d, z, param=None):
        if param != None:
            self.__init__(param)
        (ek_pke, dk_pke) = self.k_pke_keygen(d)
        ek  = ek_pke
        dk  = dk_pke + ek + self.h(ek) + z
        return (ek, dk)

    #   Algorithm 17, ML-KEM.Encaps_internal(ek, m)

    def encaps_internal(self, ek, m, param=None):
        if param != None:
            self.__init__(param)
        (k, r)  = self.g( m + self.h(ek) )
        # print('# ek:', ek.hex())
        # print('# m:', m.hex())
        # print('# K:', k.hex())
        # print('# r:', r.hex())
        c   = self.k_pke_encrypt(ek, m, r)
        return  (k, c)

    #   Algorithm 18, ML-KEM.Decaps_internal(dk, c)
    def decaps_internal(self, dk, c, param=None):
        if param != None:
            self.__init__(param)
        (k, eta1, eta2, du, dv) = ML_KEM_PARAM[param]
        dk_pke = dk[0 : 384*self.k]
        ek_pke = dk[384*self.k : 768*self.k + 32]
        h = dk[768*self.k + 32 : 768*self.k + 64]
        z = dk[768*self.k + 64 : 768*self.k + 96]
        # print('# dk_pke:', dk_pke.hex())
        # print('# ek_pke:', ek_pke.hex())
        # print('# h:', h.hex())
        # print('# z:', z.hex())
        mp = self.k_pke_decrypt(dk_pke, c)
        (kp, rp) = self.g(mp + h)
        kk = self.j(z + c)
        cp = self.k_pke_encrypt(ek_pke, mp, rp)
        if c != cp:
            kp = kk
        return kp

#   run the test on these functions
if __name__ == '__main__':
    ml_kem = ML_KEM()
    test_mlkem( ml_kem.keygen_internal,
                ml_kem.encaps_internal,
                ml_kem.decaps_internal,
                '(fips203.py)')

