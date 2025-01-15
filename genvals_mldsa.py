#   genvals_mldsa.py
#   2024-07-02  Markku-Juhani O. Saarinen <mjos@iki.fi>
#   === Python wrapper for ML-DSA / Dilithium in the NIST ACVTS Libraries

#   test_mldsa is only used by the unit test in the end
from test_mldsa import test_mldsa

#   .NET Core
from pythonnet import load
load("coreclr")
import os,clr

#   you may have to adjust these paths (need to be absolute!)
abs_path = os.getcwd() + '/ACVP-Server/gen-val/src/crypto/'
clr.AddReference(abs_path + 'test/NIST.CVP.ACVTS.Libraries.Crypto.Dilithium.Tests/bin/Debug/net8.0/NLog.dll')
clr.AddReference(abs_path + 'test/NIST.CVP.ACVTS.Libraries.Crypto.Dilithium.Tests/bin/Debug/net8.0/NIST.CVP.ACVTS.Libraries.Math.dll')
clr.AddReference(abs_path + 'src/NIST.CVP.ACVTS.Libraries.Crypto/bin/Debug/net8.0/NIST.CVP.ACVTS.Libraries.Crypto.dll')

#   imports for dilithium
from System.Collections import BitArray
from NIST.CVP.ACVTS.Libraries.Math import Random800_90
from NIST.CVP.ACVTS.Libraries.Math.Entropy import EntropyProvider
from NIST.CVP.ACVTS.Libraries.Crypto.SHA import NativeFastSha
from NIST.CVP.ACVTS.Libraries.Crypto.Dilithium import Dilithium
from NIST.CVP.ACVTS.Libraries.Crypto.Common.PQC.Dilithium import DilithiumParameterSet, DilithiumParameters

#   XXX supress debug output as the Dilithium code currently has
#   Console.WriteLine() debug.

import System
System.Console.SetOut(System.IO.TextWriter.Null);

#   test wrappers for NIST functions
class ML_DSA_GV:

    #   initialize
    def __init__(self):

        #   ML-DSA parameter sets
        self.ml_dsa_ps = {  'ML-DSA-44': DilithiumParameterSet.ML_DSA_44,
                            'ML-DSA-65': DilithiumParameterSet.ML_DSA_65,
                            'ML-DSA-87': DilithiumParameterSet.ML_DSA_87 }
        """
        'ML-DSA-44': DilithiumParameters(DilithiumParameterSet.ML_DSA_44),
        'ML-DSA-65': DilithiumParameters(DilithiumParameterSet.ML_DSA_65),
        'ML-DSA-87': DilithiumParameters(DilithiumParameterSet.ML_DSA_87) }
        """
    #   helper functions
    def nist_bits(self, x):
        """ Convert a byte array into a C# BitArray for the NIST library. """
        l = len(x) * 8
        y = BitArray(l)
        for i in range(l):
            y.Set(l - 1 - i, (x[i >> 3] << (i & 7)) & 0x80 != 0 )
        return y

    #   wrapper functions

    #   Algorithm 2, ML-DSA.Sign(sk, M, ctx)

    def sign(self, sk, m, ctx=b'', rnd=None, param=None):
        print('ML_DSA_GV.sign() not implemented')
        return None

    #   Algorithm 3, ML-DSA.Verify(pk, M, sigma, ctx)

    def verify(self, pk, m, sig, ctx=b'', param=None):
        print('ML_DSA_GV.verify() not implemented')
        return None

    #   Algorithm 4, HashML-DSA.Sign(sk, M, ctx, PH)

    def hash_ml_dsa_sign(self, sk, m, ctx=b'', ph='SHA2-512', rnd=None, param=None):
        print('ML_DSA_GV.hash_ml_dsa_sign() not implemented')
        return None

    #   Algorithm 5, HashML-DSA.Verify(pk, M, sig, ctx, PH)

    def hash_ml_dsa_verify(self, pk, m, sig, ctx=b'', ph='SHA2-512', param=None):
        print('ML_DSA_GV.hash_ml_dsa_verify() not implemented')
        return None

    #   Algorithm 6: ML-DSA.KeyGen_internal(xi)

    def keygen_internal(self, seed, param=None):
        dilithium = Dilithium(  self.ml_dsa_ps[param],
                                NativeFastSha.NativeShaFactory(),
                                EntropyProvider(Random800_90()))
        ret = dilithium.GenerateKey( self.nist_bits(seed) )
        pk  = bytes(ret.Item1)
        sk  = bytes(ret.Item2)
        return (pk, sk)

    #   Algorithm 7, ML-DSA.Sign_internal(sk, M', rnd)

    def sign_internal(self, sk, mp, rnd, param=None, mu=None):
        dilithium = Dilithium(  self.ml_dsa_ps[param],
                                NativeFastSha.NativeShaFactory(),
                                EntropyProvider(Random800_90()))
        if mu != None:
            sig = dilithium.SignExternalMu(sk, mu, rnd)
        else:
            sig = dilithium.Sign(sk, mp, rnd)
        return bytes(sig)

    #   Algorithm 8, ML-DSA.Verify_internal(pk, M', sigma)

    def verify_internal(self, pk, mp, sig, param=None, mu=None):
        dilithium = Dilithium(  self.ml_dsa_ps[param],
                                NativeFastSha.NativeShaFactory(),
                                EntropyProvider(Random800_90()))
        if mp != None:
            res = dilithium.Verify(pk, mp, sig)
            return res
        print('ML_DSA_GV.verify_internal() external mu not implemented')
        return None

#   run the test on these functions
if __name__ == '__main__':

    ml_dsa_gv = ML_DSA_GV()
    test_mldsa( ml_dsa_gv,
                '(NIST Gen/Vals)')

