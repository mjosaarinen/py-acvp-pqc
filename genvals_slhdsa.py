#   genvals_slhdsa.py
#   2024-08-18  Markku-Juhani O. Saarinen <mjos@iki.fi>
#   === Python wrapper for SLH-DSA / SPHINCS+ in the NIST ACVTS Libraries

#   test_slhdsa is only used by the unit test in the end
from test_slhdsa import test_slhdsa

#   .NET Core
from pythonnet import load
load("coreclr")
import os,clr

#   you may have to adjust these paths (need to be absolute!)
abs_path = os.getcwd() + '/ACVP-Server/gen-val/src/crypto/'
clr.AddReference(abs_path + 'test/NIST.CVP.ACVTS.Libraries.Crypto.SLHDSA.Tests/bin/Debug/net8.0/NLog.dll')
clr.AddReference(abs_path + 'test/NIST.CVP.ACVTS.Libraries.Crypto.SLHDSA.Tests/bin/Debug/net8.0/NIST.CVP.ACVTS.Libraries.Common.dll')
clr.AddReference(abs_path + 'test/NIST.CVP.ACVTS.Libraries.Crypto.SLHDSA.Tests/bin/Debug/net8.0/NIST.CVP.ACVTS.Libraries.Crypto.dll')

#   imports for slh-dsa
from System.Collections import BitArray
from NIST.CVP.ACVTS.Libraries.Math import Random800_90
from NIST.CVP.ACVTS.Libraries.Math.Entropy import EntropyProvider
from NIST.CVP.ACVTS.Libraries.Crypto.SHA import NativeFastSha
from NIST.CVP.ACVTS.Libraries.Crypto.SLHDSA import Slhdsa, Wots, Xmss, Hypertree, Fors
from NIST.CVP.ACVTS.Libraries.Crypto.Common.PQC.SLH_DSA.Enums import SlhdsaParameterSet
from NIST.CVP.ACVTS.Libraries.Crypto.Common.PQC.SLH_DSA.Helpers import AttributesHelper
from NIST.CVP.ACVTS.Libraries.Crypto.Common.PQC.SLH_DSA import PublicKey, PrivateKey

#   XXX supress debug output as the SLH-DSA code currently has
#   Console.WriteLine() debug.

import System
#System.Console.SetOut(System.IO.TextWriter.Null);

#   test wrappers for NIST functions
class SLH_DSA_GV:

    #   initialize
    def __init__(self, param=None):

        #   SLH-DSA parameter sets
        self.slh_dsa_ps = {
            'SLH-DSA-SHA2-128s' : SlhdsaParameterSet.SLH_DSA_SHA2_128s,
            'SLH-DSA-SHA2-128f' : SlhdsaParameterSet.SLH_DSA_SHA2_128f,
            'SLH-DSA-SHA2-192s' : SlhdsaParameterSet.SLH_DSA_SHA2_192s,
            'SLH-DSA-SHA2-192f' : SlhdsaParameterSet.SLH_DSA_SHA2_192f,
            'SLH-DSA-SHA2-256s' : SlhdsaParameterSet.SLH_DSA_SHA2_256s,
            'SLH-DSA-SHA2-256f' : SlhdsaParameterSet.SLH_DSA_SHA2_256f,
            'SLH-DSA-SHAKE-128s' : SlhdsaParameterSet.SLH_DSA_SHAKE_128s,
            'SLH-DSA-SHAKE-128f' : SlhdsaParameterSet.SLH_DSA_SHAKE_128f,
            'SLH-DSA-SHAKE-192s' : SlhdsaParameterSet.SLH_DSA_SHAKE_192s,
            'SLH-DSA-SHAKE-192f' : SlhdsaParameterSet.SLH_DSA_SHAKE_192f,
            'SLH-DSA-SHAKE-256s' : SlhdsaParameterSet.SLH_DSA_SHAKE_256s,
            'SLH-DSA-SHAKE-256f' : SlhdsaParameterSet.SLH_DSA_SHAKE_256f }

        if param != None:
            self.t_attrb = AttributesHelper.GetParameterSetAttribute(
                                        self.slh_dsa_ps[param])
            self.slhdsa = Slhdsa(   self.t_attrb,
                                    NativeFastSha.NativeShaFactory(),
                                    EntropyProvider(Random800_90()))

    #   helper functions
    def nist_slh_getinstance(self):
        t_shaf  = NativeFastSha.NativeShaFactory()
        t_wots  = Wots(t_shaf)
        t_xmss  = Xmss(t_shaf, t_wots)
        t_htree = Hypertree(t_xmss)
        t_fors  = Fors(t_shaf)
        return Slhdsa(t_shaf, t_xmss, t_htree, t_fors)

    #   test wrappers for NIST functions

    def slh_keygen_internal(self, sk_seed, sk_prf, pk_seed, param=None):
        """ Algorithm 18: slh_keygen_internal()."""
        if param != None:
            self.__init__(param)
        t_keys  = self.slhdsa.SlhKeyGen( sk_seed, sk_prf, pk_seed );

        #   it seems that caller has to construct the concatenated byte blobs
        pk = (  bytes(t_keys.PublicKey.PkSeed)  +
                bytes(t_keys.PublicKey.PkRoot)  )
        sk = (  bytes(t_keys.PrivateKey.SkSeed) +
                bytes(t_keys.PrivateKey.SkPrf)  +
                bytes(t_keys.PrivateKey.PkSeed) +
                bytes(t_keys.PrivateKey.PkRoot) )
        return (pk, sk)

    def slh_sign_internal(self, m, sk, addrnd, param=None):
        """ Algorithm 19: slh_sign_internal(M, SK). """
        if param != None:
            self.__init__(param)
        n       = self.t_attrb.N

        # "substitute opt_rand <- PK.seed for the deterministic variant"
        if  addrnd == None:
            addrnd = sk[2*n:3*n]

        t_sig = self.slhdsa.Sign(sk, m, addrnd);
        return bytes(t_sig)

    def slh_verify_internal(self, m, sig, pk, param=None):
        """ Algorithm 20: slh_verify_internal(M, SIG, PK)."""
        if param != None:
            self.__init__(param)
        res = self.slhdsa.Verify(pk, m, sig)
        return  res

    def slh_sign(self, m, ctx, sk, addrnd=None, param=None):
        """ Algorithm 22, slh_sign(M, ctx, SK)."""
        print('SLH_DSA_GV.slh_sign() not implemented')
        return None

    def hash_slh_sign(self, m, ctx, ph, sk, addrnd=None, param=None):
        """ Algorithm 23, hash_slh_sign(M, ctx, PH, SK). """
        print('SLH_DSA_GV.hash_slh_sign() not implemented')
        return None

    def slh_verify(self, m, sig, ctx, pk, param=None):
        """ Algorithm 24, slh_verify(M, SIG, ctx, PK)."""
        print('SLH_DSA_GV.slh_verify() not implemented')
        return None

    def hash_slh_verify(self, m, sig, ctx, ph, pk, param=None):
        """ Algorithm 25, hash_slh_verify(M, SIG, ctx, PH, PK)."""
        print('SLH_DSA_GV.hash_slh_verify() not implemented')
        return None

#   run the test on these functions
if __name__ == '__main__':
    slh_dsa_gv = SLH_DSA_GV()
    test_slhdsa(slh_dsa_gv, '(NIST Gen/Vals)')

