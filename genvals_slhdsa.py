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
clr.AddReference(abs_path + 'test/NIST.CVP.ACVTS.Libraries.Crypto.SLHDSA.Tests/bin/Debug/net6.0/NLog.dll')
clr.AddReference(abs_path + 'test/NIST.CVP.ACVTS.Libraries.Crypto.SLHDSA.Tests/bin/Debug/net6.0/NIST.CVP.ACVTS.Libraries.Common.dll')
clr.AddReference(abs_path + 'test/NIST.CVP.ACVTS.Libraries.Crypto.SLHDSA.Tests/bin/Debug/net6.0/NIST.CVP.ACVTS.Libraries.Crypto.dll')

#   imports for slh-dsa
from System.Collections import BitArray
from NIST.CVP.ACVTS.Libraries.Crypto.SHA import NativeFastSha
from NIST.CVP.ACVTS.Libraries.Crypto.SLHDSA import Slhdsa, Wots, Xmss, Hypertree, Fors
from NIST.CVP.ACVTS.Libraries.Crypto.Common.PQC.SLHDSA.Enums import SlhdsaParameterSet
from NIST.CVP.ACVTS.Libraries.Crypto.Common.PQC.SLHDSA.Helpers import AttributesHelper
from NIST.CVP.ACVTS.Libraries.Crypto.Common.PQC.SLHDSA import PublicKey, PrivateKey

#   XXX supress debug output as the SLH-DSA code currently has
#   Console.WriteLine() debug.

import System
#System.Console.SetOut(System.IO.TextWriter.Null);

#   SLH-DSA parameter sets

slh_dsa_ps = {
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
    'SLH-DSA-SHAKE-256f' : SlhdsaParameterSet.SLH_DSA_SHAKE_256f
}

#   helper functions

def nist_slh_getinstance():
    t_shaf  = NativeFastSha.NativeShaFactory()
    t_wots  = Wots(t_shaf)
    t_xmss  = Xmss(t_shaf, t_wots)
    t_htree = Hypertree(t_xmss)
    t_fors  = Fors(t_shaf)
    return Slhdsa(t_shaf, t_xmss, t_htree, t_fors)

#   test wrappers for NIST functions

def nist_slh_keygen( sk_seed, sk_prf, pk_seed, param='SLH-DSA-SHA2-128s'):
    slhdsa  = nist_slh_getinstance()
    t_attrb = AttributesHelper.GetParameterSetAttribute(slh_dsa_ps[param])
    t_keys  = slhdsa.SlhKeyGen( sk_seed, sk_prf, pk_seed, t_attrb );

    #   it seems that caller has to construct the concatenated byte blobs
    pk = (  bytes(t_keys.PublicKey.PkSeed)  +
            bytes(t_keys.PublicKey.PkRoot)  )
    sk = (  bytes(t_keys.PrivateKey.SkSeed) +
            bytes(t_keys.PrivateKey.SkPrf)  +
            bytes(t_keys.PrivateKey.PkSeed) +
            bytes(t_keys.PrivateKey.PkRoot) )
    return (pk, sk)

def nist_slh_sign( msg, sk, addrnd, param='SLH-DSA-SHA2-128s'):
    slhdsa  = nist_slh_getinstance()
    t_attrb = AttributesHelper.GetParameterSetAttribute(slh_dsa_ps[param])
    n       = t_attrb.N
    t_sk    = PrivateKey(sk[0:n], sk[n:2*n], sk[2*n:3*n], sk[3*n:4*n])

    # "substitute opt_rand <- PK.seed for the deterministic variant"
    if  addrnd == None:
        addrnd = sk[2*n:3*n]

    t_sig = slhdsa.SlhSignNonDeterministic(msg, t_sk, addrnd, t_attrb);
    return bytes(t_sig)


def nist_slh_verify( msg, sig, pk, param='SLH-DSA-SHA2-128s'):
    slhdsa  = nist_slh_getinstance()
    t_attrb = AttributesHelper.GetParameterSetAttribute(slh_dsa_ps[param])
    n       = t_attrb.N
    t_pk    = PublicKey(pk[0:n], pk[n:2*n])
    t_res   = slhdsa.SlhVerify(msg, sig, t_pk, t_attrb)
    return  t_res.Success

#   run the test on these functions
if __name__ == '__main__':
    test_slhdsa(nist_slh_keygen,
                nist_slh_sign,
                nist_slh_verify,
                '(NIST Gen/Vals)')

