#   nist_mldsa.py
#   2024-07-02  Markku-Juhani O. Saarinen <mjos@iki.fi>
#   === Python wrapper for ML-DSA / Dilithium in the NIST ACVTS Libraries

from pythonnet import load
load("coreclr")
import os,clr

#   you may have to adjust these paths (need to be absolute!)
abs_path = os.getcwd() + '/ACVP-Server/gen-val/src/crypto/'
clr.AddReference(abs_path + 'test/NIST.CVP.ACVTS.Libraries.Crypto.Dilithium.Tests/bin/Debug/net6.0/NIST.CVP.ACVTS.Libraries.Math.dll')
clr.AddReference(abs_path + 'src/NIST.CVP.ACVTS.Libraries.Crypto/bin/Debug/net6.0/NIST.CVP.ACVTS.Libraries.Crypto.dll')

#   imports for dilithium
from System.Collections import BitArray
from NIST.CVP.ACVTS.Libraries.Math import Random800_90
from NIST.CVP.ACVTS.Libraries.Math.Entropy import EntropyProvider
from NIST.CVP.ACVTS.Libraries.Crypto.SHA import NativeFastSha
from NIST.CVP.ACVTS.Libraries.Crypto.Dilithium import Dilithium
from NIST.CVP.ACVTS.Libraries.Crypto.Common.PQC.Dilithium import DilithiumParameterSet, DilithiumParameters

#   ML-DSA parameter sets

ml_dsa_ps = {
    'ML-DSA-44': DilithiumParameters(DilithiumParameterSet.ML_DSA_44),
    'ML-DSA-65': DilithiumParameters(DilithiumParameterSet.ML_DSA_65),
    'ML-DSA-87': DilithiumParameters(DilithiumParameterSet.ML_DSA_87) }

#   helper functions

def nist_bits(x):
    """ Convert a byte array into a C# BitArray for the NIST library. """
    l = len(x) * 8
    y = BitArray(l)
    for i in range(l):
        y.Set(l - 1 - i, (x[i >> 3] << (i & 7)) & 0x80 != 0 )
    return y

#   test wrappers for NIST functions

def nist_mldsa_keygen(seed, param='ML-DSA-65'):
    """ (pk, sk) = ML-DSA.KeyGen(seed, param='ML-DSA-65'). """
    dilithium = Dilithium(  ml_dsa_ps[param],
                            NativeFastSha.NativeShaFactory(),
                            EntropyProvider(Random800_90()))
    ret = dilithium.GenerateKey( nist_bits(seed) )
    pk  = bytes(ret.Item1)
    sk  = bytes(ret.Item2)
    return (pk, sk)

def nist_mldsa_sign(sk, m, det, param='ML-DSA-65'):
    """ sig = ML-DSA.Sign(sk, M, det, param='ML-DSA-64'). """
    dilithium = Dilithium(  ml_dsa_ps[param],
                            NativeFastSha.NativeShaFactory(),
                            EntropyProvider(Random800_90()))
    sig = dilithium.Sign(sk, nist_bits(m), det)
    return bytes(sig)

def nist_mldsa_verify(pk, m, sig, param='ML-DSA-65'):
    """ True/False = ML-DSA.Verify(pk, M, sig, param='ML-DSA-64'). """
    dilithium = Dilithium(  ml_dsa_ps[param],
                            NativeFastSha.NativeShaFactory(),
                            EntropyProvider(Random800_90()))
    res = dilithium.Verify(pk, sig, nist_bits(m))
    return res

