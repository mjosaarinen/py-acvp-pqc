#   genvals_mlkem.py
#   2024-07-02  Markku-Juhani O. Saarinen <mjos@iki.fi>
#   === Python wrapper for ML-KEM / Kyber in the NIST ACVTS Libraries

#   test_mlkem is only used by the unit test in the end
from test_mlkem import test_mlkem

#   .NET Core
from pythonnet import load
load("coreclr")
import os,clr

#   you may have to adjust these paths (need to be absolute!)
abs_path = os.getcwd() + '/ACVP-Server/gen-val/src/crypto/'
clr.AddReference(abs_path + 'test/NIST.CVP.ACVTS.Libraries.Crypto.Kyber.Tests/bin/Debug/net8.0/NLog.dll')
clr.AddReference(abs_path + 'src/NIST.CVP.ACVTS.Libraries.Crypto/bin/Debug/net8.0/NIST.CVP.ACVTS.Libraries.Crypto.dll')

#   imports for kyber

from NIST.CVP.ACVTS.Libraries.Crypto.SHA import NativeFastSha
from NIST.CVP.ACVTS.Libraries.Crypto.Kyber import Kyber
from NIST.CVP.ACVTS.Libraries.Crypto.Common.PQC.Kyber import KyberParameterSet, KyberParameters

#   XXX supress debug output as the Kyber code currently has
#   Console.WriteLine() debug.

import System
System.Console.SetOut(System.IO.TextWriter.Null);

#   ML-KEM parameter sets

NIST_ML_KEM_PS = {
    'ML-KEM-512':   KyberParameters(KyberParameterSet.ML_KEM_512),
    'ML-KEM-768':   KyberParameters(KyberParameterSet.ML_KEM_768),
    'ML-KEM-1024':  KyberParameters(KyberParameterSet.ML_KEM_1024) }

#   test wrappers for NIST functions

def nist_mlkem_keygen(d, z, param='ML-KEM-768'):
    """ (ek, dk) = ML-KEM.KeyGen(d, z, param='ML-KEM-768'). """
    kyber = Kyber(  NIST_ML_KEM_PS[param],
                    NativeFastSha.NativeShaFactory())
    ret = kyber.GenerateKey(z, d)   # yes, they're in reverse order
    ek  = bytes(ret.Item1)
    dk  = bytes(ret.Item2)
    return (ek, dk)

def nist_mlkem_encaps(ek, m, param='ML-KEM-768'):
    """ (K, c) = ML-KEM.Encaps(ek, m, param='ML-KEM-768'). """
    kyber = Kyber(  NIST_ML_KEM_PS[param],
                    NativeFastSha.NativeShaFactory())
    ret = kyber.Encapsulate(ek, m)
    k   = bytes(ret.Item1)
    c   = bytes(ret.Item2)
    return (k, c)

def nist_mlkem_decaps(dk, c, param='ML-KEM-768'):
    """ K = ML-KEM.Decaps(dk, c, param='ML-KEM-768'). """
    kyber = Kyber(  NIST_ML_KEM_PS[param],
                    NativeFastSha.NativeShaFactory())
    ret = kyber.Decapsulate(dk, c)
    k   = bytes(ret.Item1)
    return k

#   run the test on these functions
if __name__ == '__main__':
    test_mlkem( nist_mlkem_keygen,
                nist_mlkem_encaps,
                nist_mlkem_decaps,
                '(NIST Gen/Vals)')

