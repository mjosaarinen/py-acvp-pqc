#   py-acvp-pqc

2024-07-01  Markku-Juhani O. Saarinen  mjos@iki.fi

#   Background

Functional validation of crypto algorithms in the FIPS 140-3 scheme is based on NIST's Automated Cryptographic Validation Test System (ACVTS). This system contains crypto algorithm implementations that effectively serve as the "golden reference" for algorithm validation: They are used to generate randomized test cases in ACVTS. 

The crypto implementations used by NIST's [ACVP-Server](https://github.com/usnistgov/ACVP-Server) are written in C# and run on Microsoft's .NET framework (version 6). Recently implementations of the new NIST PQC standards
Kyber ([Kyber.cs](https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/src/crypto/src/NIST.CVP.ACVTS.Libraries.Crypto/Kyber/Kyber.cs) for [FIPS 203 ML-KEM](https://doi.org/10.6028/NIST.FIPS.203.ipd)),
Dilithium ([Dilithium.cs](https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/src/crypto/src/NIST.CVP.ACVTS.Libraries.Crypto/Dilithium/Dilithium.cs) for [FIPS 204 ML-DSA](https://doi.org/10.6028/NIST.FIPS.204.ipd)), and
SPHINCS+ ([Slhdsa.cs](https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/src/crypto/src/NIST.CVP.ACVTS.Libraries.Crypto/SLHDSA/Slhdsa.cs) for [FIPS 205 SLH-DSA](https://doi.org/10.6028/NIST.FIPS.205.ipd))have been added to the repo. These may not be the best or the most elegant implementations, many will want to ensure functional equivalence to this code for interoperability and certification purposes.

This repo provides a hacky Python interface to run the NIST Reference Kyber and Dilithium implementations on a Linux system ( I have not tested it, but [Pythonnet](http://pythonnet.github.io/) is available onMac and Windows, too. ) There is also code to run tests against the static JSON-format test vectors in the ACVP-Server repo.

Note that the NIST reference implementations absolutely should **not** be used "in production" since no attention has been paid to crucial factors such as resistance against (remote) timing attacks. This is simply not needed in test vector generation. Furthermore, the code is still "alive" and has not been officially released (AFAIK). However, they can be quite useful for functional testing, printing out intermediate values, etc.

**ABSOLUTELY NO WARRANTY. SUPPORT NOT AVAILABLE.** You can report issues but don't expect this repo to be actively maintained.


### Wrapper functions for NIST's Kyber code:

These are provided by [nist_mlkem.py](nist_mlkem.py). You may have to adjust this module to find the relevant DLLs for Kyber.

Key Generation:
```py
def nist_mlkem_keygen(z, d, param='ML-KEM-768'):
    """ (ek, dk) = ML-KEM.KeyGen(z, d, param='ML-KEM-768'). """
```

Encapsulate:
```py
def nist_mlkem_encaps(ek, m, param='ML-KEM-768'):
    """ (K, c) = ML-KEM.Encaps(ek, m, param='ML-KEM-768'). """
```

Decapsulate:
```py
def nist_mlkem_decaps(c, dk, param='ML-KEM-768'):
    """ K = ML-KEM.Decaps(c, dk, param='ML-KEM-768'). """
```

Test module [test_mlkem.py](test_mlkem.py) parses the JSON-format Kyber test vectors  in the ACVP-Server repo and executes the related tests using the wrapper functions.

```
$ python3 test_mlkem.py
ML-KEM KeyGen: PASS= 75  FAIL= 0
ML-KEM Encaps: PASS= 75  FAIL= 0
ML-KEM Decaps: PASS= 30  FAIL= 0
```

### Wrapper functions for NIST's Dilithium code:

These are provided by [nist_mldsa.py](nist_mldsa.py). You may have to adjust this module to find the relevant DLLs for Dilithium.

Key Generation:

```py
def nist_mldsa_keygen(seed, param='ML-DSA-65'):
    """ (pk, sk) = ML-DSA.KeyGen(seed, param='ML-DSA-65'). """
```

Sign a message:
```py
def nist_mldsa_sign(sk, m, det, param='ML-DSA-65'):
    """ sig = ML-DSA.Sign(sk, M, det, param='ML-DSA-64'). """
```

Verify a signature:
```py
def nist_mldsa_verify(pk, m, sig, param='ML-DSA-65'):
    """ True/False = ML-DSA.Verify(pk, M, sig, param='ML-DSA-64'). """
```

Test module [test_mldsa.py](test_mldsa.py) parses the Dilithium test vectors in the ACVP-Server repo and executes the related tests using the wrapper functions.

```
$ python3 test_mldsa.py
ML-DSA KeyGen: PASS= 75  FAIL= 0
ML-DSA SigGen: PASS= 30  FAIL= 0  SKIP= 30
ML-DSA SigVer: PASS= 45  FAIL= 0
```

_( If you're curious why 30 test vectors are "skipped," The non-deterministic signature code is indeed non-deterministic and makes an internal call to an RBG. Hence, we're not trying to match those answers. )_

#   Step-by-step Running Instructions

This is very hacky: The followign steps were executed on a fresh install of Ubuntu 24.04 LTS on July 3, 2024 and it worked then. If it doesn't work for you, too bad -- NIST ACVTS code is in flux and .NET6 is at its End of Service in 2024, etc. 

Clone this repo
```
$ git clone https://github.com/mjosaarinen/py-acvp-pqc.git
$ cd py-acvp-pqc
```

### Install the .NET 6 SDK

Following [Microsoft's instructions for .NET on Ubuntu](https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu):
```console
$ sudo add-apt-repository ppa:dotnet/backports
$ sudo apt install dotnet-sdk-6.0
```
Note that you need the SDK as you're compiling C# code. If you're using a more stripped-down distro than Ubuntu, you will encounter many more dependencies.


### Build the needed .dll files

Fetch the ACVP server sources (it's big!). We will put it right here under the py-acvp-pqc directory, but you can also have a ACVP-Server symlink.
```console
$ git clone https://github.com/usnistgov/ACVP-Server.git
```
We perform some preparatory steps:
```console
$ cd ACVP-Server
$ rm -f Directory.Build.prop
$ rm -f Directory.Packages.props
$ ln -s ./_config/Directory.Build.props
$ ln -s ./_config/Directory.Packages.props
```

We can now build the relevant implementation libraries (which are .dll files). One way to do this is by running some tests that have them as dependencies:

```console
$ dotnet test gen-val/src/crypto/test/NIST.CVP.ACVTS.Libraries.Crypto.Kyber.Tests/NIST.CVP.ACVTS.Libraries.Crypto.Kyber.Tests.csproj
$ dotnet test gen-val/src/crypto/test/NIST.CVP.ACVTS.Libraries.Crypto.Dilithium.Tests/NIST.CVP.ACVTS.Libraries.Crypto.Dilithium.Tests.csproj
```

There is quite a lot of output, but we're done here.
```
$ cd ..
```

### Run our Python Tests

We're using [Pythonnet](http://pythonnet.github.io/) and you will probably have to install it. Let's install venv (if you don't have it already), and use a local environment:

```console
$ sudo apt install python3-venv
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip3 install pythonnet
```

Note that you will have to "enter" the enviroment with `source .venv/bin/activate` to use pythonnet installed locally this way.

Anyway, we should now be able to execute our Kyber and Dilithium test programs:
```
$ python3 test_mlkem.py
ML-KEM KeyGen: PASS= 75  FAIL= 0
ML-KEM Encaps: PASS= 75  FAIL= 0
ML-KEM Decaps: PASS= 30  FAIL= 0

$ python3 test_mldsa.py
ML-DSA KeyGen: PASS= 75  FAIL= 0
ML-DSA SigGen: PASS= 30  FAIL= 0  SKIP= 30
ML-DSA SigVer: PASS= 45  FAIL= 0
```
This is a success!



