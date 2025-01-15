#   py-acvp-pqc

2024-07-01  Markku-Juhani O. Saarinen  mjos@iki.fi

Updated 2024-08-20 for the release FIPS 203, FIPS 204, FIPS 205.

Updated 2024-11-08 for some new SLH-DSA test vectors, dotnet 8.0.

Updated 2025-01-15 added new external tests for python implementations.

**note** Currently only "internal" functions are tested with NIST gen/vals.
The Python modules should support all test cases.

```
py-acvp-pqc
├── fips203.py          # Python implementation of ML-KEM ("Kyber")
├── fips204.py          # Python implementation of ML-DSA ("Dilithium")
├── fips205.py          # Python implementation of SLH-DSA ("SPHINCS+")
├── genvals_mlkem.py    # Python wrapper for ML-KEM in NIST's C# Gen/Vals
├── genvals_mldsa.py    # Python wrapper for ML-DSA in NIST's C# Gen/Vals
├── genvals_slhdsa.py   # Python wrapper for SLH-DSA in NIST's C# Gen/Vals
├── test_mlkem.py       # Parser/tester for ML-KEM ACVP test vectors
├── test_mldsa.py       # Parser/tester for ML-DSA ACVP test vectors
├── test_slhdsa.py      # Parser/tester for SLH-DSA ACVP test vectors
├── ACVP-Server         # (Symlink to) NIST's ACVP-Server repo for Gen/Vals
├── json-copy           # Local copy from ACVP-Server/gen-val/json-files/
├── Makefile            # Makefile for cleanups
├── requirements.txt    # Python dependencies
├── LICENSE             # Unlicense
└── README.md           # This file
```

#   Testing the Python implementations

You won't need the NIST C# dependencies to run the local Python implementations (or "models") of Kyber and Dilithium. These are self-contained, apart from hash function code (obtainable via `pip3 install pycryptodome`).

*   ML-KEM: [fips203.py](fips203.py) is a self-contained implementation of [FIPS 203 ML-KEM](https://doi.org/10.6028/NIST.FIPS.203) a.k.a. Kyber.
*   ML-DSA: [fips204.py](fips204.py) is a self-contained implementation of [FIPS 204 ML-DSA](https://doi.org/10.6028/NIST.FIPS.204) a.k.a. Dilithium.
*   SLH-DSA: [fips205.py](fips205.py) is a self-contained implementation of [FIPS 205 SLH-DSA](https://doi.org/10.6028/NIST.FIPS.205) a.k.a. SPHINCS+.
*   Test vector json parsers: [test_mlkem.py](test_mlkem.py), [test_mldsa.py](test_mldsa.py), and [test_slhdsa.py](test_slhdsa.py).
*   Test vectors: there's a local copy of relevant json test vectors from NIST in [json-copy](json-copy). These can be synced with [https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files).

The main functions have unit tests. For ML-KEM:

```
$ python3 fips203.py
ML-KEM KeyGen (fips203.py): PASS= 75  FAIL= 0
ML-KEM Encaps (fips203.py): PASS= 75  FAIL= 0
ML-KEM Decaps (fips203.py): PASS= 30  FAIL= 0
ML-KEM (fips203.py) -- Total FAIL= 0
```

Running the test for ML_DSA is similar. Note that 360 signatures will take a while:
```
$ python3 fips204.py
ML-DSA KeyGen (fips204.py): PASS= 75  FAIL= 0
ML-DSA SigGen (fips204.py): PASS= 360  FAIL= 0
ML-DSA SigVer (fips204.py): PASS= 180  FAIL= 0
ML-DSA (fips204.py) -- Total FAIL= 0
```

By default the output for SLH-DSA is a bit verbose, as it will take several minutes to run them all:

```
$ python3 fips205.py
SLH-DSA-SHA2-128s KeyGen/1 pass
(.. output truncated ..)
SLH-DSA-SHAKE-256f KeyGen/120 pass
SLH-DSA KeyGen (fips205.py): PASS= 120  FAIL= 0
(.. output truncated ..)
SLH-DSA-SHAKE-256s SigGen/624 pass
SLH-DSA SigGen (fips205.py): PASS= 624  FAIL= 0
(.. output truncated ..)
SLH-DSA-SHAKE-256s SigVer/504 pass
SLH-DSA SigVer (fips205.py): PASS= 504  FAIL= 0
SLH-DSA (fips205.py) -- Total FAIL= 0
```
_( This indicates success.)_

#   NIST Gen/Vals

** CONTINOUSLY EXPERIMENTAL **

Functional validation of crypto algorithms in the FIPS 140-3 scheme is based on NIST's Automated Cryptographic Validation Test System (ACVTS). This system contains crypto algorithm implementations that effectively serve as the "golden reference" for algorithm validation: They are used to generate randomized test cases in ACVTS.

The crypto implementations used by NIST's [ACVP-Server](https://github.com/usnistgov/ACVP-Server) are written in C# and run on Microsoft's .NET framework (version 6). Recently implementations of the new NIST PQC standards
Kyber ([Kyber.cs](https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/src/crypto/src/NIST.CVP.ACVTS.Libraries.Crypto/Kyber/Kyber.cs) for FIPS 203),
Dilithium ([Dilithium.cs](https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/src/crypto/src/NIST.CVP.ACVTS.Libraries.Crypto/Dilithium/Dilithium.cs) for [FIPS 204 ML-DSA](https://doi.org/10.6028/NIST.FIPS.204)), and
SPHINCS+ ([Slhdsa.cs](https://github.com/usnistgov/ACVP-Server/blob/master/gen-val/src/crypto/src/NIST.CVP.ACVTS.Libraries.Crypto/SLHDSA/Slhdsa.cs) for [FIPS 205 SLH-DSA](https://doi.org/10.6028/NIST.FIPS.205)) have been added to the repo. These may not be the best or the most elegant implementations, but many will want to ensure functional equivalence to this code for interoperability and certification purposes.

We provide Python interface to run the NIST Reference Kyber and Dilithium implementations on a Linux system ( [Pythonnet](http://pythonnet.github.io/) is available for Mac and Windows too, but I have not tested it. ) There is also code to run tests against the static JSON-format test vectors in the ACVP-Server repo.

Note that the NIST reference implementations absolutely should **not** be used "in production" since no attention has been paid to crucial factors such as resistance against (remote) timing attacks. This is simply not needed in test vector generation.


##  Step-by-step Running Instructions

This is very hacky: The following steps were executed on a fresh install of Ubuntu 24.04 LTS in July-September, 2024. If it doesn't work for you, too bad.

Install git, if needed, and clone this repo:
```
$ sudo apt install git
$ git clone https://github.com/mjosaarinen/py-acvp-pqc.git
$ cd py-acvp-pqc
```

### Install the .NET 6 SDK

Following [Microsoft's instructions for .NET on Ubuntu](https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu):
```console
$ sudo add-apt-repository ppa:dotnet/backports
(press [ENTER])
$ sudo apt install dotnet-sdk-8.0
```
Note that you need the SDK as you're compiling C# code. If you're using a more stripped-down distro than Ubuntu, you will encounter many more dependencies.

### Build the needed .dll files

Fetch the ACVP server sources (it's big!). We will put it right here under the py-acvp-pqc directory, but you can also have a ACVP-Server symlink.
```console
$ git clone https://github.com/usnistgov/ACVP-Server.git
```
Some preparatory steps for local installation:
```console
$ cd ACVP-Server
$ rm -f Directory.Build.prop Directory.Packages.props
$ ln -s ./_config/Directory.Build.props
$ ln -s ./_config/Directory.Packages.props
```

We can now build the relevant implementation libraries (which are .dll files). One way to do this is by running some tests that have them as dependencies:

```console
$ dotnet test gen-val/src/crypto/test/NIST.CVP.ACVTS.Libraries.Crypto.Kyber.Tests/NIST.CVP.ACVTS.Libraries.Crypto.Kyber.Tests.csproj
$ dotnet test gen-val/src/crypto/test/NIST.CVP.ACVTS.Libraries.Crypto.Dilithium.Tests/NIST.CVP.ACVTS.Libraries.Crypto.Dilithium.Tests.csproj
$ dotnet test gen-val/src/crypto/test/NIST.CVP.ACVTS.Libraries.Crypto.SLHDSA.Tests/NIST.CVP.ACVTS.Libraries.Crypto.SLHDSA.Tests.csproj
```

There is quite a lot of output, but we're done here.
```
$ cd ..
```

### Run our Python Tests

We're using [Pythonnet](http://pythonnet.github.io/) and you will probably have to install it. As an example, let's install venv, use a local environment:

```console
$ sudo apt install python3-venv
$ python3 -m venv .venv
$ source .venv/bin/activate
(.venv) $ pip3 install pythonnet
```

Note that you will have to "enter" the enviroment with `source .venv/bin/activate` to use pythonnet installed locally this way.

Anyway, assuming that all of the DLLs are in the right places, we should be abole to run our Kyber, Dilithium, and SPHINCS+ tests: Note however that many of the "external api" tests for the Gen/Vals wrapper are currently skipped.
```
(.venv) $ python3 genvals_mlkem.py
ML-KEM KeyGen (NIST Gen/Vals): PASS= 75  FAIL= 0
ML-KEM Encaps (NIST Gen/Vals): PASS= 75  FAIL= 0
ML-KEM Decaps (NIST Gen/Vals): PASS= 30  FAIL= 0
ML-KEM (NIST Gen/Vals) -- Total FAIL= 0
```

This is a success!

