#   test_mldsa.py
#   2024-07-02  Markku-Juhani O. Saarinen <mjos@iki.fi>
#   === ML-DSA / Dilithium KAT test with json files

import json
from nist_mldsa import nist_mldsa_keygen, nist_mldsa_sign, nist_mldsa_verify

#   === read json prompts and responses ===

json_path = 'ACVP-Server/gen-val/json-files/'

#   Key Generation KATs

with open(json_path + 'ML-DSA-keyGen-FIPS204/prompt.json') as f:
    keygen_req = json.load(f)
with open(json_path + 'ML-DSA-keyGen-FIPS204/expectedResults.json') as f:
    keygen_res = json.load(f)

keygen_kat = []
for qtg in keygen_req['testGroups']:
    alg = qtg['parameterSet']
    tgid = qtg['tgId']

    rtg = None
    for tg in keygen_res['testGroups']:
        if tg['tgId'] == tgid:
            rtg = tg['tests']
            break

    for qt in qtg['tests']:
        tcid = qt['tcId']
        for t in rtg:
            if t['tcId'] == tcid:
                qt.update(t)
        qt['parameterSet'] = alg
        keygen_kat += [qt]


#   Signature Generation KATs

with open(json_path + 'ML-DSA-sigGen-FIPS204/prompt.json') as f:
    siggen_req = json.load(f)
with open(json_path + 'ML-DSA-sigGen-FIPS204/expectedResults.json') as f:
    siggen_res = json.load(f)

siggen_kat = []
for qtg in siggen_req['testGroups']:
    alg = qtg['parameterSet']
    det = qtg['deterministic']
    tgid = qtg['tgId']

    rtg = None
    for tg in siggen_res['testGroups']:
        if tg['tgId'] == tgid:
            rtg = tg['tests']
            break

    for qt in qtg['tests']:
        tcid = qt['tcId']
        for t in rtg:
            if t['tcId'] == tcid:
                qt.update(t)
        qt['parameterSet'] = alg
        qt['deterministic'] = det
        siggen_kat += [qt]


#   Signature verification KATs

with open(json_path + 'ML-DSA-sigVer-FIPS204/prompt.json') as f:
    sigver_req = json.load(f)
with open(json_path + 'ML-DSA-sigVer-FIPS204/expectedResults.json') as f:
    sigver_res = json.load(f)
with open(json_path + 'ML-DSA-sigVer-FIPS204/internalProjection.json') as f:
    sigver_int = json.load(f)

sigver_kat = []
for qtg in sigver_req['testGroups']:
    alg = qtg['parameterSet']
    pk  = qtg['pk']
    tgid = qtg['tgId']

    rtg = None
    for tg in sigver_res['testGroups']:
        if tg['tgId'] == tgid:
            rtg = tg['tests']
            break

    itg = None
    for tg in sigver_int['testGroups']:
        if tg['tgId'] == tgid:
            itg = tg['tests']
            break

    for qt in qtg['tests']:
        tcid = qt['tcId']
        for t in rtg:
            if t['tcId'] == tcid:
                qt.update(t)
        #   message, signature in this file overrides prompts
        for t in itg:
            if t['tcId'] == tcid:
                qt.update(t)
        qt['parameterSet'] = alg
        qt['pk'] = pk
        sigver_kat += [qt]


#   === run the tests ===

#   key generation tests

keygen_pass = 0
keygen_fail = 0

for x in keygen_kat:
    #   run keygen
    (pk, sk)    = nist_mldsa_keygen(bytes.fromhex(x['seed']),
                                    x['parameterSet'])
    #   compare
    tc  = x['parameterSet'] + ' KeyGen/' + str(x['tcId'])
    if pk == bytes.fromhex(x['pk']) and sk == bytes.fromhex(x['sk']):
        keygen_pass += 1
    else:
        keygen_fail += 1
        print(tc, 'pk ref=', x['pk'])
        print(tc, 'pk got=', pk.hex())
        print(tc, 'sk ref=', x['sk'])
        print(tc, 'sk got=', sk.hex())

print(f'ML-DSA KeyGen: PASS= {keygen_pass}  FAIL= {keygen_fail}')

#   signature generation tests

siggen_pass = 0
siggen_fail = 0
siggen_skip = 0

for x in siggen_kat:
    #   generate signature
    sig = nist_mldsa_sign(  bytes.fromhex(x['sk']),
                            bytes.fromhex(x['message']),
                            x['deterministic'],
                            x['parameterSet'])

    #   compare
    tc  = x['parameterSet'] + ' SigGen/' + str(x['tcId'])
    if sig == bytes.fromhex(x['signature']):
        siggen_pass += 1
    elif not x['deterministic']:
        #   non-determistic signatures are.. non-determinstic
        siggen_skip += 1
    else:
        siggen_fail += 1
        print(tc, 'sig ref=', x['signature'])
        print(tc, 'sig got=', sig.hex())

print( 'ML-DSA SigGen:',
        f'PASS= {siggen_pass}  FAIL= {siggen_fail}  SKIP= {siggen_skip}')

#   verify tests

sigver_pass = 0
sigver_fail = 0

for x in sigver_kat:
    #   verify signature
    res = nist_mldsa_verify(bytes.fromhex(x['pk']),
                            bytes.fromhex(x['message']),
                            bytes.fromhex(x['signature']),
                            x['parameterSet'])

    #   compare result
    tc  = x['parameterSet'] + ' SigVer/' + str(x['tcId'])
    if res == x['testPassed']:
        sigver_pass += 1
    else:
        sigver_fail += 1
        print(tc, 'res ref=', x['testPassed'])
        print(tc, 'res got=', res)
        print(tc, x['reason'])

print(f'ML-DSA SigVer: PASS= {sigver_pass}  FAIL= {sigver_fail}')

