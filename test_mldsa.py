#   test_mldsa.py
#   2024-07-02  Markku-Juhani O. Saarinen <mjos@iki.fi>
#   === ML-DSA / Dilithium KAT test with json files

import json

#   === read json prompts and responses ===

#   Load key generation KATs

def mldsa_load_keygen(req_fn, res_fn):
    with open(req_fn) as f:
        keygen_req = json.load(f)
    with open(res_fn) as f:
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
    return keygen_kat

#   Perform key generation tests on keygen_func

def mldsa_test_keygen(keygen_kat, keygen_func, iut=''):
    keygen_pass = 0
    keygen_fail = 0

    for x in keygen_kat:
        #   run keygen
        (pk, sk)    = keygen_func(  bytes.fromhex(x['seed']),
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

    print(f'ML-DSA KeyGen {iut}: PASS= {keygen_pass}  FAIL= {keygen_fail}')
    return keygen_fail

#   Load signature Generation KATs

def mldsa_load_siggen(req_fn, res_fn):
    with open(req_fn) as f:
        siggen_req = json.load(f)
    with open(res_fn) as f:
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
    return siggen_kat

#   Perform signature generation tests on siggen_func

def mldsa_test_siggen(siggen_kat, siggen_func, iut=''):

    siggen_pass = 0
    siggen_fail = 0
    siggen_skip = 0

    for x in siggen_kat:
        #   generate signature
        if x['deterministic']:
            rnd = b'\0'*32          #   deterministic signatures have rnd = 00
        else:
            rnd = bytes(range(32))  #   we can't really test these cases

        sig = siggen_func(  bytes.fromhex(x['sk']),
                            bytes.fromhex(x['message']),
                            rnd,
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

    print( f'ML-DSA SigGen {iut}:',
            f'PASS= {siggen_pass}  FAIL= {siggen_fail}  SKIP= {siggen_skip}')

    return siggen_fail

#   Load signature verification KATs

def mldsa_load_sigver(req_fn, res_fn, int_fn):

    with open(req_fn) as f:
        sigver_req = json.load(f)
    with open(res_fn) as f:
        sigver_res = json.load(f)
    with open(int_fn) as f:
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
    return sigver_kat

#   Perform signature verification tests on sigver_func

def mldsa_test_sigver(sigver_kat, sigver_func, iut=''):

    sigver_pass = 0
    sigver_fail = 0

    for x in sigver_kat:
        #   verify signature
        res = sigver_func(  bytes.fromhex(x['pk']),
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

    print(f'ML-DSA SigVer {iut}: PASS= {sigver_pass}  FAIL= {sigver_fail}')
    return sigver_fail

#   === run the tests ===

#   load all KATs
#json_path = 'ACVP-Server/gen-val/json-files/'
json_path = 'json-copy/'

keygen_kat = mldsa_load_keygen(
                json_path + 'ML-DSA-keyGen-FIPS204/prompt.json',
                json_path + 'ML-DSA-keyGen-FIPS204/expectedResults.json')

siggen_kat = mldsa_load_siggen(
                json_path + 'ML-DSA-sigGen-FIPS204/prompt.json',
                json_path + 'ML-DSA-sigGen-FIPS204/expectedResults.json')

sigver_kat = mldsa_load_sigver(
                json_path + 'ML-DSA-sigVer-FIPS204/prompt.json',
                json_path + 'ML-DSA-sigVer-FIPS204/expectedResults.json',
                json_path + 'ML-DSA-sigVer-FIPS204/internalProjection.json')


def test_mldsa(keygen_func, siggen_func, sigver_func, iut=''):
    fail = 0
    fail += mldsa_test_keygen(keygen_kat, keygen_func, iut)
    fail += mldsa_test_siggen(siggen_kat, siggen_func, iut)
    fail += mldsa_test_sigver(sigver_kat, sigver_func, iut)
    print(f'ML-DSA {iut} -- Total FAIL= {fail}')

if __name__ == '__main__':
    print('no unit tests here: provide cryptographic functions to test.')
