#   test_slhdsa.py
#   2024-08-19  Markku-Juhani O. Saarinen <mjos@iki.fi>
#   === SLH-DSA / SPHINCS+ KAT test with json files

import json

#   === read json prompts and responses ===

#   Load key generation KATs

def slhdsa_load_keygen(req_fn, res_fn):
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

def slhdsa_test_keygen(keygen_kat, keygen_func, iut=''):
    keygen_pass = 0
    keygen_fail = 0

    for x in keygen_kat:
        #   run keygen
        (pk, sk)    = keygen_func(  bytes.fromhex(x['skSeed']),
                                    bytes.fromhex(x['skPrf']),
                                    bytes.fromhex(x['pkSeed']),
                                    x['parameterSet'])
        #   compare
        tc  = x['parameterSet'] + ' KeyGen/' + str(x['tcId'])
        if pk == bytes.fromhex(x['pk']) and sk == bytes.fromhex(x['sk']):
            keygen_pass += 1
            print(tc, 'pass')
        else:
            keygen_fail += 1
            print(tc, 'pk ref=', x['pk'])
            print(tc, 'pk got=', pk.hex())
            print(tc, 'sk ref=', x['sk'])
            print(tc, 'sk got=', sk.hex())

    print(f'SLH-DSA KeyGen {iut}: PASS= {keygen_pass}  FAIL= {keygen_fail}')
    return keygen_fail

def slhdsa_print_keygen(keygen_kat, i=0):
    for x in keygen_kat:
        print(i, 'keygen', x['parameterSet'])
        print(i, 'skSeed', x['skSeed'])
        print(i, 'skPrf',  x['skPrf'])
        print(i, 'pkSeed', x['pkSeed'])
        print(i, 'pk', x['pk'])
        print(i, 'sk', x['sk'])
        i += 1
    return i

#   Load signature Generation KATs

def slhdsa_load_siggen(req_fn, res_fn):
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

def slhdsa_test_siggen(siggen_kat, siggen_func, iut=''):

    siggen_pass = 0
    siggen_fail = 0
    siggen_skip = 0

    for x in siggen_kat:
        if 'additionalRandomness' in x:
            addrnd = bytes.fromhex(x['additionalRandomness'])
        else:
            addrnd = None
        #   generate signature
        sig = siggen_func(  bytes.fromhex(x['message']),
                            bytes.fromhex(x['sk']),
                            addrnd,
                            x['parameterSet'])

        #   compare
        tc  = x['parameterSet'] + ' SigGen/' + str(x['tcId'])
        if sig == bytes.fromhex(x['signature']):
            siggen_pass += 1
            print(tc, 'pass')
        else:
            siggen_fail += 1
            print(tc, 'fail')
            print(tc, 'sig ref=', x['signature'])
            print(tc, 'sig got=', sig.hex())

    print( f'SLH-DSA SigGen {iut}:',
            f'PASS= {siggen_pass}  FAIL= {siggen_fail}  SKIP= {siggen_skip}')

    return siggen_fail

def slhdsa_print_siggen(siggen_kat, i=0):
    for x in siggen_kat:
        print(i, 'siggen', x['parameterSet'])
        print(i, 'sk', x['sk'])
        print(i, 'mp', x['message'])
        #print(i, 'rnd', x['rnd'])
        print(i, 'sig', x['signature'])
        i += 1
    return i

#   Load signature verification KATs

def slhdsa_load_sigver(req_fn, res_fn, int_fn):

    with open(req_fn) as f:
        sigver_req = json.load(f)
    with open(res_fn) as f:
        sigver_res = json.load(f)
    with open(int_fn) as f:
        sigver_int = json.load(f)

    sigver_kat = []
    for qtg in sigver_req['testGroups']:
        alg = qtg['parameterSet']
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
            pk   = qt['pk']
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

def slhdsa_test_sigver(sigver_kat, sigver_func, iut=''):

    sigver_pass = 0
    sigver_fail = 0

    for x in sigver_kat:
        #   verify signature
        res = sigver_func(  bytes.fromhex(x['message']),
                            bytes.fromhex(x['signature']),
                            bytes.fromhex(x['pk']),
                            x['parameterSet'])

        #   compare result
        tc  = x['parameterSet'] + ' SigVer/' + str(x['tcId'])
        if res == x['testPassed']:
            sigver_pass += 1
            print(tc, 'pass')
        else:
            sigver_fail += 1
            print(tc, 'res ref=', x['testPassed'])
            print(tc, 'res got=', res)
            print(tc, x['reason'])

    print(f'SLH-DSA SigVer {iut}: PASS= {sigver_pass}  FAIL= {sigver_fail}')
    return sigver_fail

def slhdsa_print_sigver(sigver_kat, i=0):
    for x in sigver_kat:
        print(i, 'sigver', x['parameterSet'])
        print(i, 'pk', x['pk'])
        print(i, 'mp', x['message'])
        print(i, 'sig', x['signature'])
        print(i, 'res', int(x['testPassed']))
        i += 1
    return i

#   === run the tests ===

#   load all KATs
#json_path = 'ACVP-Server/gen-val/json-files/'
json_path = 'json-copy/'

keygen_kat = slhdsa_load_keygen(
                json_path + 'SLH-DSA-keyGen-FIPS205/prompt.json',
                json_path + 'SLH-DSA-keyGen-FIPS205/expectedResults.json')

siggen_kat = slhdsa_load_siggen(
                json_path + 'SLH-DSA-sigGen-FIPS205/prompt.json',
                json_path + 'SLH-DSA-sigGen-FIPS205/expectedResults.json')

sigver_kat = slhdsa_load_sigver(
                json_path + 'SLH-DSA-sigVer-FIPS205/prompt.json',
                json_path + 'SLH-DSA-sigVer-FIPS205/expectedResults.json',
                json_path + 'SLH-DSA-sigVer-FIPS205/internalProjection.json')

def test_slhdsa(keygen_func, siggen_func, sigver_func, iut=''):
    fail = 0
    fail += slhdsa_test_keygen(keygen_kat, keygen_func, iut)
    fail += slhdsa_test_siggen(siggen_kat, siggen_func, iut)
    fail += slhdsa_test_sigver(sigver_kat, sigver_func, iut)
    print(f'SLH-DSA {iut} -- Total FAIL= {fail}')

#   if invoked directly, just dump test vectors in an even simpler format

if __name__ == '__main__':
    slhdsa_print_keygen(keygen_kat)
    slhdsa_print_siggen(siggen_kat)
    slhdsa_print_sigver(sigver_kat)
