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

def slhdsa_test_keygen(keygen_kat, slh_dsa, iut=''):
    keygen_pass = 0
    keygen_fail = 0

    for x in keygen_kat:
        #   run keygen
        (pk, sk)    = slh_dsa.slh_keygen_internal(
                                    sk_seed = bytes.fromhex(x['skSeed']),
                                    sk_prf  = bytes.fromhex(x['skPrf']),
                                    pk_seed = bytes.fromhex(x['pkSeed']),
                                    param   = x['parameterSet'])
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
        pre = False
        if 'preHash' in qtg and qtg['preHash'] == 'preHash':
                pre = True
        ifc = None
        if 'signatureInterface' in qtg:
            ifc = qtg['signatureInterface']
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
            if 'preHash' not in qt:
                qt['preHash'] = pre
            if 'context' not in qt:
                qt['context'] = ''
            qt['signatureInterface'] = ifc
            siggen_kat += [qt]
    return siggen_kat

#   Perform signature generation tests on siggen_func

def slhdsa_test_siggen(siggen_kat, slh_dsa, iut=''):

    siggen_pass = 0
    siggen_fail = 0
    siggen_skip = 0

    for x in siggen_kat:
        if 'additionalRandomness' in x:
            addrnd = bytes.fromhex(x['additionalRandomness'])
        else:
            addrnd = None

        #   generate signature
        sig = None
        if x['preHash']:
            sig = slh_dsa.hash_slh_sign(
                        m       = bytes.fromhex(x['message']),
                        ctx     = bytes.fromhex(x['context']),
                        ph      = x['hashAlg'],
                        sk      = bytes.fromhex(x['sk']),
                        addrnd  = addrnd,
                        param   = x['parameterSet'])
        elif x['signatureInterface'] == 'external':
            sig = slh_dsa.slh_sign(
                        m       = bytes.fromhex(x['message']),
                        ctx     = bytes.fromhex(x['context']),
                        sk      = bytes.fromhex(x['sk']),
                        addrnd  = addrnd,
                        param   = x['parameterSet'])
        elif x['signatureInterface'] == 'internal':
            sig = slh_dsa.slh_sign_internal(
                        m       = bytes.fromhex(x['message']),
                        sk      = bytes.fromhex(x['sk']),
                        addrnd  = addrnd,
                        param   = x['parameterSet'])

        #   compare
        tc  = x['parameterSet'] + ' SigGen/' + str(x['tcId'])
        if sig == None:
            siggen_skip += 1
            print(tc, 'skip')
        elif sig == bytes.fromhex(x['signature']):
            siggen_pass += 1
            print(tc, 'pass')
        else:
            siggen_fail += 1
            print(tc, 'fail')
            print(tc, 'sig ref=', x['signature'])
            print(tc, 'sig got=', sig.hex())

    print( f'SLH-DSA SigGen {iut}: PASS= {siggen_pass}  FAIL= {siggen_fail}')
    if siggen_skip > 0:
        print( f'SLH-DSA SigGen {iut}: SKIP= {siggen_skip}')
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
        pre = False
        if 'preHash' in qtg and qtg['preHash'] == 'preHash':
                pre = True
        ifc = None
        if 'signatureInterface' in qtg:
            ifc = qtg['signatureInterface']

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
            if 'preHash' not in qt:
                qt['preHash'] = pre
            qt['signatureInterface'] = ifc
            sigver_kat += [qt]
    return sigver_kat

#   Perform signature verification tests on sigver_func

def slhdsa_test_sigver(sigver_kat, slh_dsa, iut=''):
    sigver_pass = 0
    sigver_fail = 0
    sigver_skip = 0

    for x in sigver_kat:

        #   verify signature
        res = None
        if x['preHash']:
            res = slh_dsa.hash_slh_verify(
                                m   = bytes.fromhex(x['message']),
                                sig = bytes.fromhex(x['signature']),
                                ctx = bytes.fromhex(x['context']),
                                ph  = x['hashAlg'],
                                pk  = bytes.fromhex(x['pk']),
                                param = x['parameterSet'])
        elif x['signatureInterface'] == 'external':
            res = slh_dsa.slh_verify(
                                m   = bytes.fromhex(x['message']),
                                sig = bytes.fromhex(x['signature']),
                                ctx = bytes.fromhex(x['context']),
                                pk  = bytes.fromhex(x['pk']),
                                param = x['parameterSet'])
        elif x['signatureInterface'] == 'internal':
            res = slh_dsa.slh_verify_internal(
                                m   = bytes.fromhex(x['message']),
                                sig = bytes.fromhex(x['signature']),
                                pk  = bytes.fromhex(x['pk']),
                                param = x['parameterSet'])

        #   compare result
        tc  = x['parameterSet'] + ' SigVer/' + str(x['tcId'])
        if res == None:
            sigver_skip += 1
            print(tc, 'skip')
        elif res == x['testPassed']:
            sigver_pass += 1
            print(tc, 'pass')
        else:
            sigver_fail += 1
            print(tc, 'res ref=', x['testPassed'])
            print(tc, 'res got=', res)
            print(tc, x['reason'])
            exit(0)

    print(f'SLH-DSA SigVer {iut}: PASS= {sigver_pass}  FAIL= {sigver_fail}')
    if sigver_skip > 0:
        print(f'SLH-DSA SigVer {iut}: SKIP= {sigver_skip}')
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

def kat_filter(kat_in, param):
    kat_out = []
    for x in kat_in:
        if x['parameterSet'] == param:
            kat_out += [x]
    return kat_out

#   for quick testing with a single parameter set
"""
keygen_kat = kat_filter(keygen_kat, 'SLH-DSA-SHAKE-128f')
siggen_kat = kat_filter(siggen_kat, 'SLH-DSA-SHAKE-128f')
sigver_kat = kat_filter(sigver_kat, 'SLH-DSA-SHAKE-128f')
"""

def test_slhdsa(slh_dsa, iut=''):
    fail = 0
    fail += slhdsa_test_keygen(keygen_kat, slh_dsa, iut)
    fail += slhdsa_test_siggen(siggen_kat, slh_dsa, iut)
    fail += slhdsa_test_sigver(sigver_kat, slh_dsa, iut)
    print(f'SLH-DSA {iut} -- Total FAIL= {fail}')

#   if invoked directly, just dump test vectors in an even simpler format

if __name__ == '__main__':
    slhdsa_print_keygen(keygen_kat)
    slhdsa_print_siggen(siggen_kat)
    slhdsa_print_sigver(sigver_kat)
