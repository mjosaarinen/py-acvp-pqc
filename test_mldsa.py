#   test_mldsa.pyq
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

def mldsa_test_keygen(keygen_kat, ml_dsa, iut=''):
    keygen_pass = 0
    keygen_fail = 0

    for x in keygen_kat:
        #   run keygen
        (pk, sk)    = ml_dsa.keygen_internal(bytes.fromhex(x['seed']),
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

def mldsa_print_keygen(keygen_kat, i=0):
    for x in keygen_kat:
        print(i, 'keygen', x['parameterSet'])
        print(i, 'xi', x['seed'])
        print(i, 'pk', x['pk'])
        print(i, 'sk', x['sk'])
        i += 1
    return i

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
        pre = False
        if 'preHash' in qtg and qtg['preHash'] == 'preHash':
                pre = True
        ifc = None
        if 'signatureInterface' in qtg:
            ifc = qtg['signatureInterface']
        if 'externalMu' in qtg:
            emu = qtg['externalMu']
        else:
            emu = False
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
            if det:
                qt['rnd'] = '00'*32 #   deterministic signatures: rnd = 00
            if 'preHash' not in qt:
                qt['preHash'] = pre
            if 'context' not in qt:
                qt['context'] = ''
            qt['signatureInterface'] = ifc
            qt['externalMu'] = emu
            siggen_kat += [qt]
    return siggen_kat


#   Perform signature generation tests with the target

def mldsa_test_siggen(siggen_kat, ml_dsa, iut=''):
    siggen_pass = 0
    siggen_fail = 0
    siggen_skip = 0

    for x in siggen_kat:
        #   generate signature
        sig = None

        if x['preHash']:
            sig = ml_dsa.hash_ml_dsa_sign(
                                sk  = bytes.fromhex(x['sk']),
                                m   = bytes.fromhex(x['message']),
                                ctx = bytes.fromhex(x['context']),
                                ph  = x['hashAlg'],
                                rnd = bytes.fromhex(x['rnd']),
                                param = x['parameterSet'])
        elif x['externalMu']:
            sig = ml_dsa.sign_internal(
                                sk  = bytes.fromhex(x['sk']),
                                mp  = None,
                                rnd = bytes.fromhex(x['rnd']),
                                param = x['parameterSet'],
                                mu  = bytes.fromhex(x['mu']))
        elif x['signatureInterface'] == 'external':
            sig = ml_dsa.sign(  sk  = bytes.fromhex(x['sk']),
                                m   = bytes.fromhex(x['message']),
                                ctx = bytes.fromhex(x['context']),
                                rnd = bytes.fromhex(x['rnd']),
                                param = x['parameterSet'])
        elif x['signatureInterface'] == 'internal':
            sig = ml_dsa.sign_internal(
                                sk  = bytes.fromhex(x['sk']),
                                mp  = bytes.fromhex(x['message']),
                                rnd = bytes.fromhex(x['rnd']),
                                param = x['parameterSet'],
                                mu  = None)

        #   compare
        tc  = x['parameterSet'] + ' SigGen/' + str(x['tcId'])
        if sig == None:
            siggen_skip += 1
            print(tc, 'skip')
        elif sig == bytes.fromhex(x['signature']):
            siggen_pass += 1
        else:
            siggen_fail += 1
            print(tc, 'sig ref=', x['signature'])
            print(tc, 'sig got=', sig.hex())

    print( f'ML-DSA SigGen {iut}: PASS= {siggen_pass}  FAIL= {siggen_fail}')
    if siggen_skip > 0:
        print( f'ML-DSA SigGen {iut}: SKIP= {siggen_skip}')

    return siggen_fail

def mldsa_print_siggen(siggen_kat, i=0):
    for x in siggen_kat:
        print(x)
        print(i, 'siggen', x['parameterSet'])
        print(i, 'prehash', x['preHash'])
        if x['preHash']:
            print(i, 'hash', x['hashAlg'])
        print(i, 'sk', x['sk'])
        if 'message' in x:
            print(i, 'message', x['message'])
        else:
            print(i, 'mu', x['mu'])
        print(i, 'rnd', x['rnd'])
        print(i, 'context', x['context'])
        print(i, 'sig', x['signature'])
        i += 1
    return i

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
        pre = False
        if 'preHash' in qtg and qtg['preHash'] == 'preHash':
                pre = True
        tgid = qtg['tgId']
        ifc = None
        if 'signatureInterface' in qtg:
            ifc = qtg['signatureInterface']
        if 'externalMu' in qtg:
            emu = qtg['externalMu']
        else:
            emu = False

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
            if 'preHash' not in qt:
                qt['preHash'] = pre
            if 'context' not in qt:
                qt['context'] = ''
            qt['signatureInterface'] = ifc
            qt['externalMu'] = emu
            sigver_kat += [qt]
    return sigver_kat

#   Perform signature verification tests on the target

def mldsa_test_sigver(sigver_kat, ml_dsa, iut=''):

    sigver_pass = 0
    sigver_fail = 0
    sigver_skip = 0

    for x in sigver_kat:
        #   verify signature
        res = None

        if x['preHash']:
            res = ml_dsa.hash_ml_dsa_verify(
                                pk  = bytes.fromhex(x['pk']),
                                m   = bytes.fromhex(x['message']),
                                sig = bytes.fromhex(x['signature']),
                                ctx = bytes.fromhex(x['context']),
                                ph  = x['hashAlg'],
                                param = x['parameterSet'])
        elif x['externalMu']:
            res = ml_dsa.verify_internal(
                                pk  = bytes.fromhex(x['pk']),
                                mp  = None,
                                sig = bytes.fromhex(x['signature']),
                                param = x['parameterSet'],
                                mu  = bytes.fromhex(x['mu']))
        elif x['signatureInterface'] == 'external':
            res = ml_dsa.verify(
                                pk  = bytes.fromhex(x['pk']),
                                m   = bytes.fromhex(x['message']),
                                sig = bytes.fromhex(x['signature']),
                                ctx = bytes.fromhex(x['context']),
                                param = x['parameterSet'])
        elif x['signatureInterface'] == 'internal':
            res = ml_dsa.verify_internal(
                                pk  = bytes.fromhex(x['pk']),
                                mp  = bytes.fromhex(x['message']),
                                sig = bytes.fromhex(x['signature']),
                                param = x['parameterSet'])

        #   compare result
        tc  = x['parameterSet'] + ' SigVer/' + str(x['tcId'])
        if res == None:
            sigver_skip += 1
            print(tc, 'skip')
        elif res == x['testPassed']:
            sigver_pass += 1
        else:
            sigver_fail += 1
            print(tc, 'res ref=', x['testPassed'])
            print(tc, 'res got=', res)
            print(tc, x['reason'])

    print(f'ML-DSA SigVer {iut}: PASS= {sigver_pass}  FAIL= {sigver_fail}')
    if sigver_skip > 0:
        print(f'ML-DSA SigVer {iut}: SKIP= {sigver_skip}')
    return sigver_fail

def mldsa_print_sigver(sigver_kat, i=0):
    for x in sigver_kat:
        print(i, 'sigver', x['parameterSet'])
        print(i, 'pk', x['pk'])
        if 'message' in x:
            print(i, 'mp', x['message'])
        if 'mu' in x:
            print(i, 'mu', x['mu'])
        print(i, 'sig', x['signature'])
        print(i, 'res', int(x['testPassed']))
        i += 1
    return i

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

def test_mldsa(ml_dsa, iut=''):
    fail = 0
    fail += mldsa_test_keygen(keygen_kat, ml_dsa, iut)
    fail += mldsa_test_siggen(siggen_kat, ml_dsa, iut)
    fail += mldsa_test_sigver(sigver_kat, ml_dsa, iut)
    print(f'ML-DSA {iut} -- Total FAIL= {fail}')

#   if invoked directly, just dump test vectors in an even simpler format

if __name__ == '__main__':
    mldsa_print_keygen(keygen_kat)
    mldsa_print_siggen(siggen_kat)
    mldsa_print_sigver(sigver_kat)

