#   test_mlkem.py
#   2024-04-21  Markku-Juhani O. Saarinen <mjos@iki.fi>
#   === ML-KEM / Kyber KAT test with json files

import json

#   === read json prompts and responses ===

#   KeyGen KATs

def mlkem_load_keygen(req_fn, res_fn):
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

#   Perfrom key generation tests on keygen_func

def mlkem_test_keygen(keygen_kat, keygen_func, iut=''):
    keygen_pass = 0
    keygen_fail = 0

    for x in keygen_kat:
        #   run keygen
        (ek, dk)    = keygen_func(  bytes.fromhex(x['d']),
                                    bytes.fromhex(x['z']),
                                    x['parameterSet'])

        #   compare
        tc  = x['parameterSet'] + ' KeyGen/' + str(x['tcId'])
        if ek == bytes.fromhex(x['ek']) and dk == bytes.fromhex(x['dk']):
            keygen_pass += 1
            #print(tc, 'ok')
        else:
            keygen_fail += 1
            print(tc, 'ek ref=', x['ek'])
            print(tc, 'ek got=', ek.hex())
            print(tc, 'dk ref=', x['dk'])
            print(tc, 'dk got=', dk.hex())

    print(f'ML-KEM KeyGen {iut}: PASS= {keygen_pass}  FAIL= {keygen_fail}')
    return keygen_fail

def mlkem_print_keygen(keygen_kat, i=0):
    for x in keygen_kat:
        print(i, 'keygen', x['parameterSet'])
        print(i, 'd', x['d'])
        print(i, 'z', x['z'])
        print(i, 'ek', x['ek'])
        print(i, 'dk', x['dk'])
        i += 1
    return i

#   Load encaps and decaps KATs

def mlkem_load_encdec(req_fn, res_fn):
    with open(req_fn) as f:
        encdec_req = json.load(f)
    with open(res_fn) as f:
        encdec_res = json.load(f)

    encaps_kat = []
    decaps_kat = []
    for qtg in encdec_req['testGroups']:
        alg = qtg['parameterSet']
        func = qtg['function']
        tgid = qtg['tgId']

        rtg = None
        for tg in encdec_res['testGroups']:
            if tg['tgId'] == tgid:
                rtg = tg['tests']
                break

        for qt in qtg['tests']:
            tcid = qt['tcId']
            for t in rtg:
                if t['tcId'] == tcid:
                    qt.update(t)
            qt['parameterSet'] = alg
            if func == 'encapsulation':
                encaps_kat += [qt]
            elif func == 'decapsulation':
                qt['dk'] = qtg['dk']
                decaps_kat += [qt]
            else:
                print('ERROR: Unkonwn function:', func)

    return (encaps_kat, decaps_kat)

#   Perform encapsulation tests on encaps_func

def mlkem_test_encaps(encaps_kat, encaps_func, iut=''):
    encaps_pass = 0
    encaps_fail = 0
    for x in encaps_kat:

        #   run encaps
        (k, c) = encaps_func(bytes.fromhex  (x['ek']),
                                            bytes.fromhex(x['m']),
                                            x['parameterSet'])

        #   compare
        tc  = x['parameterSet'] + ' Encaps/' + str(x['tcId'])
        if k == bytes.fromhex(x['k']) and c == bytes.fromhex(x['c']):
            encaps_pass += 1
            #print(tc, 'ok')
        else:
            encaps_fail += 1
            print(tc, 'k ref=', x['k'])
            print(tc, 'k got=', k.hex())
            print(tc, 'c ref=', x['c'])
            print(tc, 'c got=', c.hex())

    print(f'ML-KEM Encaps {iut}: PASS= {encaps_pass}  FAIL= {encaps_fail}')
    return encaps_fail

def mlkem_print_encaps(encaps_kat, i=0):
    for x in encaps_kat:
        print(i, 'encaps', x['parameterSet'])
        print(i, 'ek', x['ek'])
        print(i, 'm', x['m'])
        print(i, 'K', x['k'])
        print(i, 'c', x['c'])
        i += 1
    return i

#   Perform decapsulation tests on decaps_func

def mlkem_test_decaps(decaps_kat, decaps_func, iut=''):
    decaps_pass = 0
    decaps_fail = 0
    for x in decaps_kat:

        #   run decaps
        k   = decaps_func(  bytes.fromhex(x['dk']),
                             bytes.fromhex(x['c']),
                             x['parameterSet'])

        #   compare
        tc  = x['parameterSet'] + ' Decaps/' + str(x['tcId'])
        if k == bytes.fromhex(x['k']):
            decaps_pass += 1
            #print(tc, 'ok')
        else:
            decaps_fail += 1
            print(tc, 'k ref=', x['k'])
            print(tc, 'k got=', k.hex())

    print(f'ML-KEM Decaps {iut}: PASS= {decaps_pass}  FAIL= {decaps_fail}')
    return decaps_fail

def mlkem_print_decaps(decaps_kat, i=0):
    for x in decaps_kat:
        print(i, 'decaps', x['parameterSet'])
        print(i, 'dk', x['dk'])
        print(i, 'c', x['c'])
        print(i, 'K', x['k'])
        i += 1
    return i

#   === run the tests ===

#   load all KATs
#json_path = 'ACVP-Server/gen-val/json-files/'
json_path = 'json-copy/'

keygen_kat = mlkem_load_keygen(
                json_path + 'ML-KEM-keyGen-FIPS203/prompt.json',
                json_path + 'ML-KEM-keyGen-FIPS203/expectedResults.json')

(encaps_kat, decaps_kat) = mlkem_load_encdec(
                json_path + 'ML-KEM-encapDecap-FIPS203/prompt.json',
                json_path + 'ML-KEM-encapDecap-FIPS203/expectedResults.json')

def test_mlkem(keygen_func, encaps_func, decaps_func, iut=''):
    fail = 0
    fail += mlkem_test_keygen(keygen_kat, keygen_func, iut)
    fail += mlkem_test_encaps(encaps_kat, encaps_func, iut)
    fail += mlkem_test_decaps(decaps_kat, decaps_func, iut)
    print(f'ML-KEM {iut} -- Total FAIL= {fail}')

#   if invoked directly, just dump test vectors in an even simpler format

if __name__ == '__main__':
    mlkem_print_keygen(keygen_kat)
    mlkem_print_encaps(encaps_kat)
    mlkem_print_decaps(decaps_kat)

