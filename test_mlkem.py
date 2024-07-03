#   test_mlkem.py
#   2024-04-21  Markku-Juhani O. Saarinen <mjos@iki.fi>
#   === ML-KEM / Kyber KAT test with json files

import json
from nist_mlkem import nist_mlkem_keygen, nist_mlkem_encaps, nist_mlkem_decaps

#   === read json prompts and responses ===

json_path = 'ACVP-Server/gen-val/json-files/'

#   KeyGen KATs

with open(json_path + 'ML-KEM-keyGen-FIPS203/prompt.json') as f:
    keygen_req = json.load(f)
with open(json_path + 'ML-KEM-keyGen-FIPS203/expectedResults.json') as f:
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


#   Encaps and Decaps KATs

with open(json_path + 'ML-KEM-encapDecap-FIPS203/prompt.json') as f:
    encdec_req = json.load(f)
with open(json_path + 'ML-KEM-encapDecap-FIPS203/expectedResults.json') as f:
    encdec_res = json.load(f)

encap_kat = []
decap_kat = []
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
            encap_kat += [qt]
        elif func == 'decapsulation':
            qt['dk'] = qtg['dk']
            decap_kat += [qt]
        else:
            print('ERROR: Unkonwn function:', func)


#   === run the tests ===

#   key generation tests

keygen_pass = 0
keygen_fail = 0

for x in keygen_kat:
    #   run keygen
    (ek, dk)    = nist_mlkem_keygen(bytes.fromhex(x['z']),
                                    bytes.fromhex(x['d']),
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

print(f'ML-KEM KeyGen: PASS= {keygen_pass}  FAIL= {keygen_fail}')


#   Encapsulation tests

encap_pass  = 0
encap_fail  = 0
for x in encap_kat:

    #   run encaps
    (k, c) = nist_mlkem_encaps( bytes.fromhex(x['ek']),
                                bytes.fromhex(x['m']),
                                x['parameterSet'])

    #   compare
    tc  = x['parameterSet'] + ' Encaps/' + str(x['tcId'])
    if k == bytes.fromhex(x['k']) and c == bytes.fromhex(x['c']):
        encap_pass += 1
        #print(tc, 'ok')
    else:
        encap_fail += 1
        print(tc, 'k ref=', x['k'])
        print(tc, 'k got=', k.hex())
        print(tc, 'c ref=', x['c'])
        print(tc, 'c got=', c.hex())

print(f'ML-KEM Encaps: PASS= {encap_pass}  FAIL= {encap_fail}')


#   Decapsulation tests

decap_pass  = 0
decap_fail  = 0
for x in decap_kat:

    #   run decaps
    k   = nist_mlkem_decaps(bytes.fromhex(x['c']),
                            bytes.fromhex(x['dk']),
                            x['parameterSet'])

    #   compare
    tc  = x['parameterSet'] + ' Decaps/' + str(x['tcId'])
    if k == bytes.fromhex(x['k']):
        decap_pass += 1
        #print(tc, 'ok')
    else:
        decap_fail += 1
        print(tc, 'k ref=', x['k'])
        print(tc, 'k got=', k.hex())

print(f'ML-KEM Decaps: PASS= {decap_pass}  FAIL= {decap_fail}')

