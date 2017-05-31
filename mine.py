import hashlib
import random
from Crypto.PublicKey import RSA
import rsa
from base64 import b64encode, b64decode
import urllib
import urllib.parse, urllib.request
import json
import requests
import datetime
import binascii
import time

def bin2hex(binStr):
    return binascii.hexlify(binStr)

def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)

keysize = 2048

bank_url = 'http://localhost:8228'

global_target = 4e71

def updateGlobalTarget():
    global global_target

    response = requests.get(bank_url+'/global_target')
    print(response.text)
    print()
    global_target = float(response.text)

updateGlobalTarget()
last_checked_minute = datetime.datetime.now().minute

# url_opener = urllib.request.URLopener(key_file='~/Coding/wooden_nickle/server/python/server.pem', cert_file='~/Coding/wooden_nickle/server/python/server.crt')

(mining_public_key, mining_private_key) = rsa.newkeys(keysize)
mining_public_key_hex = bin2hex(mining_public_key.exportKey('DER')).decode('utf-8')
mining_private_key_hex = bin2hex(mining_private_key.exportKey('DER')).decode('utf-8')

# print(mining_public_key)
# print(bin2hex(mining_public_key.exportKey('DER')))
# print(RSA.importKey(mining_public_key.exportKey('DER')))

# mining_public_key_hash = hashlib.sha256(mining_public_key.exportKey()).hexdigest()

# print(private.exportKey().decode('utf-8'))

print('starting to mine...')

last_won_time = datetime.datetime.now()

while True:
    mined_nonce = str(random.randrange(1e16)).zfill(16)
    mined_coin_raw = mining_public_key_hex+'_'+mined_nonce
    mined_coin_hash = hashlib.sha256(mined_coin_raw.encode('utf-8')).hexdigest()
    mined_coin_hash_int = int(mined_coin_hash, 16)

    if mined_coin_hash_int < global_target:
        # raw_coin_str = raw_coin.decode('utf-8')

        # For kicks, display the shiny new coin!
        print(mined_coin_hash)

        # Sign the raw coin so that Banks can verify that I own the private key
        print('signing...')
        signature = b64encode(rsa.sign(mined_coin_raw.encode('utf-8'), mining_private_key, "SHA-256")).decode('utf-8')

        # Submit the new coin

        print('contacting server...')

        response = requests.post(bank_url+'/submit', json={
            'mined_coin_raw': mined_coin_raw,
            'signature': signature
        })
        print(response.text)

        # Check that the submission was successful
        if response.text[:9] != 'Congrats!':
            print('syncing with global target...')
            updateGlobalTarget()
            last_checked_minute = now_minute
            continue

        # Create the cheque
        mined_cheque_raw = '1_'+mined_coin_hash
        mined_cheque_hash = hashlib.sha256(mined_coin_raw.encode('utf-8')).hexdigest()

        # Display the time taken to min that coin
        now_time = datetime.datetime.now()

        d1_ts = time.mktime(last_won_time.timetuple())
        d2_ts = time.mktime(now_time.timetuple())

        print('TIME: {} seconds'.format(d2_ts-d1_ts))

        last_won_time = now_time

        # Save the cheque
        with open("private_coin_storage.txt", "a+") as myfile:
            string  = '1' + '\t'
            string += mining_public_key_hex + '\t'
            string += mined_nonce + '\t'
            string += mining_private_key_hex + '\n'
            myfile.write(string)

        # Regenerate keys
        (mining_public_key, mining_private_key) = rsa.newkeys(keysize)
        mining_public_key_hex = bin2hex(mining_public_key.exportKey('DER')).decode('utf-8')
        mining_private_key_hex = bin2hex(mining_private_key.exportKey('DER')).decode('utf-8')


        print('\n'*2, end='')

    now_minute = datetime.datetime.now().minute

    if now_minute % 1 == 0 and now_minute != last_checked_minute:
        print('syncing with global target...')
        updateGlobalTarget()
        last_checked_minute = now_minute
