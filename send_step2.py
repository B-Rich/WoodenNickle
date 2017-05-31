import socket
import hashlib
import random
import rsa
from base64 import b64encode, b64decode
import urllib
import urllib.parse, urllib.request
import json
import requests
import datetime
from Crypto.PublicKey import RSA
import binascii
import time
import sys

def pause():
    try:
        input('Press enter to continue...')
    except SyntaxError:
        pass

def bin2hex(binStr):
    return binascii.hexlify(binStr)

def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)

def send(txt):
    return s.send(txt.encode('utf-8'))
def recv():
    return s.recv(listen_port).decode('utf-8')

amnt_to_send = 1 # TODO: This should be chosen by the user!

# FIXME: This is where I would split/combine coins if needed

cheque_amnt, coin_public_key_hex, coin_nonce, coin_private_key_hex = (None, None, None, None,)
with open('private_coin_storage.txt', 'r') as f:
    for line in f:
        cheque_amnt, coin_public_key_hex, coin_nonce, coin_private_key_hex = f.readline().rstrip().split('\t')

        if cheque_amnt == amnt_to_send:
            break # We'll use this cheque

# In case we didn't find a coin...
if cheque_amnt is None:
    print('Coin not found!')
    sys.exit(1)

cheque_str = '_'.join((cheque_amnt, coin_public_key_hex, coin_nonce,))

coin_private_key = RSA.importKey(hex2bin(coin_private_key_hex))

bank_url = 'http://localhost:8228'

s = socket.socket()
host = '104.199.121.149'
port = 1247
s.connect((host, port))

print('connected')

listen_port = 1024

# Make sure that I'm connected
assert recv() == 'awk.init'
print('awk.init')

# Make the public key sharable
public_key_b64 = b64encode(hex2bin(coin_public_key_hex)).decode('utf-8')
print('Share this Base64 public key with the payee: ')
print(public_key_b64)

# Announce who I am to the server
print('Connecting to server...')

# (Sign the timestamp to verify I own the key)
timestamp = str(time.time())
signature = b64encode(rsa.sign(timestamp.encode('utf-8'), coin_private_key, 'SHA-256')).decode('utf-8')

# (Send public key along with signed timestamp as proof)
send(public_key_b64)
assert recv() == 'recv.public_key_b64'

send(timestamp)
assert recv() == 'recv.timestamp'

send(signature)
assert recv() == 'recv.signature'

assert recv() == 'awk.sig'

print('Connected')

send('protocol.payer.download_cheque')
assert recv() == 'awk.protocol.payer.download_cheque'

send('awk.ready')

encrypted_cheque_str = recv()

if encrypted_cheque_str == 'None':
    print('The payer has not send his/her request yet. Please try again in a few minutes.')
    print('Payment cancelled.')
    print()
    print('Next time, run this command with the -s flag.')
    sys.exit(1)

# Decrypt the cheque
payee_cheque_str = rsa.decrypt(b64decode(encrypted_cheque_str), coin_private_key).decode('utf-8')

# Sign the cheque
signature_b64 = b64encode(rsa.sign(payee_cheque_str.encode('utf-8'), coin_private_key, 'SHA-256')).decode('utf-8')

# Send it to the Bank
response = requests.post(bank_url+'/replace', json={
    'old_cheque_raw': cheque_str,
    'new_cheque': payee_cheque_str,
    'signature_b64': signature_b64
})

if response.text == 'True':
    print('Payment successful.')
else:
    print('Error: ')
    print(response.text)
