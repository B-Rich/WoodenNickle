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
print('\033[94m')
print(public_key_b64)
print('\033[0m')

# Announce who I am to the server
print('Connecting to server...')

coin_private_key = RSA.importKey(hex2bin(coin_private_key_hex))

# (Sign the timestamp to verify I own the key)
timestamp = str(int(time.time()))
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

# Tell the server that we want to upload our cheque for the payee
send('protocol.payer.upload_cheque')
assert recv() == 'awk.protocol.payer.upload_cheque'

payee_public_key_b64 = input('What is the recepient\'s Base64 public key? ')

# Send the payee's base64 encoded public key to the server
send(payee_public_key_b64)
assert recv() == 'recv.payee_public_key_b64'

# Decode the base64 key
payee_public_key = RSA.importKey(b64decode(payee_public_key_b64))

# Encrypt the raw cheque with the payee's public key
# (They already know our public key)
encrypted_cheque_str = b64encode(rsa.encrypt((cheque_amnt + '_' + coin_nonce).encode('utf-8'), payee_public_key)).decode('utf-8')

send(encrypted_cheque_str)
assert recv() == 'recv.encrypted_cheque_str'

print('Cheque proof sent!')

print('Once the payee has send his/her request, run step 2.')
