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

requested_amnt = 1 # TODO: This should be chosen by the user!

bank_url = 'http://104.199.121.149:8228'

# Generate keys
keysize = 2048
(public_key, private_key) = rsa.newkeys(keysize)

public_key_b64 = b64encode(public_key.exportKey('DER')).decode('utf-8')
public_key_hex = bin2hex(public_key.exportKey('DER')).decode('utf-8')

private_key_hex = bin2hex(private_key.exportKey('DER')).decode('utf-8')

print('Share this Base64 encoded public key with the payer: ')
print('\033[94m')
print(public_key_b64)
print('\033[0m')

pause()

s = socket.socket()
host = '104.199.121.149'
port = 1247
s.connect((host, port))

print('connected')

listen_port = 1024

# Make sure that I'm connected
assert recv() == 'awk.init'
print('awk.init')

# Announce who I am to the server
print('Connecting to server...')

# (Sign the timestamp to verify I own the key)
timestamp = str(time.time())
signature = b64encode(rsa.sign(timestamp.encode('utf-8'), private_key, 'SHA-256')).decode('utf-8')

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
send('protocol.payee')
assert recv() == 'awk.protocol.payee'

send('awk.ready')

payer_public_key_b64 = input('What is the payer\'s Base64 public key? ')
payer_public_key_hex = bin2hex(b64decode(payer_public_key_b64)).decode('utf-8')

payer_coin_str_encrypted = recv()

if payer_coin_str_encrypted == 'None':
    print('The payer\'s coin has not been uploaded yet. Please wait a few minutes and try again when it is.')
    print('Payment cancelled.')
    sys.exit(1)
else:
    send('recv.payer_coin_str')

payer_coin_str = rsa.decrypt(b64decode(payer_coin_str_encrypted), private_key).decode('utf-8')

payer_amnt_str, payer_coin_nonce = payer_coin_str.split('_')
payer_amnt = float(payer_amnt_str)

# Verify the amount
if payer_amnt != requested_amnt:
    send('False')
    print('The payer sent {}. You requested {}.'.format(payer_amnt, requested_amnt))
    print('Payment cancelled.')
    sys.exit(1)

# # Verify that the payer owns the cheque
# if payer_public_key_hex != payer_coin_public_key_hex:
#     send('False')
#     print('The payer\'s public key does not match that of the coin they claim to own.')
#     print('Payment cancelled.')
#     sys.exit(1)

# Check that the cheque is in enough Banks
payer_coin_raw = payer_public_key_hex + '_' + payer_coin_nonce
payer_coin_hash = hashlib.sha256(payer_coin_raw.encode('utf-8')).hexdigest()
payer_cheque_raw = payer_amnt_str + '_' + payer_coin_hash
payer_cheque_hash = hashlib.sha256(payer_cheque_raw.encode('utf-8')).hexdigest()

response = requests.post(bank_url+'/check', json={
    'cheque_hash': payer_cheque_hash
})

print(response.text)

exists = bool(response.text)

if not exists:
    send('False')
    print('The payer claimed to own a coin that does not exist.')
    print('Payment cancelled.')
    sys.exit(1)

# Since no checks failed, this is probably legit
send('True')
assert recv() == 'awk.approval'
print('Response sent')

# Generate a new cheque
new_coin_nonce = str(random.randrange(1e16)).zfill(16)
new_coin_raw = public_key_hex + '_' + new_coin_nonce
new_coin_hash = hashlib.sha256(new_coin_raw.encode('utf-8')).hexdigest()
new_cheque_raw = payer_amnt_str + '_' + new_coin_hash

# Save the new cheque
with open("private_coin_storage.txt", "a+") as myfile:
    string  = payer_amnt_str + '\t'
    string += public_key_hex + '\t'
    string += new_coin_nonce + '\t'
    string += private_key_hex + '\n'
    myfile.write(string)

# Upload the new cheque encrypted using the payer's public key
payer_public_key = RSA.importKey(b64decode(payer_public_key_b64))

encrypted_cheque_str = b64encode(rsa.encrypt(new_cheque_raw.encode('utf-8'), payer_public_key)).decode('utf-8')

# Send the payee's cheque request to the server
print('sending encrypted_cheque_str')
send(encrypted_cheque_str)
print('sent')
assert recv() == 'recv.encrypted_cheque_str'
print('server awk\'ed')

# Send the payer's public key
print('sending payer_public_key_b64')
send(payer_public_key_b64)
print('public key sent')
assert recv() == 'recv.payer_public_key_b64'

print('Cheque request sent!')
