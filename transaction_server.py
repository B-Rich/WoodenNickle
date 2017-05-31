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
import math

listen_port = 1026

def send(txt):
    return c.send(txt.encode('utf-8'))
def recv():
    return c.recv(listen_port).decode('utf-8')

s = socket.socket()
host = socket.gethostname()
port = 1247
s.bind((host,port))
s.listen(5)

import atexit
atexit.register(s.close)

pending_payer_uploads = {}
pending_payee_uploads = {}

while True:
    c, addr = s.accept()
    print('Connection accepted from ' + repr(addr[1]))

    send('awk.init')

    public_key_b64 = recv()
    send('recv.public_key_b64')
    print('got public_key_b64')

    timestamp = recv()
    send('recv.timestamp')
    print('got timestamp')

    signature = recv()
    send('recv.signature')
    print('got signature')

    print('got credentials')
    # Check that the timestamp hasn't expired
    now = time.time()
    print('timestamp: {}'.format(timestamp))
    if abs(now - float(timestamp)) > 10:
        send('err.time')
        c.close()
        continue

    print('timestamp verified')

    # Decode the public key
    public_key = RSA.importKey(b64decode(public_key_b64))

    # Verify signature on the timestamp
    valid_signature = rsa.verify(timestamp.encode('utf-8'), b64decode(signature), public_key)
    valid_signature = valid_signature * 1 # Convert to boolean

    print('checking signature')
    if not valid_signature:
        send('err.sig')
        c.close()
        continue

    # Store their IP
    print(c.getpeername()[0])

    send('awk.sig')

    protocol = recv()

    if protocol == 'protocol.payer.upload_cheque':
        send('awk.protocol.payer.upload_cheque') # This code duplication is on purpose

        payee_public_key_b64 = recv()
        send('recv.payee_public_key_b64')

        encrypted_cheque_str = recv()
        send('recv.encrypted_cheque_str')

        pending_payer_uploads[payee_public_key_b64] = encrypted_cheque_str
    elif protocol == 'protocol.payer.download_cheque':
        send('awk.protocol.payer.download_cheque') # This code duplication is on purpose

        recv() # Make sure the payer is ready for the next message

        if public_key_b64 in pending_payee_uploads:
            send(pending_payee_uploads[public_key_b64])
            pending_payee_uploads.pop(public_key_b64)
        else:
            send('None')
    elif protocol == 'protocol.payee':
        send('awk.protocol.payee') # This code duplication is on purpose

        recv() # Make sure the payer is ready for the next message

        if public_key_b64 in pending_payer_uploads:
            send(pending_payer_uploads[public_key_b64])
            recv()

            pending_payer_uploads.pop(public_key_b64)
        else:
            send('None')
            c.close()
            continue

        print('Waiting for approval')

        # See if the payee approves
        approved = bool(recv())
        send('awk.approval')

        print(approved)

        print('got approval')

        if approved:
            print('approved')
            # Ask for the payee's new coin
            print('waiting for encrypted_cheque_str')
            encrypted_cheque_str = recv()
            send('recv.encrypted_cheque_str')

            print('waiting for payer_public_key_b64')
            payer_public_key_b64 = recv()
            send('recv.payer_public_key_b64')

            pending_payee_uploads[payer_public_key_b64] = encrypted_cheque_str

    c.close()

    print('Done!')
