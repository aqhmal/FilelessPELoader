#!/usr/bin/env python3
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
import hashlib


def AESencrypt(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = 16 * b'\x00'
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, k

def dropFile(key, ciphertext):
  with open("cipher.bin", "wb") as fc:
    fc.write(ciphertext)
  with open("key.bin", "wb") as fk:
    fk.write(key)


try:
    file = open(sys.argv[1], "rb")
    content = file.read()
except:
    print("Usage: aes.py PAYLOAD_FILE")
    sys.exit()

KEY = urandom(32)
ciphertext, key = AESencrypt(content, KEY)

dropFile(KEY,ciphertext)
