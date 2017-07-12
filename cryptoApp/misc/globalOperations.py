#/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import sys
import os
from itertools import izip, cycle

# Size of each block
block_size = 256

# IV size
IV_size = block_size/8

# Encoding default function
def encodeDefault():
    reload(sys)
    sys.setdefaultencoding('iso-8859-1')

# Initialisation vector generation function
def genIV():
    return os.urandom(IV_size)

# Padding generation function
def padding(size):
    return chr(0xFF)*size

# Key hash generation function
def hashing_key(tohash):
    return hashlib.sha256(tohash).digest()

# Xor function
def xor_crypt(data, key):
    # Foreach carac x and y respectively present in data and key xor x from data with y from key
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
    # Return xored value
    return xored

