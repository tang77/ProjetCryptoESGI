#!/usr/bin/python
# coding: utf-8
import os
import hashlib
import argparse
from itertools import izip, cycle


#init const vars
block_size = 8

def genIV():
    return os.urandom(block_size)
    #return chr(0x41)*block_size

IV=genIV()

def padding(size):
    return chr(0x41)*size

def hashing_key(input):
    return hashlib.sha256(input).hexdigest()

def xor_crypt(data, key):
    """Sinon on xor
    Pour chaque caractere x et y present respectivement dans data et key xor le caractere x de data avec le caractere y de key"""
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
    """On retourne la valeur xoree"""
    return xored


def CBC_decrypt(file_in,file_out,key):
    # init vars
    last_block = IV.encode('hex')
    print('IV : 0x' + last_block)
    iteration = 0 
    with open(file_in, "rb") as buffer_in:
        with open(file_out, 'wb') as buffer_out:
            while True:
                curr_block = buffer_in.read(block_size).decode('utf-8')
                if curr_block != '':
                    print('=============================================================')
                    print('# Decipher Block N°' + str(iteration) + ' with cyclic key 0x' + key)
                    round2=xor_crypt(xor_crypt(curr_block,key),last_block)
                    print('# Decipher Block : ' + round2)
                    print('=============================================================')
                    last_block=curr_block.encode('hex')

                else:
                    break
                buffer_out.write(round2.encode('utf-8'))
                iteration+=1
        
def CBC_crypt(file_in,file_out,key):
    # generate the init vector from crypto random lib
    last_block = IV.encode('hex')
    iteration = 0
    print("IV : 0x" + last_block)
    # open file
    with open(file_in, "rb") as buffer_in:
        with open(file_out, "wb") as buffer_out:
            while True:
                curr_block = buffer_in.read(block_size)
                curr_len = len(curr_block)

                if curr_block == "":
                    print 'Done!'
                    break #EOF

                if curr_len < block_size:
                    curr_block += padding(block_size - curr_len)

                # first round cipher with IV/last block
                round1 = xor_crypt(curr_block, last_block)
                # second round cipher with Passphrase
                round2 = xor_crypt(round1,key)
                print('=============================================================')
                print "# Cipher block N°" + str(iteration) + " with cyclic key 0x" + key 
                print "# Cipher block : " + round2.encode("utf-8")
                print('=============================================================')
                if b'\x00' in round2:
                    print 'null byte detected!!'
                    print round2.encode("utf-8")
                    break

                last_block = round2.encode('hex')
                iteration += 1

                buffer_out.write(round2.encode("utf-8"))

if __name__ == "__main__":
    #here we crypt
    CBC_crypt('test.txt','out.txt','123456')

    #shall we decrypt
    CBC_decrypt('out.txt', 'dec.txt', '123456')
