#!/usr/bin/python
# coding: utf-8

# Modules import
import os
import hashlib
import argparse
import sys
from itertools import izip, cycle

reload(sys)
sys.setdefaultencoding('iso-8859-1')

# Size of each block
block_size = 256
# IV size
IV_size = block_size/8

# Initialisation vector generation function
def genIV():
    return os.urandom(IV_size)

# Initialisation vector generation
IV=genIV()

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

# Decrypt CBC function
def CBC_decrypt(file_in,file_out,key):
    #generate 256bit key (sha256bits)
    key = hashing_key(key)
    # Init the blocks counter
    iteration = 0 
    # Open input and output streams
    # Input file is open as buffer_in with read permission
    with open(file_in, "rb") as buffer_in:
        # The last block is our initialisation vector
        last_block = buffer_in.read(IV_size)
        # Displaying initialisation vector
        print('IV : 0x' + last_block.encode('hex'))
        # Open output file as buffer_out with write permission
        with open(file_out, 'wb') as buffer_out:
            # Loop while there is content
            while True:
                # We get the current block and decoding it
                curr_block = buffer_in.read(block_size).decode()
                # If the block is not empty
                if curr_block != '':
                    # Then we decrypt it with the key and after we xor it with the initialisation vector
                    dexor = xor_crypt(xor_crypt(curr_block,key),last_block)
                    # Encoding in utf-8
                    dexorUtf = dexor.encode()
                    # Display the number of the block and the decrypt content
                    print('=============================================================')
                    print('# Decipher Block N°' + str(iteration) + ' with hashed key 0x' + key.encode('hex'))
                    print('# Decipher Block : ' + dexorUtf)
                    print('=============================================================')
                    # Then the last_block var takes the value of the current block
                    last_block=curr_block
                # Else
                else:
                    # We leave the loop because there are not any more data
                    break
                if b'\xFF' in dexor:
                    dexor = dexor.replace(b'\xFF','')
                # We write the deciphered data to the output stream
                buffer_out.write(dexor)
                # Iterate the counter
                iteration+=1

# Encrypt CBC function
def CBC_crypt(file_in,file_out,key):
    #generate 256bit key (sha256bits)
    key = hashing_key(key)
    # The last block is our initialisation vector
    last_block = IV
    # Init the blocks counter
    iteration = 0
    # Displaying initialisation vector
    print("IV : 0x" + last_block.encode('hex'))
    # Open input and output streams
    # Input file is open as buffer_in with read permission
    with open(file_in, "rb") as buffer_in:
        with open(file_out, "wb") as buffer_out:
            #storing IV
            buffer_out.write(last_block)
            while True:
                # We get the current block 
                curr_block = buffer_in.read(block_size)
                # We get the current length block 
                curr_len = len(curr_block)

                # If current block is empty 
                if curr_len <= 0:
                    # Display Done
                    print 'Done!'
                    break #EOF

                # If current block length is lower than the block size
                if curr_len < block_size:
                    # Then we add padding
                    curr_block += padding(block_size - curr_len)
                # Then we xor the current block with the last block and encrypt it with the key
                enxor = xor_crypt(xor_crypt(curr_block,last_block),key)
                # Encoding in utf-8
                enxorUtf = enxor.encode()
                # Display the number of the block and the encrypt content
                print('=============================================================')
                print("# Cipher block N°" + str(iteration) + " with hashed key 0x" + key.encode('hex')) 
                print("# Cipher block : " + enxorUtf)
                print('=============================================================')
                
                # Then the last_block var takes the value of the encrypted block
                last_block = enxor
                # Iterate the counter
                iteration += 1
                # We write the ciphered data to the output stream
                buffer_out.write(enxor)

if __name__ == "__main__":
    #Here we call the CBC_crypt function
    CBC_crypt('test.txt','out.txt','123456')

    #Here we call the CBC_decrypt function
    CBC_decrypt('out.txt', 'dec.txt', '123456')
