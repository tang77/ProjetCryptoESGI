#!/usr/bin/python
# coding: utf-8

# Modules import
import os
import hashlib
import argparse
from itertools import izip, cycle

# Size of each block
block_size = 8

# Initialisation vector generation function
def genIV():
    return os.urandom(block_size).encode('hex')

# Initialisation vector generation
IV=genIV()

# Padding generation function
def padding(size):
    return chr(0x41)*size

# Key hash generation function
def hashing_key(input):
    return hashlib.sha256(input).hexdigest()

# Xor function
def xor_crypt(data, key):
    
    # Foreach carac x and y respectively present in data and key xor x from data with y from key
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
    # Return xored value
    return xored

# Decrypt CBC function
def CBC_decrypt(file_in,file_out,key):
    
    # The last block is our initialisation vector
    last_block = IV
    # Displaying initialisation vector
    print('IV : 0x' + last_block)
    # Init the blocks counter
    iteration = 0 
    # Open input and output streams
    # Input file is open as buffer_in with read permission
    with open(file_in, "rb") as buffer_in:
        # Open output file as buffer_out with write permission
        with open(file_out, 'wb') as buffer_out:
            # Loop while there is content
            while True:
                # We get the current block and decoding it
                curr_block = buffer_in.read(block_size).decode('utf-8')
                # If the block is not empty
                if curr_block != '':
                    # Then we decrypt it with the key and after we xor it with the initialisation vector
                    dexor = xor_crypt(xor_crypt(curr_block,key),last_block)
                    # Encoding in utf-8
                    dexorUtf = dexor.encode('utf-8')
                    # Display the number of the block and the decrypt content
                    print('=============================================================')
                    print('# Decipher Block N°' + str(iteration) + ' with cyclic key 0x' + key)
                    print('# Decipher Block : ' + dexorUtf)
                    print('=============================================================')
                    # Then the last_block var takes the value in hexadecimal of the current block
                    last_block=curr_block.encode('hex')
                # Else
                else:
                    # We leave the loop because there are not any more data
                    break
                # We write the deciphered data to the output stream
                buffer_out.write(dexorUtf)
                # Iterate the counter
                iteration+=1

# Encrypt CBC function
def CBC_crypt(file_in,file_out,key):
     
    # The last block is our initialisation vector
    last_block = IV
    # Init the blocks counter
    iteration = 0
    # Displaying initialisation vector
    print("IV : 0x" + last_block)
    # Open input and output streams
    # Input file is open as buffer_in with read permission
    with open(file_in, "rb") as buffer_in:
        with open(file_out, "wb") as buffer_out:
            while True:
                # We get the current block 
                curr_block = buffer_in.read(block_size)
                # We get the current length block 
                curr_len = len(curr_block)

                # If current block is empty 
                if curr_block == "":
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
                enxorUtf = enxor.encode('utf-8')
                # Display the number of the block and the encrypt content
                print('=============================================================')
                print("# Cipher block N°" + str(iteration) + " with cyclic key 0x" + key) 
                print("# Cipher block : " + enxorUtf)
                print('=============================================================')
                
                # If we encounter the null byte in the xor
                if b'\x00' in enxor:
                    # Display the following
                    print 'null byte detected!!'
                    print enxor
                    # And we leave
                    break
                # Then the last_block var takes the value in hexadecimal of the encrypted block
                last_block = enxor.encode('hex')
                # Iterate the counter
                iteration += 1
                # We write the ciphered data to the output stream
                buffer_out.write(enxorUtf)


if __name__ == "__main__":
    #Here we call the CBC_crypt function
    CBC_crypt('test.txt','out.txt','123456')

    #Here we call the CBC_decrypt function
    CBC_decrypt('out.txt', 'dec.txt', '123456')
