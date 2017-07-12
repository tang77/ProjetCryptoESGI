#/usr/bin/env python
# -*- coding: utf-8 -*-

from itertools import izip, cycle
from cryptoApp.misc import globalOperations
# Size of each block
block_size = 256

# IV size
IV_size = block_size/8
IV=globalOperations.genIV()

# Encrypt CBC function
def CBC_crypt(file_in,file_out,key):
    #generate 256bit key (sha256bits)
    key = globalOperations.hashing_key(key)
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
                    curr_block += globalOperations.padding(block_size - curr_len)
                # Then we xor the current block with the last block and encrypt it with the key
                enxor = globalOperations.xor_crypt(globalOperations.xor_crypt(curr_block,last_block),key)
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
