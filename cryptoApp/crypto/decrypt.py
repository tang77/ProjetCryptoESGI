#/usr/bin/env python
# -*- coding: utf-8 -*-

from itertools import izip, cycle
from cryptoApp.misc import globalOperations

# Size of each block
block_size = 256

# IV size
IV_size = block_size/8

# Decrypt CBC function
def CBC_decrypt(file_in,file_out,key):
    #generate 256bit key (sha256bits)
    key = globalOperations.hashing_key(key)
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
                    dexor = globalOperations.xor_crypt(globalOperations.xor_crypt(curr_block,key),last_block)
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

