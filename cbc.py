#!/usr/bin/python
import os
import hashlib
import sys
import argparse

reload(sys)  # Reload does the trick!
sys.setdefaultencoding('ISO-8859-1')

#init const vars
block_size = 8

def genIV():
    return os.urandom(block_size)
    #return chr(0x41)*block_size

def padding(size):
    return chr(0x41)*size

def crypt(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def hashing_key(input):
    return hashlib.sha256(input.encode()).hexdigest()

def cyclic_hashed_key_for_xor(password, shift):
    hashkey = hashing_key(password)
    size = len(hashkey)
    cyclic = ""
    i = shift % size
    while (len(cyclic) < block_size*2):
        if(i+1>size):
            i = 0
        cyclic += hashkey[i]
        i += 2
    return cyclic

def CBC_decrypt(file_in,file_out,key):
    # init vars
    IV = ""
    last_block = ""
    filesize = os.path.getsize(file_in)
    iteration = (filesize / block_size)
    print iteration
    return

    # open file
    with open(file_in, "rb") as buffer_in:
        buffer_in.seek(-block_size, 2)
        
        IV = buffer_in.read(block_size).decode()
        print 'Recovering IV from buffer: 0x' + IV.encode('hex')
        
        buffer_in.seek(block_size*iteration, 0)
        last_block = IV

        with open(file_out, "wb") as buffer_out:
            while True:
                if iteration>=0:
                    buffer_in.seek(block_size*iteration, 0)
                    curr_block = buffer_in.read(block_size).decode()
                
                    print curr_block.encode('hex')

                    round1 = crypt(curr_block, key)
                    round2 = crypt(round1, last_block)

                    last_block = round2
                    iteration -= 1

                    buffer_out.write(round2.decode())
                else:
                    break


def CBC_crypt(file_in,file_out,key):
    # generate the init vector from crypto random lib
    IV = genIV()
    last_block = IV
    iteration = 0

    print "Generated initial IV : 0x" + IV.encode("hex")

    # open file
    with open(file_in, "rb") as buffer_in:
        with open(file_out, "wb") as buffer_out:
            while True:
                curr_block = buffer_in.read(block_size)
                curr_len = len(curr_block)

                if curr_block == "":
                    print 'Writing IV to a new block!'
                    #buffer_out.write(IV.encode())
                    print 'Done!'
                    break #EOF

                if curr_len < block_size:
                    print curr_block
                    curr_block += padding(block_size - curr_len)
                    print curr_block

                # first round cipher with IV/last block
                round1 = crypt(curr_block, last_block)

                # second round cipher with Passphrase
                #hashed_alternating_key = cyclic_hashed_key_for_xor(key, iteration)
                hashed_alternating_key = key
                round2 = crypt(round1, hashed_alternating_key)
                print "Cipher block N" + str(iteration) + " with cyclic key 0x" + hashed_alternating_key

                if b'\x00' in round2:
                    print 'null byte detected!!'
                    print round2
                    break

                last_block = round2
                iteration += 1

                buffer_out.write(round2.encode())

if __name__ == "__main__":
    #here we crypt
    CBC_crypt('test.txt','out.txt','123456')

    #shall we decrypt
    CBC_decrypt('out.txt', 'dec.txt', '123465')