#!/usr/bin/python
import os
import hashlib

block_size = 8

def genIV():
    return os.urandom(block_size)

def padding(size):
    return chr(0x1)*size
    #return os.urandom(size)

def crypt(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

def hashing_key(input):
    return hashlib.sha256(input.encode('utf-8')).hexdigest()

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

def main():
    #setting passphrase key
    key = "MyPassphrase"

    # store result
    result = ""

    #changing vector
    last_block = ""

    # generate the init vector from crypto random lib
    IV = genIV()
    last_block = IV
    iteration = 0

    print "Generated initial IV : 0x" + IV.encode("hex")

    # open file
    with open("test.txt", "rb") as in_file:
        with open("test.cbcrypted.txt", "wb") as out_file:
            while True:
                curr_block = in_file.read(block_size)
                curr_len = len(curr_block)

                if curr_block == "":
                    break #EOF

                if curr_len < block_size:
                    curr_block += padding(block_size - curr_len)
                    print "padded block: " + curr_block

                # first round cipher with IV/last block
                r1 = crypt(curr_block, last_block)

                # second round cipher with Passphrase
                hashed_alternating_key = cyclic_hashed_key_for_xor(key, iteration)
                r2 = crypt(r1, hashed_alternating_key)
                print "Cipher block N" + str(iteration) + " with cyclic key 0x" + hashed_alternating_key

                last_block = r2
                iteration += 1
                out_file.write(r2.encode('hex'))

if __name__ == "__main__":
    main()
