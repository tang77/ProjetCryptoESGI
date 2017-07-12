#!/usr/bin/python
# coding: utf-8

# Modules import

from cryptoApp.misc import globalOperations 
from cryptoApp.crypto import encrypt
from cryptoApp.crypto import decrypt 


globalOperations.encodeDefault()

if __name__ == "__main__":
    
    # Here We have some debug functions for modules
    # hello_misc.hello()
    # hello_crypto.hello()
    
        
    #Here we call the CBC_crypt function
    encrypt.CBC_crypt('test.txt','out.txt','123456')

    #Here we call the CBC_decrypt function
    decrypt.CBC_decrypt('out.txt', 'dec.txt', '123456')
