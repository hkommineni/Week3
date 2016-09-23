import itertools
import random
import os
# Author: Harish Kommineni
# Date: September 21, 2016
from Crypto.Cipher import AES
random.seed('Harish')

#http://docs.python.org/2/library/itertools.html#recipes
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)

# This method XOR's the given two blocks
def exclusiveOR(b1, b2):
    return ''.join(chr(ord(x) ^ ord(y)) for x,y in zip(b1, b2))

# This method is to decrypt using CBC mode of operation.
def decryption_Cbc(key, iv, data):
    output = []
    prev_block = iv
    for block in grouper(len(key), data):
        block = ''.join(block)
        x = AES.new(key, mode=AES.MODE_ECB).decrypt(block)
        output.append(exclusiveOR(prev_block, x))
        prev_block = block
    return ''.join(output)

def aesInCbc():
    """ AES in Cipher Block Chaining Mode, this program implements CBC mode using earlier ECB function.
 This program takes the input from data/w4p1.txt
"""
    with open('data/w4p1.txt') as f:
        ciphertext = ''.join(line for line in f).decode('base64')

    # AESKEY to Change
    print decryption_Cbc("NO PAIN NO GAIN!", '\x00' * 16, ciphertext)

# This method is to generate a random AES key
def random_key(keylen):
    return ''.join(os.urandom(keylen))

def pkcs7_pad(blocklength, text):
    """ This method is to return data with pad length"""
    padlen = blocklength - len(text) % blocklength
    return text + chr(padlen) * padlen

#This method detects the given cipher text in which operating mode
def detect_mode(ciphertext):
    blocks = grouper(16, ciphertext)
    blockset = set()
    for block in blocks:
        if block in blockset:
            return AES.MODE_ECB
        blockset.add(block)
    return AES.MODE_CBC

def detectEcbOrCbc():
    """
    This method detects the given text is encrypted in CBC mode or ECB mode
    This emthod gives encrypted Stuff for a method with prepended and appended 5,10 bytes of plaintext
    This method chooses the operation modes randomly.
"""

    def encryption_oracle(data):
        key = random_key(16)
        #NoOfPrependBytes
        prepend = random_key(random.randint(5, 10))
        #NoOfAppendBytes
        append = random_key(random.randint(5, 10))
        data = ''.join((prepend, data, append))

        #randomChoiceOfECB-CBC
        if random.randint(0, 1):
            mode = AES.MODE_ECB
            return mode, AES.new(key, mode=mode).encrypt(pkcs7_pad(16, data))
        else:
            mode = AES.MODE_CBC
            iv = random_key(16)
            return mode, AES.new(key, IV=iv, mode=mode).encrypt(pkcs7_pad(16, data))

    for i in xrange(10):
        #inputFile
        mode, ciphertext = encryption_oracle('NO PAIN NO GAIN!')
        print i, 'ecb' if mode == AES.MODE_ECB else 'cbc',
        if mode == detect_mode(ciphertext):
            print 'Selected'
        else:
            print 'Not Selected'

# This is the main method executes week 4 exercises.
if __name__ == '__main__':
    for f in (aesInCbc, detectEcbOrCbc ):
        print f.__doc__.split('\n')[0]
        f()
        print