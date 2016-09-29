import itertools
import os

# Author: Harish Kommineni
# Date: September 26, 2016
from functools import partial
from Crypto.Cipher import AES

#http://docs.python.org/2/library/itertools.html#recipes
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)


def pkcs7_pad(blocklength, text):
    """ This method is to return data with pad length"""
    padlen = blocklength - len(text) % blocklength
    return text + chr(padlen) * padlen

# This method is to generate a random AES key
def random_key(keylen):
    return ''.join(os.urandom(keylen))

def findBlockLength(fcrypt):
    #push ciphertext over into the next block length
    orig_len = len(fcrypt(''))
    for i in xrange(1, 128):
        cur_len = len(fcrypt('A' * i))
        if cur_len - orig_len:
            blocklen = cur_len - orig_len
            return blocklen
    return -1

#This method detects the given cipher text in which operating mode
def detect_mode(ciphertext):
    blocks = grouper(16, ciphertext)
    blockset = set()
    for block in blocks:
        if block in blockset:
            return AES.MODE_ECB
        blockset.add(block)
    return AES.MODE_CBC

def decryptCookie():
    """
    This to decrypt the encrypted cookie data using oracle function from previois exercise. The encryption function appends to the plaintext and finds blocks length.
    Then using determined block length this method detects the ecnryption mode and then decrypts the data.
"""
    def encryption_oracle(key, data):
        # Cookie64.txt.
        unknown = "fFNhbm98MzUwMSBTLiBTaGllbGRzIEF2ZXx8Q2hpY2Fnb3xJTHw2MDYxNnwzMTItNzQ0LTEwMDN8YWRtaW5AbXlzaXRlLmNvbXw5MjgtMjkzLTE5Mjh8aWQ9ODM3fHY9MXxkbD0xfHJlcT0xfG1ncj0wfGFkbWluPTA=".decode('base64')
        return AES.new(key, mode=AES.MODE_ECB).encrypt(pkcs7_pad(16, data + unknown))

    #  Genretes the random 16 byte randome key
    key = random_key(16)
    fullCrypt = partial(encryption_oracle, key)

    #detect blocklen
    blocklen = findBlockLength(fullCrypt)
    print 'Block length:', blocklen

    #detect mode
    mode = detect_mode(fullCrypt('A' * 48))
    print 'Mode:', 'ecb' if mode == AES.MODE_ECB else 'cbc'
    print

    def decrypt_block(blocklen, fcrypt, known):
        "decrypt block by passing prefixes into oracle function fcrypt"
        offset = len(known)
        plain = ''
        for i in xrange(blocklen,0,-1):
            pad = 'A' * (i - 1)
            cipher_block = fcrypt(pad)[offset:offset + blocklen]
            pad += known + plain
            for c in (chr(x) for x in xrange(256)):
                if cipher_block == fcrypt(pad + c)[offset:offset + blocklen]:
                    plain += c
                    break
        return plain

    #decrypt cipher text
    cipher_blocks = len(fullCrypt('')) / blocklen
    output = ''
    for _ in xrange(cipher_blocks):
        output += decrypt_block(blocklen, fullCrypt, output)
    print 'Plaintext:'
    print output


# This is the main method executes week 5 exercises.
if __name__ == '__main__':
    decryptCookie()