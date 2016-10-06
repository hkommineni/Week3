import itertools
import random
import os

# Author: Harish Kommineni
# Date: October 05, 2016

from functools import partial
from Crypto.Cipher import AES

#http://docs.python.org/2/library/itertools.html#recipes
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)

# This method is to return data with pad length
def pkcs7_pad(blocklength, text):
    padlen = blocklength - len(text) % blocklength
    return text + chr(padlen) * padlen

# This method is to generate a random AES key
def random_key(keylen):
    return ''.join(os.urandom(keylen))

# This method is to find the block legth for a given data
def findBlockLength(fcrypt):
    orig_len = len(fcrypt(''))
    for i in xrange(1, 128):
        cur_len = len(fcrypt('A' * i))
        if cur_len - orig_len:
            blocklen = cur_len - orig_len
            return blocklen
    return -1

# This method detects the given cipher text in which operating mode
def detect_mode(ciphertext):
    blocks = grouper(16, ciphertext)
    blockset = set()
    for block in blocks:
        if block in blockset:
            return AES.MODE_ECB
        blockset.add(block)
    return AES.MODE_CBC

# This method helps to detect the full prefix blocks
def detectPrefixlength(blocklength, fcrypt):
    prefixlen = 0
    blocks1 = grouper(blocklength, fcrypt(''))
    blocks2 = grouper(blocklength, fcrypt('A'))
    for block1, block2 in zip(blocks1, blocks2):
        if block1 != block2:
            break
        prefixlen += blocklength

    # add last (partial-block) prefix length
    offset = prefixlen
    for i in xrange(blocklength):
        b1 = fcrypt('A' * i)[offset:offset + blocklength]
        b2 = fcrypt('A' * (i + 1))[offset:offset + blocklength]
        if b1 == b2:
            prefixlen += blocklength - i
            break
    return prefixlen

def decrypt_block(blocklen, prefixlen, fcrypt, known):
    "decrypt block by passing prefixes into oracle function fcrypt"
    offset = 0
    while offset <= prefixlen:
        offset += blocklen
    offset += len(known)
    plain = ''
    prefix_pad = 'X' * (blocklen - prefixlen % blocklen)
    for i in xrange(blocklen, 0, -1):
        pad = prefix_pad + 'A' * (i - 1)
        cipher_block = fcrypt(pad)[offset:offset + blocklen]
        pad += known + plain
        for c in (chr(x) for x in xrange(256)):
            if cipher_block == fcrypt(pad + c)[offset:offset + blocklen]:
                plain += c
                break
    return plain

def decryptCookiePart2():
    """ This method uses the week 5 code and modify the encryption oracle to add 10,20 number of bytes to the start and decryot the target_bytes"""

    def encryption_oracle(key, prefix, data):
        unknown = "fFNhbm98MzUwMSBTLiBTaGllbGRzIEF2ZXx8Q2hpY2Fnb3xJTHw2MDYxNnwzMTItNzQ0LTEwMDN8YWRtaW5AbXlzaXRlLmNvbXw5MjgtMjkzLTE5Mjh8aWQ9ODM3fHY9MXxkbD0xfHJlcT0xfG1ncj0wfGFkbWluPTA=".decode('base64')
        return AES.new(key, mode=AES.MODE_ECB).encrypt(pkcs7_pad(16, prefix + data + unknown))

    key = random_key(16)
    prefix = random_key(random.randint(10,20))
    fcrypt = partial(encryption_oracle, key, prefix)

    #detect blocklen
    blocklen = findBlockLength(fcrypt)
    print 'Block length:', blocklen

    #detect mode
    mode = detect_mode(fcrypt('A' * 48))
    print 'Mode:', 'ecb' if mode == AES.MODE_ECB else 'cbc'

    #detect the prefix length
    prefixlen = detectPrefixlength(blocklen, fcrypt)
    print 'Prefix length:', prefixlen
    print

    #decrypt unknown from oracle
    cipher_blocks = len(fcrypt('')) / blocklen
    output = ''
    for _ in xrange(cipher_blocks):
        output += decrypt_block(blocklen, prefixlen, fcrypt, output)
    print 'Plaintext:'
    print output

# This method strips off the padding if the padding is valid and throws an exception if the padding is invalid.
class PadException(Exception):
    pass

def pkcs7_strip(data):
    padchar = data[-1]
    padlen = ord(padchar)
    if padlen == 0 or not data.endswith(padchar * padlen):
        raise PadException
    return data[:-padlen]


def validatePKCS7Padding():
    """This function takes the plaintext, checks if it has valid padding,
    if the padding is valid this function strip off the padding."""
    strings = [
            "This is a Saturday\x02\x02",
            "This is a Saturda\x03\x02\x02"]

    for test in strings:
        try:
            print '%s: %s' % (repr(test), pkcs7_strip(test))
        except PadException as e:
            print '%s: %s' % (repr(test), repr(e))

# This is the main method executes week 5 exercises.
if __name__ == '__main__':
    for f in (decryptCookiePart2, validatePKCS7Padding):
        print f.__doc__.split('\n')[0]
        f()
        print