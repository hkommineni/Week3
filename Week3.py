import itertools
# Author: Harish Kommineni
# Date: September 14, 2016
from Crypto.Cipher import AES

def aesInEcb():
    """AES-128 in ECB Mode:

The Base64-encoded content at the location: data/w3p1.txt
Has been encrypted via AES-128 in ECB mode under the key "NO PAIN NO GAIN!".
"""
    with open('data/w3p1.txt') as f:
        base64_text = f.read().decode('base64')
        #AESKEY to Change
    print AES.new("NO PAIN NO GAIN!", mode=AES.MODE_ECB).decrypt(base64_text)

#http://docs.python.org/2/library/itertools.html#recipes
def grouper(n, iterable, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper(3, 'ABCDEFG', 'x') --> ABC DEF Gxx
    args = [iter(iterable)] * n
    return itertools.izip_longest(fillvalue=fillvalue, *args)

def detectEcb():
    """Detecting ECB
    hex-encoded ciphertexts is located at data/w3p2.txt
This method detects where one of them is in ECB mode
"""
    with open('data/w3p2.txt') as text:
        for i, line in enumerate(text):
            blocks = grouper(16, line.strip().decode('hex'))
            blockset = set()
            for block in blocks:
                if block in blockset:
                    print 'ECB mode is in line %d: %s...' % (i+1, line[:64])
                    break
                blockset.add(block)

def pkcs7_pad(blocklength, text):
    """ This method is to return data with pad length"""
    padlen = blocklength - len(text) % blocklength
    return text + chr(padlen) * padlen

def pkcsPadding():
    """To Implement PKCS#7 padding
'This is a Saturday' to 160 bit blocks gives 'This is a Saturday\x02\x02'
and 128 bit blocks gives 'NO PAIN NO GAIN!' to 'NO PAIN NO GAIN!\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'

"""
    test_data = [(20, 'This is a Saturday'),(16, 'NO PAIN NO GAIN!')]

    for padlength,data in test_data:
        print padlength, repr(data), repr(pkcs7_pad(padlength, data))

# This is the main method executes week 3 exercises.
if __name__ == '__main__':
    for f in (aesInEcb, detectEcb, pkcsPadding):
        print f.__doc__.split('\n')[0]
        f()
        print
