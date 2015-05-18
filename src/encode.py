''' File containing various crypto encoding and decoding functions'''
import re
import binascii
import base64

import crypt_utils

base64_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
b64_step = 6


def base64_to_binary(b64_string):
    s = base64.standard_b64decode(b64_string)
    print(s)
    print(str(s)[2:-1])
    return crypt_utils.toBinary(str(s)[2:-1])
    
    s = ''
    for b in b64_string:
        print(b)
        s += ''.join(bin(base64_table.index(b))[2:].zfill(b64_step))
    return s


def hex_to_base64(hex_string):
    if type(hex_string) != str and type(hex_string) != bytes:
        raise TypeError("Error: hex_to_base64 requires a string")

    if not crypt_utils.is_hex(hex_string):
        raise TypeError("Error: passed data is not Hex")
    
    if type(hex_string) is not bytes:
        hex_string = bytes(hex_string, 'UTF8')

    s = binascii.unhexlify(hex_string)
    return str(base64.standard_b64encode(s))[2:-1]


def base64_to_hex(b64):
    if type(b64) != str and type(hex_string) != bytes:
        raise TypeError("Error: base64_to_hex requires input in str")

    if type(b64) is not bytes:
        b64 = bytes(b64, 'UTF8')

    h = base64.standard_b64decode(b64)
    return crypt_utils.toHex(h)


def repeating_key_loop(key):
    """generates the next byte of key information for repeating key XOR."""
    loc = 0
    while(True):
        h = crypt_utils.toHex(key[loc])
        yield h
        loc = (loc + 1) % len(key)


def encrypt_repeating_key_xor(data, key):
    """Implementation of repeating key xor. (ex 1.5)."""
    message = ""
    keygen = repeating_key_loop(key)
    for b in crypt_utils.get_next_hex(data):
        keybit = next(keygen)
        enc = crypt_utils.xor(b, keybit)
        if(len(enc) < 2):   # ensure leading 0's are added to the byte if required
            enc = '0' + enc
        message += enc
    return message
