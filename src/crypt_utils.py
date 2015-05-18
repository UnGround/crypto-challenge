"""
common utilities for encrypt and decrypt
"""
import encode
import binascii
import re


hex_table = '0123456789ABCDEF'
byte_len = 4


def is_hex(hex_string):
    hex_regexp = '[0-9A-Fa-f]+$'
    if type(hex_string) is not str:
        return False
    return re.match(hex_regexp, hex_string) is not None


def is_binary(binary_string):
    binary_regexp = '[0-1]+$'
    return re.match(binary_regexp, binary_string) is not None


def hex_to_binary(hex_string):
    if not is_hex(hex_string):
        raise TypeError("Error: Requires hexadecimal string input, received " + hex_string)
    return ''.join(bin(int(h, 16))[2:].zfill(byte_len) for h in hex_string)


def binary_to_hex(binary_string):
    if not is_binary(binary_string):
        raise TypeError("Error: Requires binary string input")
    return ''.join(hex_table[int(binary_string[b-byte_len if b-byte_len > 0 else 0:b],2)] for b in range(len(binary_string), 0, -byte_len))[::-1]


def xor(a, b):
    a = int(hex_to_binary(a), 2)
    b = int(hex_to_binary(b), 2)
    c = bin(a ^ b)[2:]
    return binary_to_hex(c)


def get_next_hex(data):
    """generates next hex byte of information from data."""
    loc = 0
    while loc < len(data):
        h = toHex(data[loc])
        yield h
        loc += 1


def toBinary(s, is_hex=False):
    """convert string s to a binary string representation.
    For instance, passing the character 'a' will return
    '01100001'

    If isHex is set to True, this treats the data as a 
    hex string instead of ascii.
    """
    if is_hex:
        return ''.join(bin(int(h, 16))[2:].zfill(4) for h in s)
    else:
        return ''.join(format(ord(c), 'b').zfill(8) for c in s)


def toHex(s):
    """convert string s to a hex string representation
    """
    if type(s) is not bytes:
        s = bytes(s, 'UTF8')

    return str(binascii.hexlify(s))[2:-1]


def hamming_distance(s1, s2, is_hex=False):
    """calculates the hamming distance between two strings.
    The hamming distance is defined as the number of differing
    bits.

    set is_hex to true if the strings are in a hex format. By
    default, strings are treated as ascii.
    """
    diff = xor(toBinary(s1, is_hex), toBinary(s2, is_hex))
    hamming_distance = 0
    for c in diff:
        hamming_distance += int(c)
    return hamming_distance
