''' File containing various crypto encoding and decoding functions'''
import re

base64_table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
hex_table = '0123456789ABCDEF'
byte_len = 4
b64_step=6

def is_hex(hex_string):
    hex_regexp = '[0-9A-Fa-f]+$'
    return re.match(hex_regexp, hex_string) is not None

def is_binary(binary_string):
    binary_regexp = '[0-1]+$'
    return re.match(binary_regexp, binary_string) is not None

def hex_to_binary(hex_string):
    if not is_hex(hex_string):
        raise TypeError("Error: Requires hexadecimal string input")
    return ''.join(bin(int(h,16))[2:].zfill(byte_len) for h in hex_string)

def binary_to_hex(binary_string):
    if not is_binary(binary_string):
        raise TypeError("Error: Requires binary string input")
    return ''.join(hex_table[int(binary_string[b:b+byte_len],2)] for b in range(0,len(binary_string), byte_len))

def base64_to_binary(b64_string):
    return ''.join(bin(base64_table.index(b))[2:].zfill(b64_step) for b in b64_string)

def hex_to_base64(hex_string):
    if type(hex_string) != str:
        raise TypeError("Error: hex_to_base requires input in str")

    data = hex_to_binary(hex_string)  #convert hex to binary
    return ''.join([base64_table[int(data[p:p+b64_step],2)] for p in range(0,len(data),b64_step)])

def base64_to_hex(base64):
    if type(base64) != str:
        raise TypeError("Error: base64_to_hex requires input in str")
    return binary_to_hex(base64_to_binary(base64))
