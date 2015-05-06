import encode
import binascii
import sys
from collections import defaultdict

#English letter frequencies from http://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
english_letter_frequencies = {
        'E' :   12.02,
        'T' :   9.10,
        'A' :   8.12,
        'O' :   7.68,
        'I' :   7.31,
        'N' :   6.95,
        'S' :   6.28,
        'R' :   6.02,
        'H' :   5.92,
        'D' :   4.32,
        'L' :   3.98,
        'U' :   2.88,
        'C' :   2.71,
        'M' :   2.61,
        'F' :   2.30,
        'Y' :   2.11,
        'W' :   2.09,
        'G' :   2.03,
        'P' :   1.82,
        'B' :   1.49,
        'V' :   1.11,
        'K' :   0.69,
        'X' :   0.17,
        'Q' :   0.11,
        'J' :   0.10,
        'Z' :   0.07,
    }
characters_not_to_score = ' \',.' #common english punctuation to ignore for frequency scoring

def single_byte_xor_decrypt(message, key):
    '''Key should be a single character, represented in Hex.'''
    if not encode.is_hex(message) or not encode.is_hex(key):
        raise TypeError("Error: message and key expected in Hex format")
    decode = ''
    for i in range(len(message), 0, -2):
        b = message[i-2:i]
        tmp = encode.xor(b, key)
        if len(tmp) < 2:
            tmp = '0' + tmp
        decode = tmp + decode
    return decode

def analyze_char_freq(string):
    if type(string) is not str:
        raise TypeError("Required input is a str object")
    frequencies = defaultdict(int)
    analysis = {}
    chars = 0
    for c in string:
        c = c.upper()
        frequencies[c] += 1
        chars += 1
    frequencies = dict(frequencies)
    for key in frequencies.keys():
        frequencies[key] = (frequencies[key] / chars) *100

    return frequencies

def score_char_freq(d1, reference=english_letter_frequencies):
    '''reuturn a score as to how much d1 differs from the expected reference. A better score is closer to 0. 
    That means that, over a large enough sample text run through analyze_char_freq and then scored, it should approach a score of 0.'''
    score = 0
    for key, val in d1.items():
        if key in characters_not_to_score:
            continue
        if key not in reference.keys():
            score += val * 10
        else:
            score += abs(val - reference[key])
    return score

def search_single_byte_xor_key(message):
    '''searches for the most likely key based on letter frequencies.'''
    max_byte = 2 ** 8 - 1
    decoded_messages = {}
    frequency_table = {}

    d = {}
    #decode all message variants
    for key in range(0, max_byte):
        key = hex(key)[2:]
        try:
            decoded_messages[key] = binascii.unhexlify(single_byte_xor_decrypt(message, key)).decode('ascii')
            frequency_table[key] = analyze_char_freq(decoded_messages[key])
            score = score_char_freq(frequency_table[key])
            d[score] = decoded_messages[key]
        except UnicodeDecodeError:
            #some inavlid characters, so ignore this iteration
            pass

    return None if d == {} else d[min(d)]

def decrypt_repeating_key_xor(cyphertext, key):
    """Decrypts the cyphertext using the given key, using repeating xor cypher
    Assumes the cyphertext is already hex"""
    text = ""
    keycode = encode.repeating_key_loop(key)
    loc=0
    while loc < len(cyphertext):
        b = cyphertext[loc:loc+2]
        keybyte = next(keycode)
        htext = encode.xor(b, keybyte)
        if len(htext) < 2:  #ensure leading '0' if only a single digit returned
            htext = "0" + htext
        text += htext
        loc += 2
    return binascii.unhexlify(text)
