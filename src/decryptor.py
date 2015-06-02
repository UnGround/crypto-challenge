import encode
import binascii
import sys
from collections import defaultdict
import math
import itertools
import crypt_utils
import base64
from Crypto.Cipher import AES

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
    if not crypt_utils.is_hex(message) or not crypt_utils.is_hex(key):
        raise TypeError("Error: message and key expected in Hex format")
    decode = ''
    for i in range(len(message), 0, -2):
        b = message[i-2:i]
        tmp = crypt_utils.xor(b, key)
        if len(tmp) < 2:
            tmp = '0' + tmp
        decode = tmp + decode
    return decode


def analyze_char_freq(string):
    """Generates a frequency table
    for each character in string"""
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


def score_char_freq(string, reference=english_letter_frequencies):
    '''return a score as to how much a string differs from the expected
    reference alphabet frequencies. A better score is closer to 0.
    That means that, over a large enough sample text run through
    analyze_char_freq and then scored, it should approach a score of 0.'''
    d1 = analyze_char_freq(string)
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
    '''searches for the most likely key based on letter frequencies.
    returns a (key, decoded_message) pair'''
    max_byte = 2 ** 8 - 1
    decoded_messages = {}

    d = {}
    k = {}
    #decode all message variants
    for key in range(0, max_byte):
        key = hex(key)[2:]
        try:
            decoded_messages[key] = binascii.unhexlify(single_byte_xor_decrypt(message, key)).decode('ascii')
            score = score_char_freq(decoded_messages[key])
            d[score] = decoded_messages[key]
            k[score] = key
        except UnicodeDecodeError:
            #some inavlid characters, so ignore this iteration
            pass

    return None if d == {} else (k[min(k)], d[min(d)])

def decrypt_repeating_key_xor(cyphertext, key):
    """Decrypts the cyphertext using the given key, using repeating xor cypher
    Assumes the cyphertext is already hex"""
    text = ""
    keycode = encode.repeating_key_loop(key)
    loc = 0
    while loc < len(cyphertext):
        b = cyphertext[loc:loc+2]
        keybyte = next(keycode)
        htext = crypt_utils.xor(b, keybyte)
        if len(htext) < 2:  # ensure leading '0' if only a single digit returned
            htext = "0" + htext
        text += htext
        loc += 2
    return binascii.unhexlify(text)


###############################
# to break Vigenere cyphers                             #
###############################


def get_vigenere_key_score(ciphertext, keysize, compare_blocks=4):
    """returns the score for this keysize on this text"""
    hdist = 0
    blocks = vigenere_blocks(ciphertext, keysize, compare_blocks)
    comparisons = 0
    for b1, b2 in itertools.combinations(blocks, 2):
        hdist += crypt_utils.hamming_distance(b1, b2)
        comparisons += 1

    hdist = hdist / comparisons

    return hdist / keysize


def generate_vigenere_key_sizes(ciphertext, min_size=2, max_size=80, compare_blocks=4, nresults=4, include_scores=False):
    """Generate nresults worth of likely key sizes based on hamming differences.
    """
    key_scores = {}
    for keysize in range(min_size, max_size):
        key_scores[keysize] = get_vigenere_key_score(ciphertext, keysize, compare_blocks)

    sizes = sorted(key_scores, key=key_scores.__getitem__)[:nresults]
    if include_scores:
        return {i:key_scores[i] for i in sizes}
    return sorted(key_scores, key=key_scores.__getitem__)[:nresults]


def vigenere_blocks(cyphertext, keysize, max_blocks=None):
    """break the cypher into n keysize blocks.
    If max_blocks is set, returns only the first max_blocks"""
    if max_blocks is None:
        max_blocks = len(cyphertext)
    else:
        max_blocks = max_blocks * keysize
    return [cyphertext[l:l+keysize] for l in range(0, max_blocks, keysize)]


def vigenere_transpose(blocks):
    """returns a list of blocks that are all encoded with the same key"""
    trans = list(map(list, itertools.zip_longest(*blocks, fillvalue='')))
    return list(map(''.join, trans))


def crack_vigenere(cyphertext):
    if not crypt_utils.is_hex(cyphertext):
        cyphertext = crypt_utils.toHex(cyphertext)

    keysizes = generate_vigenere_key_sizes(cyphertext)
    options = {}

    for keysize in keysizes:
        blocks = vigenere_blocks(cyphertext, keysize)
        try:
            # Chunk the hex strings into 8 bit lengths (2 Hex digits)
            # Otherwise transpose would split bytes incorrectly
            blocks = [[s[i] + s[i+1] for i in range(0, len(s), 2)] for s in blocks]
        except IndexError:
            # blocks contain invalid Hex, so assume this is not the solution
            continue
        blocks = vigenere_transpose(blocks)

        decrypted_message = []
        key = ''

        for block in blocks:
            key_byte, message_part = search_single_byte_xor_key(block)
            decrypted_message.append(message_part)
            key += key_byte

        decrypted_message = vigenere_transpose(decrypted_message)
        decrypted_message = ''.join(decrypted_message)
        score = score_char_freq(decrypted_message)
        try:
            key = binascii.unhexlify(key).decode('ascii')
        except:
            #if key cannot be converted to ascii, leave as is
            pass
        options[score] = (key, decrypted_message)

    return options[min(options)]


###############################
# AES                                                                   #
###############################

def decrypt_aes_ecb(message, key, b64=False):
    """decrypts the message using the key in AES 
    using ECB block mode
    """
    if b64:
        message = base64.b64decode(message)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(message)


def find_AES_ECB(messages):
    """detect which message was likely encrypted
    with ECB"""
    scores = {}
    for message in messages:
        scores[message] = get_vigenere_key_score(message, 32)

    return sorted(scores, key=scores.__getitem__)[0]
