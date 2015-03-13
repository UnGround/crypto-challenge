'''solution to challenge 1.4, detects single byte xor, then returns the decrypted string.'''

import sys
import decryptor

def detect_xor(file_name):
    f = open(file_name, 'r')
    d = {}

    for line in f:
        line = line.rstrip().lstrip()
        candidate = decryptor.search_single_byte_xor_key(line)
        if candidate is None:
            continue

        freq = decryptor.analyze_char_freq(candidate)
        score = decryptor.score_char_freq(freq)
        d[score] = candidate
    
    return d[min(d)]

print(detect_xor('../challenges/set1/1.4.txt'))