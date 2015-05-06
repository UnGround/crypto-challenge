import unittest
import binascii

import decryptor
import encode

class TestDecrypt(unittest.TestCase):

    def test_xor_single_byte_decode(self):
        source_str = binascii.hexlify(b'A').decode('ascii')
        key = binascii.hexlify(b'B').decode('ascii')
        crypt = encode.xor(source_str, key)
        self.assertEqual(decryptor.single_byte_xor_decrypt(crypt, key), source_str)
        source_str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        key = binascii.hexlify(b'h').decode('ascii')
        crypt = ''.join(encode.xor(binascii.hexlify(bytes(c, 'ascii')).decode('ascii'), key) for c in source_str)
        self.assertEqual(decryptor.single_byte_xor_decrypt(crypt, key), binascii.hexlify(bytes(source_str,'ascii')).decode('ascii').upper())

    def test_analyze_char_freq(self):
        self.assertEqual(decryptor.analyze_char_freq('ABCD'), {'A': 25, 'B': 25, 'C': 25, 'D': 25})
        self.assertEqual(decryptor.analyze_char_freq('abcd'), {'A': 25, 'B': 25, 'C': 25, 'D': 25})
        self.assertEqual(decryptor.analyze_char_freq('AbCd'), {'A': 25, 'B': 25, 'C': 25, 'D': 25})
        self.assertEqual(decryptor.analyze_char_freq('AABCD'), {'A': 40, 'B': 20, 'C': 20, 'D': 20})
        self.assertEqual(decryptor.analyze_char_freq('KAABCD?/DA'), {'A': 30, 'B': 10, 'C': 10, 'D': 20, 'K': 10, '?': 10, '/': 10})

    def test_score_char_freq(self):
        self.assertEqual(decryptor.score_char_freq(decryptor.english_letter_frequencies), 0)
        self.assertEqual(decryptor.score_char_freq({'/':1}), 1*10)

    def test_search_single_byte_xor_key(self):
        self.assertEqual(decryptor.search_single_byte_xor_key('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'), "Cooking MC's like a pound of bacon")
        self.assertEqual(decryptor.search_single_byte_xor_key('0e3647e8592d35514a081243582536ed3de6734059001e3f535ce6271032'), None)

    def test_decrypt_repeating_key_xor(self):
        cyphertext="0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        key = "ICE"
        text = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
        self.assertEqual(decryptor.decrypt_repeating_key_xor(cyphertext, key), text)


if __name__ == "__main__":
    unittest.main()