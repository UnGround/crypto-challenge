import unittest
import binascii
import base64

import decryptor
import encode
import crypt_utils

class TestDecrypt(unittest.TestCase):

    def test_xor_single_byte_decode(self):
        source_str = binascii.hexlify(b'A').decode('ascii')
        key = binascii.hexlify(b'B').decode('ascii')
        crypt = crypt_utils.xor(source_str, key)
        self.assertEqual(decryptor.single_byte_xor_decrypt(crypt, key), source_str)
        source_str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        key = binascii.hexlify(b'h').decode('ascii')
        crypt = ''.join(crypt_utils.xor(binascii.hexlify(bytes(c, 'ascii')).decode('ascii'), key) for c in source_str)
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
        key, message = decryptor.search_single_byte_xor_key('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
        self.assertEqual(message, "Cooking MC's like a pound of bacon")
        self.assertEqual(decryptor.search_single_byte_xor_key('0e3647e8592d35514a081243582536ed3de6734059001e3f535ce6271032'), None)

    def test_decrypt_repeating_key_xor(self):
        cyphertext="0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        key = "ICE"
        text = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
        self.assertEqual(decryptor.decrypt_repeating_key_xor(cyphertext, key), text)

    def test_vigenere_blocks(self):
        """Test that blocks are created correctly based on keysize"""
        cyphertext = '350A1A47415E154100061E190B1E15501F141D174C1B060641'
        expected_result = ['350A1A4741',
                           '5E15410006',
                           '1E190B1E15',
                           '501F141D17',
                           '4C1B060641']
        self.assertEqual(decryptor.vigenere_blocks(cyphertext, 10), expected_result)

    def test_vigenere_transpose(self):
        initial = ['350A1A4741',
                       '5E15410006',
                       '1E190B1E15',
                       '501F141D17',
                       '4C1B060641']
        expected_result = ['35154',
                             '5EE0C',
                             '01111',
                             'A59FB',
                             '14010',
                             'A1B46',
                             '40110',
                             '70ED6',
                             '40114',
                             '16571']
        self.assertEqual(decryptor.vigenere_transpose(initial), expected_result)

    def test_break_vigenere(self):
        """test that we can break vignere"""
        f = open('../challenges/set1/1.6.txt')
        cyphertext = f.read()
        cyphertext = cyphertext.replace('\n','')
        cyphertext = base64.standard_b64decode(cyphertext)
        key, text = decryptor.crack_vigenere(cyphertext)
        self.assertEqual(key, 'Terminator X: Bring the noise')
        f.close()


if __name__ == "__main__":
    unittest.main()