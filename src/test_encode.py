import unittest 
import encode 

class TestEncodings(unittest.TestCase):

    def test_base64_encode(self):
        self.assertRaises(TypeError, encode.hex_to_base64, 12)
        self.assertRaises(TypeError, encode.hex_to_base64, 'ABCDEFG')
        self.assertEqual(encode.hex_to_base64('4d616e'), 'TWFu')
        self.assertEqual(encode.hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'), 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

    def test_base64_decode(self):
        self.assertEqual(encode.base64_to_hex('TWFu').lower(), '4d616e')
        self.assertEqual(encode.base64_to_hex('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t').lower(), '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')

    def test_b64_to_binary(self):
        self.assertEqual(encode.base64_to_binary('TWFu'), '010011010110000101101110')

    def test_repeating_key_xor_encode(self):
        test_text = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
        key = "ICE"
        result_crypt = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        self.assertEqual(encode.encrypt_repeating_key_xor(test_text, key).lower(), result_crypt.lower())


if __name__ == '__main__':
    unittest.main()