import unittest 
import encode 

class TestEncodings(unittest.TestCase):

    def test_base64_encode(self):
        self.assertRaises(TypeError, encode.hex_to_base64, b'AE')
        self.assertRaises(TypeError, encode.hex_to_base64, 12)
        self.assertRaises(TypeError, encode.hex_to_base64, 'ABCDEFG')
        self.assertEqual(encode.hex_to_base64('4d616e'), 'TWFu')
        self.assertEqual(encode.hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'), 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

    def test_base64_decode(self):
        self.assertEqual(encode.base64_to_hex('TWFu').lower(), '4d616e')
        self.assertEqual(encode.base64_to_hex('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t').lower(), '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')

    def test_is_hex(self):
        self.assertTrue(encode.is_hex('0'))
        self.assertTrue(encode.is_hex('1'))
        self.assertTrue(encode.is_hex('2'))
        self.assertTrue(encode.is_hex('3'))
        self.assertTrue(encode.is_hex('4'))
        self.assertTrue(encode.is_hex('5'))
        self.assertTrue(encode.is_hex('6'))
        self.assertTrue(encode.is_hex('7'))
        self.assertTrue(encode.is_hex('8'))
        self.assertTrue(encode.is_hex('9'))
        self.assertTrue(encode.is_hex('A'))
        self.assertTrue(encode.is_hex('B'))
        self.assertTrue(encode.is_hex('C'))
        self.assertTrue(encode.is_hex('D'))
        self.assertTrue(encode.is_hex('E'))
        self.assertTrue(encode.is_hex('F'))
        self.assertTrue(encode.is_hex('AF'))
        self.assertTrue(encode.is_hex('23'))
        self.assertTrue(encode.is_hex('1A0F5'))
        self.assertTrue(encode.is_hex('A0F5DF'))
        self.assertTrue(encode.is_hex('A0F5D34FAB45Bc54Abcd12345002300Fd'))
        self.assertFalse(encode.is_hex('G'))
        self.assertFalse(encode.is_hex('Z'))
        self.assertFalse(encode.is_hex('FA00M'))
        self.assertFalse(encode.is_hex('&'))
        self.assertFalse(encode.is_hex(''))

    def test_is_b64_to_binary(self):
        self.assertEqual(encode.base64_to_binary('/'), '111111')
        self.assertEqual(encode.base64_to_binary('f'), '011111')
        self.assertEqual(encode.base64_to_binary('TWFu'), '010011010110000101101110')

    def test_binary_to_hex(self):
        self.assertEqual(encode.binary_to_hex('0100'), '4')
        self.assertEqual(encode.binary_to_hex('1101'), 'D')
        self.assertEqual(encode.binary_to_hex('010011010110000101101110'), '4D616E')
        self.assertEqual(encode.binary_to_hex('111111'), '3F') #can it handle dropped leading 0's?
        self.assertEqual(encode.binary_to_hex('100'), '4') #how about less than 4 bits?

    def test_xor(self):
        self.assertEqual(encode.xor('F0','0F'),'FF')
        self.assertEqual(encode.xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965').lower(), '746865206b696420646f6e277420706c6179')

    def test_repeating_key_xor_encode(self):
        test_text = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
        key = "ICE"
        result_crypt = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        self.assertEqual(encode.encrypt_repeating_key_xor(test_text, key).lower(), result_crypt.lower())


if __name__ == '__main__':
    unittest.main()