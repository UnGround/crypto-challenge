import unittest
import crypt_utils


class TestCryptUtils(unittest.TestCase):

    def test_hamming_distance(self):
        s1 = "this is a test"
        s2 = "wokka wokka!!!"
        h_dist = crypt_utils.hamming_distance(s1, s2)
        self.assertEqual(h_dist, 37)

    def test_binary_to_hex(self):
        self.assertEqual(crypt_utils.binary_to_hex('0100'), '4')
        self.assertEqual(crypt_utils.binary_to_hex('1101'), 'D')
        self.assertEqual(crypt_utils.binary_to_hex('010011010110000101101110'), '4D616E')
        self.assertEqual(crypt_utils.binary_to_hex('111111'), '3F') #can it handle dropped leading 0's?
        self.assertEqual(crypt_utils.binary_to_hex('100'), '4') #how about less than 4 bits?

    def test_xor(self):
        self.assertEqual(crypt_utils.xor('F0','0F'),'FF')
        self.assertEqual(crypt_utils.xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965').lower(), '746865206b696420646f6e277420706c6179')

    def test_is_hex(self):
        self.assertTrue(crypt_utils.is_hex('0'))
        self.assertTrue(crypt_utils.is_hex('1'))
        self.assertTrue(crypt_utils.is_hex('2'))
        self.assertTrue(crypt_utils.is_hex('3'))
        self.assertTrue(crypt_utils.is_hex('4'))
        self.assertTrue(crypt_utils.is_hex('5'))
        self.assertTrue(crypt_utils.is_hex('6'))
        self.assertTrue(crypt_utils.is_hex('7'))
        self.assertTrue(crypt_utils.is_hex('8'))
        self.assertTrue(crypt_utils.is_hex('9'))
        self.assertTrue(crypt_utils.is_hex('A'))
        self.assertTrue(crypt_utils.is_hex('B'))
        self.assertTrue(crypt_utils.is_hex('C'))
        self.assertTrue(crypt_utils.is_hex('D'))
        self.assertTrue(crypt_utils.is_hex('E'))
        self.assertTrue(crypt_utils.is_hex('F'))
        self.assertTrue(crypt_utils.is_hex('AF'))
        self.assertTrue(crypt_utils.is_hex('23'))
        self.assertTrue(crypt_utils.is_hex('1A0F5'))
        self.assertTrue(crypt_utils.is_hex('A0F5DF'))
        self.assertTrue(crypt_utils.is_hex('A0F5D34FAB45Bc54Abcd12345002300Fd'))
        self.assertFalse(crypt_utils.is_hex('G'))
        self.assertFalse(crypt_utils.is_hex('Z'))
        self.assertFalse(crypt_utils.is_hex('FA00M'))
        self.assertFalse(crypt_utils.is_hex('&'))
        self.assertFalse(crypt_utils.is_hex(''))

if __name__ == '__main__':
    unittest.main()
