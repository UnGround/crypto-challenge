"""
encrypt or decrypt files using repeating key xor
"""
import argparse
import encode
import decryptor

parser = argparse.ArgumentParser(
    description='Encrypt or decrypt a given file using repeating key xor.')
parser.add_argument('file', type=argparse.FileType('r'),
                    help='the file to encrypt or decrypt')
parser.add_argument('key', type=str,
                    help='encryption key')
parser.add_argument('outfile', type=str,
                    help='file to output to')
parser.add_argument('-d', '--decrypt', action='store_true',
                    help='decrypt the file instead of encrypting it')

args = parser.parse_args()
outfile = open(args.outfile,'w', newline=None)

if args.decrypt:
    outfile.write(decryptor.decrypt_repeating_key_xor(args.file.read(), args.key).decode('ascii'))
else:
    outfile.write(encode.encrypt_repeating_key_xor(args.file.read(), args.key))
