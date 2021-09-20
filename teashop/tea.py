#!/usr/bin/python3
import base64
import struct
import re
import argparse
import pathlib
import sys


##### Variables and stuff ##########################

default_key_as_list = re.findall('.', "iamsixteenchars!")
bytelike_key = bytes('', 'utf-8')
given_key = ''
key_based_cycles = 32
b64_block_segments = []


##### Argparse stuff ###############################

parser = argparse.ArgumentParser(description='Basic encryption/decryption tool using TEA.', epilog="For best practice, the key should be 16 characters. When decrypting, it adds a .dtea extension so it doesn't accidentally overwrite something important. The number of cycles (one cycle is two Feistel rounds) ran is based off the Unicode code of the first character of the key.")
parser.add_argument('-e', nargs=1, metavar='<file.ext>', help='Encrypt the given file with TEA. Adds a .tea extension.')
parser.add_argument('-d', nargs=1, metavar='<file.tea>', help='Decrypt the given file with TEA. Assumes a .tea extension.')
group = parser.add_mutually_exclusive_group()
group.add_argument('-k', nargs=1, metavar='<key>', help='Key used for encryption/decryption. Must be 16 chars or less.')
group.add_argument('-p', help='Prompts for the key. Easier to use special characters. Must be 16 chars or less.', action='store_true')
args = parser.parse_args()


def main():
    global bytelike_key
    global key_based_cycles
    global given_key

    # The key should be 16 chars, so replace however much of the default key with the given key
    if args.k is not None:
        given_key = args.k[0]
    elif args.p is True:
        given_key = input("Key: ")
    if (len(given_key) > 16):
        print("Key can't be longer than 16 characters!")
        sys.exit(1)
    else:
        given_key_as_list = re.findall('.', given_key)
        for c in range(len(given_key)):
            default_key_as_list[c] = given_key_as_list[c]
        key = "".join(default_key_as_list)
        bytelike_key = bytes(key, 'utf-8')
        key_based_cycles = ord(key[0])

    if args.e is not None:
        if pathlib.Path(str(args.e[0])).exists():
            encrypt(str(args.e[0]))
            print("Encryption done.")
        else:
            print("File to encrypt does not appear to exist. Please make sure it does.")
    elif args.d is not None:
        if pathlib.Path(str(args.d[0])).exists():
            decrypt(str(args.d[0]))
            print("Decryption done.")
        else:
            print("File to decrypt does not appear to exist. Please make sure it does.")
    else:
        parser.print_help()


###### TEA IMPLEMENTATION BETWEEN THESE LINES ######
####################################################

# Encryption function.
def tea_e(plaintext, key, cycles):
    # Setup
    v = struct.unpack("!2L",plaintext)
    v0, v1, s = v[0], v[1], 0

    # Key Schedule Constant
    delta = 2654435769

    # Cache Key
    k = struct.unpack("!4L",key)
    k0, k1, k2, k3 = k[0],k[1],k[2],k[3]

    count = 0
    while (count < cycles):
        count += 1
        s += delta
        v0 += ((v1<<4) + k0) ^ (v1 + s) ^ ((v1>>5) + k1)
        v1 += ((v0<<4) + k2) ^ (v0 + s) ^ ((v0>>5) + k3)
    v_as_list = [v0,v1]
    return v_as_list


# Decryption function.
def tea_d(ciphertext, key, cycles):
    # Setup
    v = ciphertext
    v0, v1, s = v[0], v[1], 2654435769 * cycles

    # Key Schedule Constant
    delta = 2654435769

    # Cache Key
    k = struct.unpack("!4L",key)
    k0, k1, k2, k3 = k[0],k[1],k[2],k[3]

    count = 0
    while (count < cycles):
        count += 1
        v1 -= ((v0<<4) + k2) ^ (v0 + s) ^ ((v0>>5) + k3)
        v0 -= ((v1<<4) + k0) ^ (v1 + s) ^ ((v1>>5) + k1)
        s -= delta

    # If the decryption doesn't work then the result wont pack, so we can easily error out.
    try:
        v = struct.pack("!2L",v0,v1)
    except:
        print("Wrong decryption key.")
        sys.exit(1)
    return v

####################################################
###### TEA IMPLEMENTATION BETWEEN THESE LINES ######


def encrypt(infile):
    with open(infile, 'rb') as f:
        enc_plaintext = base64.b64encode(f.read())
    # Regex to get 8 char chunks.  Decode/convert to string so regex eats it right.
    send_to_encrypt = re.findall('.{1,8}', str(enc_plaintext.decode('utf-8')))

    with open(infile + '.tea', 'w') as f:
        for block in send_to_encrypt:
            working_block = block
            # Has to be 8 bytes long for the struct unpacking, so add padding.
            while (len(working_block) < 8):
                working_block = working_block + "="
            # Re-byte-like it so the struct doesn't get mad.
            bytelike_block = bytes(working_block, 'utf-8')
            encrypted_block = tea_e(bytelike_block, bytelike_key, key_based_cycles)
            f.write(str(encrypted_block[0]) + "." + str(encrypted_block[1]) + "\n")


def decrypt(infile):
    with open(infile, 'r') as f:
        for block in f:
            # Split, strip the newline, then make the strs ints.
            working_block = block.split(".")
            working_block[1] = working_block[1][:-1]
            working_block[0] = int(working_block[0])
            working_block[1] = int(working_block[1])
            b64_block = tea_d(working_block, bytelike_key, key_based_cycles)
            b64_block_segments.append(b64_block.decode('utf-8'))

    with open(infile[:-4] + ".dtea", 'wb') as f:
        f.write(base64.b64decode("".join(b64_block_segments)))


main()
