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

parser = argparse.ArgumentParser(description='Create teatag or teabox files. They are like packed files, but with encryption not compression. Also has the ability to just encrypt files with TEA.', epilog="For best practice, the key should be 16 characters. The number of cycles (one cycle is two Feistel rounds) ran is based off the Unicode code of the first character of the key.")
parser.add_argument('-e', nargs=1, metavar='<file.ext>', help='Encrypt the given file with TEA. Adds a .tea extension.')
parser.add_argument('-d', nargs=1, metavar='<file.tea>', help='Decrypt the given file with TEA. Assumes a .tea extension.')
parser.add_argument('-t', nargs=1, metavar='<file.ext>', help='Make a teatag of the given file.')
parser.add_argument('-b', help='Make a teabox with all the files in the ./teabox directory. Creates ./packed.teabox', action='store_true')
group = parser.add_mutually_exclusive_group()
group.add_argument('-k', nargs=1, metavar='<key>', help='Key used for encryption/decryption. Must be 16 chars or less.')
group.add_argument('-p', help='Prompts for the key. Easier to use special characters. Must be 16 chars or less.', action='store_true')
args = parser.parse_args()


def main():
    global bytelike_key
    global key_based_cycles
    global given_key

    # The key should be 16 chars, so we overwrite part of the default key with the given key.  Basically we are padding the given key to 16.
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

    # Start doing whatever the user wanted to do.  It's written so some arguments take priority over others.
    if args.t is not None:
        if pathlib.Path(str(args.t[0])).exists():
            tag(str(args.t[0]))
            print("Teatag created.")
        else:
            print("File to teatag does not appear to exist. Please make sure it does.")
            sys.exit(1)
    elif args.b is True:
        if pathlib.Path("./teabox").exists():
            box()
            print("Teabox created.")
        else:
            print("Could not find ./teabox. Please make sure it exists.")
            sys.exit(1)
    elif args.e is not None:
        if pathlib.Path(str(args.e[0])).exists():
            encrypt(str(args.e[0]))
            print("Encryption done.")
        else:
            print("File to encrypt does not appear to exist. Please make sure it does.")
            sys.exit(1)
    elif args.d is not None:
        if pathlib.Path(str(args.d[0])).exists():
            decrypt(str(args.d[0]))
            print("Decryption done.")
        else:
            print("File to decrypt does not appear to exist. Please make sure it does.")
            sys.exit(1)
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


def tag(infile):
    with open(infile, 'rb') as f:
        enc_plaintext = base64.b64encode(f.read())
    # Regex to get 8 char chunks. Decode/convert to string so regex eats it right.
    send_to_encrypt = re.findall('.{1,8}', str(enc_plaintext.decode('utf-8')))

    with open(infile + '.teatag', 'w') as f:
        encrypted_block_list = []
        for block in send_to_encrypt:
            working_block = block
            # Has to be 8 bytes long for the struct unpacking, so add padding.
            while (len(working_block) < 8):
                working_block = working_block + "="
            # Re-byte-like it so the struct doesn't get mad.
            bytelike_block = bytes(working_block, 'utf-8')
            encrypted_block = tea_e(bytelike_block, bytelike_key, key_based_cycles)
            encrypted_block_list.append(str(encrypted_block[0]) + "." + str(encrypted_block[1]))
        f.write("#!/usr/bin/python3\n")
        f.write("encrypted_blocks = ['" + "','".join(encrypted_block_list) + "']\n")
        f.write(decrypt_stub)
    pathlib.Path(infile + ".teatag").chmod(0o777)


def box():
    if pathlib.Path("packed.teabox").exists():
        print("A packed.teabox already exists, aborting. Please delete it before trying again.")
        sys.exit(1)

    available_modules = []

    # Write all the modules in ./teabox to a temp file after writing a shebang and import.
    with open("temp.teabox", 'w') as f:
        f.write("#!/usr/bin/python3\nimport sys\n")
    for infile in pathlib.Path("./teabox").glob("*"):
        available_modules.append(str(infile)[7:])
        with open(str(infile), 'r') as f:
            data_to_write = f.read()
        with open("temp.teabox", 'a') as f:
            f.write("\n" + data_to_write + "\n")

    # Write the list of modules and teabox stub to the temp file.
    with open("temp.teabox", 'a') as f:
        f.write("\navailable_modules = ['" + "','".join(available_modules) + "']\n")
        f.write("\n" + teabox_stub + "\n")

    # Encrypt and make the teabox.
    with open("temp.teabox", 'rb') as f:
        enc_plaintext = base64.b64encode(f.read())
    # Regex to get 8 char chunks.  Decode/convert to string so regex eats it right.
    send_to_encrypt = re.findall('.{1,8}', str(enc_plaintext.decode('utf-8')))

    with open("packed.teabox", 'w') as f:
        encrypted_block_list = []
        for block in send_to_encrypt:
            working_block = block
            # Has to be 8 bytes long for the struct unpacking, so add padding.
            while (len(working_block) < 8):
                working_block = working_block + "="
            # Re-byte-like it so the struct doesn't get mad.
            bytelike_block = bytes(working_block, 'utf-8')
            encrypted_block = tea_e(bytelike_block, bytelike_key, key_based_cycles)
            encrypted_block_list.append(str(encrypted_block[0]) + "." + str(encrypted_block[1]))
        f.write("#!/usr/bin/python3\n")
        f.write("encrypted_blocks = ['" + "','".join(encrypted_block_list) + "']\n")
        f.write(decrypt_stub)
    pathlib.Path("packed.teabox").chmod(0o777)
    pathlib.Path("temp.teabox").unlink()


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


decrypt_stub = """import base64
import re
import struct
import os
import sys
default_key_as_list = re.findall('.', "iamsixteenchars!")
bytelike_key = bytes('', 'utf-8')
key_based_cycles = 32
b64_block_segments = []

given_key = input("Key: ")

def tea_d(ciphertext, key, cycles):
    v = ciphertext
    v0, v1, s = v[0], v[1], 2654435769 * cycles
    delta = 2654435769
    k = struct.unpack("!4L",key)
    k0, k1, k2, k3 = k[0],k[1],k[2],k[3]
    count = 0
    while (count < cycles):
        count += 1
        v1 -= ((v0<<4) + k2) ^ (v0 + s) ^ ((v0>>5) + k3)
        v0 -= ((v1<<4) + k0) ^ (v1 + s) ^ ((v1>>5) + k1)
        s -= delta
    try:
        v = struct.pack("!2L",v0,v1)
    except:
        print("Wrong decryption key.")
        sys.exit(1)
    return v

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

for block in encrypted_blocks:
    working_block = block.split(".")
    working_block[1] = working_block[1]
    working_block[0] = int(working_block[0])
    working_block[1] = int(working_block[1])
    b64_block = tea_d(working_block, bytelike_key, key_based_cycles)
    b64_block_segments.append(b64_block.decode('utf-8'))

with open("teatag.lib", 'wb') as f:
    f.write(base64.b64decode("".join(b64_block_segments)))

os.system("chmod 777 teatag.lib")
os.system("./teatag.lib")
os.system("shred -uz teatag.lib")"""


teabox_stub = """available_modules.append("quit")

def quit():
    sys.exit(0)

print("Teabox opened successfully!")

while True:
    print("")
    print("Available Modules: " + ", ".join(available_modules))
    module_to_run = input("Enter Module: ")
    eval(module_to_run + "()")
"""


main()
