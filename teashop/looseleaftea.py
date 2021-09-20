#!/usr/bin/python3
import struct
import sys

# If you found my github because you were just looking for a simple python implementation of TEA, here you go!
# These are just the functions that actually do the encryption, without the data handling of my other scripts.

# I'm not like an encryption doctor or anything.  I'm more like a low-calorie idiot sandwich.
# If you want to use this for some important stuff, double check my work.

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
    # You may want to handle the exception in a way that doesn't exit the script, so adjust as needed.
    try:
        v = struct.pack("!2L",v0,v1)
    except:
        print("Wrong decryption key.")
        sys.exit(1)
    return v

####################################################
###### TEA IMPLEMENTATION BETWEEN THESE LINES ######
