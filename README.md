# Teashop

Teashop is a multi-function python3 script that can encrypt files, decrypt files, attach a crypter to a file, or build a collection of individual modules into a single encrypted script for easy transport/use later. All encryption is done with Tiny Encryption Algorithm (TEA) using just the python standard library, so you shouldn't need to bring anything extra with you. This also lets the little snippet of code ontop of the encrypted file stay nice and short.

This was created to be used as a training aid for my students.

### What's Inside

**teashop.py** - The main script. You can see how it works with the following commands:
```
./teashop.py -h
```
```
./teashop.py -e sample.txt -k abcd
```
```
./teashop.py -d sample.txt.tea -k abcd
```
```
./teashop.py -t hello_world.py -k abcd
```
```
./teashop.py -b -k abcd
```

**tea.py** - This script can just encrypt or decrypt files.
```
./tea.py -e sample.txt -k abcd
```
```
./tea.py -d sample.txt.tea -k abcd
```

**looseleaftea.py** - The only thing this file contains are the TEA encrypt and decrypt functions.

### Additional Notes

1. The number of cycles ran (one cycle is two Feistel rounds) is based on the Unicode value of the first character in the password. I did this because I wanted an easy way to change how many cycles are ran without needing to add another argument. The recommended amount of cycles is 32, and luckily the lowest character likely to be used as the first character in a key is !, which has a code of 33.

2. From a forensics standpoint, there is a flaw with teatags and teaboxes. During transport they are encrypted, however they do write the executable code on target when they are executed. When the temp file that is being executed is cleaned up, it is not shreded. That means it should be relatively easy to recover with basic digital forensics tools/knowldege. I know the shred command exists, but I would consider it non-standard. I will probably add the ability to shred the temp file later, but for now my students don't have the ability to forensically analyze the disk.

