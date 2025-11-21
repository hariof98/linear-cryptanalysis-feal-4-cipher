## Requirements

- GCC compiler
- Makefile
- known.txt file with plaintext-ciphertext pairs

## Build

make
./feal_ready known.txt

## Files

- `attack.c` - Main cryptanalysis code
- `cipher.c` - FEAL-4 cipher functions
- `data.c` - Data loading functions
- `known.txt` - 200 plaintext-ciphertext pairs (input)

## Output

Finds all 6 subkeys (K0-K5):
0x63cab942 0x00a0c541 0x4674095a 0x64204c03 0x4b37d10a 0xd0a24877
