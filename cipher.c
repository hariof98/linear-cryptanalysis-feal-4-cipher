/*
 * feal-4 block cipher main operations,
 * provides encryption/decryption functions for cryptanalysis
*/

typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

// feal-4 constants
#define FEAL_ROUNDS 4

// rotate left by 2 bits (circular shift)
#define ROTATE_LEFT_2(x) (((x) << 2) | ((x) >> 6))

// feal S-box operations
#define SBOX_0(a, b) (ROTATE_LEFT_2((uint8_t)((a) + (b))))
#define SBOX_1(a, b) (ROTATE_LEFT_2((uint8_t)((a) + (b) + 1)))

// converting 4 bytes to 32-bit word
uint32_t bytesToWord32(const uint8_t *bytes) {
    return (uint32_t)bytes[3] | 
           ((uint32_t)bytes[2] << 8) | 
           ((uint32_t)bytes[1] << 16) | 
           ((uint32_t)bytes[0] << 24);
}

// converting 32-bit word to 4 bytes 
void word32ToBytes(uint32_t word, uint8_t *bytes) {
    bytes[0] = (uint8_t)(word >> 24);
    bytes[1] = (uint8_t)(word >> 16);
    bytes[2] = (uint8_t)(word >> 8);
    bytes[3] = (uint8_t)word;
}

// feal f-function: core nonlinear transformation
uint32_t fealFFunction(uint32_t input) {
    uint8_t inputBytes[4];
    uint8_t outputBytes[4];
    
    word32ToBytes(input, inputBytes);
    
    outputBytes[1] = SBOX_1(inputBytes[1] ^ inputBytes[0], 
                             inputBytes[2] ^ inputBytes[3]);
    outputBytes[0] = SBOX_0(inputBytes[0], outputBytes[1]);
    outputBytes[2] = SBOX_0(outputBytes[1], 
                             inputBytes[2] ^ inputBytes[3]);
    outputBytes[3] = SBOX_1(outputBytes[2], inputBytes[3]);
    
    return bytesToWord32(outputBytes);
}

// feal-4 decryption function
void fealDecryptBlock(uint8_t ciphertext[8], const uint32_t subkeys[6]) {
    uint32_t leftHalf, rightHalf, temp;
    
    rightHalf = bytesToWord32(&ciphertext[0]) ^ subkeys[4];
    leftHalf = rightHalf ^ bytesToWord32(&ciphertext[4]) ^ subkeys[5];
    
    for (int round = 0; round < FEAL_ROUNDS; round++) {
        temp = leftHalf;
        leftHalf = rightHalf ^ fealFFunction(leftHalf ^ subkeys[FEAL_ROUNDS - 1 - round]);
        rightHalf = temp;
    }
    
    rightHalf ^= leftHalf;
    word32ToBytes(leftHalf, &ciphertext[0]);
    word32ToBytes(rightHalf, &ciphertext[4]);
}
