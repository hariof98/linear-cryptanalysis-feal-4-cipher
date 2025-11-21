/*
 * linear cryptanalysis attack on FEAL-4,
 * recovers secret sub-keys K0 through K5 using linear approximations,
 * 
 * this implementation uses a divide-and-conquer approach, searching for
 * 12-bit inner key candidates first, then 20-bit outer key candidates,
 * significantly reducing the search space complexity
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <time.h>
 
 typedef unsigned int uint32_t;
 typedef unsigned char uint8_t;
 
 extern uint32_t bytesToWord32(const uint8_t *bytes);
 extern void word32ToBytes(uint32_t word, uint8_t *bytes);
 extern uint32_t fealFFunction(uint32_t input);
 extern void fealDecryptBlock(uint8_t ciphertext[8], const uint32_t subkeys[6]);
 
 extern int getPairCount(void);
 extern uint32_t getPlaintextLeft(int index);
 extern uint32_t getPlaintextRight(int index);
 extern uint32_t getCiphertextLeft(int index);
 extern uint32_t getCiphertextRight(int index);
 extern int loadKnownPairs(const char *filename);
 extern void cleanupPairData(void);
 
 // configuring attack parameters
 #define MAX_VALID_KEYS 256
 #define INNER_KEY_BITS 12
 #define OUTER_KEY_BITS 20
 #define INNER_KEY_SPACE (1 << INNER_KEY_BITS)  // 4096 possibilities
 #define OUTER_KEY_SPACE (1 << OUTER_KEY_BITS)  // 1048576 possibilities
 
 // initial attack state
 static int validKeysDiscovered = 0;
 static clock_t attackStartTime = 0;
 
 static void processKey0Candidate(uint32_t k0);
 static void processKey1Candidate(uint32_t k0, uint32_t k1);
 static void processKey2Candidate(uint32_t k0, uint32_t k1, uint32_t k2);
 static void processKey3Candidate(uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3);
 static int deriveAndValidateKey(uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3);
 
 /*
  * extracting a specific bit from a 32-bit word
  * bit numbering: S0 is msb (bit 31), S31 is lsb (bit 0)
 */
 static int getBitAtPosition(uint32_t value, int sPosition) {
     return (value >> (31 - sPosition)) & 1;
 }
 
 /*
  * extracting and XORing multiple bits (for S7,15,23,31 notation)
 */
 static int getMultipleBits(uint32_t value, int pos1, int pos2, int pos3, int pos4) {
     return getBitAtPosition(value, pos1) ^ 
            getBitAtPosition(value, pos2) ^ 
            getBitAtPosition(value, pos3) ^ 
            getBitAtPosition(value, pos4);
 }
 
 /*
  * extracting and XORing three bits (for S5,13,21 notation)
  */
 static int getThreeBits(uint32_t value, int pos1, int pos2, int pos3) {
     return getBitAtPosition(value, pos1) ^ 
            getBitAtPosition(value, pos2) ^ 
            getBitAtPosition(value, pos3);
 }
 
 /*
  * constructing 12-bit inner key candidate (middle bytes)
  */
 static uint32_t constructInnerKeyCandidate(int candidate) {
     uint32_t byte1 = ((candidate >> 6) & 0x3F) << 16;
     uint32_t byte2 = (candidate & 0x3F) << 8;
     return byte1 | byte2;
 }
 
 /*
  * constructing 20-bit outer key candidate (first and last bytes)
  */
 static uint32_t constructOuterKeyCandidate(int candidate, uint32_t innerKey) {
     int a0 = (((candidate & 0xF) >> 2) << 6) + ((innerKey >> 16) & 0xFF);
     int a1 = ((candidate & 0x3) << 6) + ((innerKey >> 8) & 0xFF);
     int b0 = (candidate >> 12) & 0xFF;
     int b3 = (candidate >> 4) & 0xFF;
     int b1 = b0 ^ a0;
     int b2 = b3 ^ a1;
 
     return ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) | 
            ((uint32_t)b2 << 8) | (uint32_t)b3;
 }
 
 /*
  * linear approximation for K0 inner bytes
  * equation: S5,13,21(L0⊕R0⊕L4) ⊕ S15(L0⊕L4⊕R4) ⊕ S15 F(L0⊕R0⊕K0)
  */
 static int linearApproxK0Inner(int pairIdx, uint32_t keyCandidate) {
     uint32_t pLeft = getPlaintextLeft(pairIdx); // L0
     uint32_t pRight = getPlaintextRight(pairIdx); // R0
     uint32_t cLeft = getCiphertextLeft(pairIdx); // L4
     uint32_t cRight = getCiphertextRight(pairIdx); // R4
     
     uint32_t val1 = pLeft ^ pRight ^ cLeft; // L0⊕R0⊕L4
     int term1 = getThreeBits(val1, 5, 13, 21); // S5,13,21(L0⊕R0⊕L4)
     
     uint32_t val2 = pLeft ^ cLeft ^ cRight; // L0⊕L4⊕R4
     int term2 = getBitAtPosition(val2, 15); // S15(L0⊕L4⊕R4)
     
     uint32_t fOutput = fealFFunction(pLeft ^ pRight ^ keyCandidate); // F(L0⊕R0⊕K0)
     int term3 = getBitAtPosition(fOutput, 15); // S15 F(L0⊕R0⊕K0)
     
     return term1 ^ term2 ^ term3; // S5,13,21(L0⊕R0⊕L4) ⊕ S15(L0⊕L4⊕R4) ⊕ S15 F(L0⊕R0⊕K0)
 }
 
 /*
  * linear approximation for K0 outer bytes
  * equation: S13(L0⊕R0⊕L4) ⊕ S7,15,23,31(L0⊕L4⊕R4) ⊕ S7,15,23,31 F(L0⊕R0⊕K0)
  */
 static int linearApproxK0Outer(int pairIdx, uint32_t keyCandidate) {
     uint32_t pLeft = getPlaintextLeft(pairIdx); // L0
     uint32_t pRight = getPlaintextRight(pairIdx); // R0
     uint32_t cLeft = getCiphertextLeft(pairIdx); // L4
     uint32_t cRight = getCiphertextRight(pairIdx); // R4
     
     uint32_t val1 = pLeft ^ pRight ^ cLeft; // L0⊕R0⊕L4
     int term1 = getBitAtPosition(val1, 13); // S13(L0⊕R0⊕L4)
     
     uint32_t val2 = pLeft ^ cLeft ^ cRight; // L0⊕L4⊕R4
     int term2 = getMultipleBits(val2, 7, 15, 23, 31); // S7,15,23,31(L0⊕L4⊕R4)
     
     uint32_t fOutput = fealFFunction(pLeft ^ pRight ^ keyCandidate); // F(L0⊕R0⊕K0)    
     int term3 = getMultipleBits(fOutput, 7, 15, 23, 31); // S7,15,23,31 F(L0⊕R0⊕K0)
     
     return term1 ^ term2 ^ term3; // S13(L0⊕R0⊕L4) ⊕ S7,15,23,31(L0⊕L4⊕R4) ⊕ S7,15,23,31 F(L0⊕R0⊕K0)
 }
 
 /*
  * linear approximation for K1 inner bytes (middle bytes)
  */
 static int linearApproxK1Inner(int pairIdx, uint32_t keyCandidate, uint32_t k0) {
     uint32_t pLeft = getPlaintextLeft(pairIdx); // L0
     uint32_t pRight = getPlaintextRight(pairIdx); // R0
     uint32_t cLeft = getCiphertextLeft(pairIdx); // L4
     uint32_t cRight = getCiphertextRight(pairIdx); // R4
     
     uint32_t val1 = pLeft ^ cLeft ^ cRight; // L0⊕L4⊕R4
     int term1 = getThreeBits(val1, 5, 13, 21); // S5,13,21(L0⊕L4⊕R4)
     
     uint32_t y0 = fealFFunction(pLeft ^ pRight ^ k0); // F(L0⊕R0⊕K0)
     uint32_t fOutput = fealFFunction(pLeft ^ y0 ^ keyCandidate); // F(L0⊕Y0⊕K1)
     int term2 = getBitAtPosition(fOutput, 15); // S15 F(L0⊕Y0⊕K1)  
     
     return term1 ^ term2; // S5,13,21(L0⊕L4⊕R4) ⊕ S15 F(L0⊕Y0⊕K1)
 }
 
 /*
  * linear approximation for K1 outer bytes (first and last bytes)
  */
 static int linearApproxK1Outer(int pairIdx, uint32_t k0, uint32_t k1) {
     uint32_t pLeft = getPlaintextLeft(pairIdx); // L0
     uint32_t pRight = getPlaintextRight(pairIdx); // R0
     uint32_t cLeft = getCiphertextLeft(pairIdx); // L4 
     uint32_t cRight = getCiphertextRight(pairIdx); // R4
     
     uint32_t val1 = pLeft ^ cLeft ^ cRight; // L0⊕L4⊕R4
     int term1 = getBitAtPosition(val1, 13);
     
     uint32_t y0 = fealFFunction(pLeft ^ pRight ^ k0); // F(L0⊕R0⊕K0)
     uint32_t y1 = fealFFunction(pLeft ^ y0 ^ k1); // F(L0⊕Y0⊕K1)
     int term2 = getMultipleBits(y1, 7, 15, 23, 31); // S7,15,23,31(L0⊕Y0⊕K1)
     
     return term1 ^ term2; // S13(L0⊕L4⊕R4) ⊕ S7,15,23,31(L0⊕Y0⊕K1)
 }
 
 /*
  * linear approximation for K2 inner bytes (middle bytes)
  */
 static int linearApproxK2Inner(int pairIdx, uint32_t keyCandidate, 
                                 uint32_t k0, uint32_t k1) {
     uint32_t pLeft = getPlaintextLeft(pairIdx); // L0      
     uint32_t pRight = getPlaintextRight(pairIdx); // R0
     uint32_t cLeft = getCiphertextLeft(pairIdx); // L4
     
     uint32_t val1 = pLeft ^ pRight ^ cLeft; // L0⊕R0⊕L4
     int term1 = getThreeBits(val1, 5, 13, 21); // S5,13,21(L0⊕R0⊕L4)
     
     uint32_t y0 = fealFFunction(pLeft ^ pRight ^ k0); // F(L0⊕R0⊕K0)
     uint32_t y1 = fealFFunction(pLeft ^ y0 ^ k1);
     uint32_t fOutput = fealFFunction(pLeft ^ pRight ^ y1 ^ keyCandidate); // F(L0⊕R0⊕Y1⊕K2)
     int term2 = getBitAtPosition(fOutput, 15); // S15 F(L0⊕R0⊕Y1⊕K2)
     
     return term1 ^ term2; // S5,13,21(L0⊕R0⊕L4) ⊕ S15 F(L0⊕R0⊕Y1⊕K2)
 }
 
 /*
  * linear approximation for K2 outer bytes (first and last bytes)
  */
 static int linearApproxK2Outer(int pairIdx, uint32_t k0, uint32_t k1, uint32_t k2) {
     uint32_t pLeft = getPlaintextLeft(pairIdx); // L0
     uint32_t pRight = getPlaintextRight(pairIdx); // R0
     uint32_t cLeft = getCiphertextLeft(pairIdx); // L4
     
     uint32_t val1 = pLeft ^ pRight ^ cLeft; // L0⊕R0⊕L4                                    
     int term1 = getBitAtPosition(val1, 13);
     
     uint32_t y0 = fealFFunction(pLeft ^ pRight ^ k0); // F(L0⊕R0⊕K0)                               
     uint32_t y1 = fealFFunction(pLeft ^ y0 ^ k1); // F(L0⊕Y0⊕K1)
     uint32_t y2 = fealFFunction(pLeft ^ pRight ^ y1 ^ k2); // F(L0⊕R0⊕Y1⊕K2)
     int term2 = getMultipleBits(y2, 7, 15, 23, 31);
     
     return term1 ^ term2; // S13(L0⊕R0⊕L4) ⊕ S7,15,23,31(L0⊕R0⊕Y1⊕K2)
 }
 
 /*
  * linear approximation for K3 inner bytes (middle bytes)
  */
 static int linearApproxK3Inner(int pairIdx, uint32_t keyCandidate,
                                 uint32_t k0, uint32_t k1, uint32_t k2) {
     uint32_t pLeft = getPlaintextLeft(pairIdx); // L0
     uint32_t pRight = getPlaintextRight(pairIdx); // R0
     uint32_t cLeft = getCiphertextLeft(pairIdx); // L4
     uint32_t cRight = getCiphertextRight(pairIdx); // R4
     
     uint32_t val1 = pLeft ^ cLeft ^ cRight; // L0⊕L4⊕R4
     int term1 = getThreeBits(val1, 5, 13, 21);
     
     uint32_t val2 = pLeft ^ pRight ^ cLeft; // L0⊕R0⊕L4
     int term2 = getBitAtPosition(val2, 15);
     
     uint32_t y0 = fealFFunction(pLeft ^ pRight ^ k0); // F(L0⊕R0⊕K0)
     uint32_t y1 = fealFFunction(pLeft ^ y0 ^ k1);
     uint32_t y2 = fealFFunction(pLeft ^ pRight ^ y1 ^ k2); // F(L0⊕R0⊕Y1⊕K2)
     uint32_t fOutput = fealFFunction(pLeft ^ y0 ^ y2 ^ keyCandidate); // F(L0⊕Y0⊕Y2⊕K3)    
     int term3 = getBitAtPosition(fOutput, 15); // S15 F(L0⊕Y0⊕Y2⊕K3)
     
     return term1 ^ term2 ^ term3; // S5,13,21(L0⊕L4⊕R4) ⊕ S15(L0⊕R0⊕L4) ⊕ S15 F(L0⊕Y0⊕Y2⊕K3)
 }
 
 /*
  * linear approximation for K3 outer bytes (first and last bytes)
  */
 static int linearApproxK3Outer(int pairIdx, uint32_t k0, uint32_t k1, 
                                 uint32_t k2, uint32_t k3) {
     uint32_t pLeft = getPlaintextLeft(pairIdx); // L0
     uint32_t pRight = getPlaintextRight(pairIdx); // R0
     uint32_t cLeft = getCiphertextLeft(pairIdx); // L4
     uint32_t cRight = getCiphertextRight(pairIdx); // R4
     
     uint32_t val1 = pLeft ^ cLeft ^ cRight; // L0⊕L4⊕R4
     int term1 = getBitAtPosition(val1, 13);
     
     uint32_t val2 = pLeft ^ pRight ^ cLeft; // L0⊕R0⊕L4
     int term2 = getMultipleBits(val2, 7, 15, 23, 31);
     
     uint32_t y0 = fealFFunction(pLeft ^ pRight ^ k0); // F(L0⊕R0⊕K0)
     uint32_t y1 = fealFFunction(pLeft ^ y0 ^ k1); // F(L0⊕Y0⊕K1)
     uint32_t y2 = fealFFunction(pLeft ^ pRight ^ y1 ^ k2); // F(L0⊕R0⊕Y1⊕K2)
     uint32_t y3 = fealFFunction(pLeft ^ y0 ^ y2 ^ k3); // F(L0⊕Y0⊕Y2⊕K3)   
     int term3 = getMultipleBits(y3, 7, 15, 23, 31); // S7,15,23,31(L0⊕Y0⊕Y2⊕K3)
     
     return term1 ^ term2 ^ term3; // S13(L0⊕L4⊕R4) ⊕ S7,15,23,31(L0⊕R0⊕L4) ⊕ S7,15,23,31(L0⊕Y0⊕Y2⊕K3)              
 }
 
 /*
  * processing a valid K0 candidate by searching for K1
  */
 static void processKey0Candidate(uint32_t k0) {
     int numPairs = getPairCount();
     
     for (int innerIdx = 0; innerIdx < INNER_KEY_SPACE; innerIdx++) {
         uint32_t innerKey = constructInnerKeyCandidate(innerIdx);
         int firstInner = linearApproxK1Inner(0, innerKey, k0);
         
         int allMatch = 1;
         for (int pairIdx = 1; pairIdx < numPairs && allMatch; pairIdx++) {
             if (firstInner != linearApproxK1Inner(pairIdx, innerKey, k0)) {
                 allMatch = 0;
             }
         }
         
         if (allMatch) {
             for (int outerIdx = 0; outerIdx < OUTER_KEY_SPACE; outerIdx++) {
                 uint32_t k1 = constructOuterKeyCandidate(outerIdx, innerKey);
                 int firstOuter = linearApproxK1Outer(0, k0, k1);
                 
                 int allMatchOuter = 1;
                 for (int pairIdx = 1; pairIdx < numPairs && allMatchOuter; pairIdx++) {
                     if (firstOuter != linearApproxK1Outer(pairIdx, k0, k1)) {
                         allMatchOuter = 0;
                     }
                 }
                 
                 if (allMatchOuter) {
                     processKey1Candidate(k0, k1);
                 }
             }
         }
     }
 }
 
 /*
  * processing a valid K1 candidate by searching for K2
  */
 static void processKey1Candidate(uint32_t k0, uint32_t k1) {
     int numPairs = getPairCount();
     
     for (int innerIdx = 0; innerIdx < INNER_KEY_SPACE; innerIdx++) {
         uint32_t innerKey = constructInnerKeyCandidate(innerIdx);
         int firstInner = linearApproxK2Inner(0, innerKey, k0, k1);
         
         int allMatch = 1;
         for (int pairIdx = 1; pairIdx < numPairs && allMatch; pairIdx++) {
             if (firstInner != linearApproxK2Inner(pairIdx, innerKey, k0, k1)) {
                 allMatch = 0;
             }
         }
         
         if (allMatch) {
             for (int outerIdx = 0; outerIdx < OUTER_KEY_SPACE; outerIdx++) {
                 uint32_t k2 = constructOuterKeyCandidate(outerIdx, innerKey);
                 int firstOuter = linearApproxK2Outer(0, k0, k1, k2);
                 
                 int allMatchOuter = 1;
                 for (int pairIdx = 1; pairIdx < numPairs && allMatchOuter; pairIdx++) {
                     if (firstOuter != linearApproxK2Outer(pairIdx, k0, k1, k2)) {
                         allMatchOuter = 0;
                     }
                 }
                 
                 if (allMatchOuter) {
                     processKey2Candidate(k0, k1, k2);
                 }
             }
         }
     }
 }
 
 /*
  * processing a valid K2 candidate by searching for K3
  */
 static void processKey2Candidate(uint32_t k0, uint32_t k1, uint32_t k2) {
     int numPairs = getPairCount();
     
     for (int innerIdx = 0; innerIdx < INNER_KEY_SPACE; innerIdx++) {
         uint32_t innerKey = constructInnerKeyCandidate(innerIdx);
         int firstInner = linearApproxK3Inner(0, innerKey, k0, k1, k2); 
         
         int allMatch = 1;
         for (int pairIdx = 1; pairIdx < numPairs && allMatch; pairIdx++) {
             if (firstInner != linearApproxK3Inner(pairIdx, innerKey, k0, k1, k2)) {
                 allMatch = 0;
             }
         }
         
         if (allMatch) {
             for (int outerIdx = 0; outerIdx < OUTER_KEY_SPACE; outerIdx++) {
                 uint32_t k3 = constructOuterKeyCandidate(outerIdx, innerKey);
                 int firstOuter = linearApproxK3Outer(0, k0, k1, k2, k3);
                 
                 int allMatchOuter = 1;
                 for (int pairIdx = 1; pairIdx < numPairs && allMatchOuter; pairIdx++) {
                     if (firstOuter != linearApproxK3Outer(pairIdx, k0, k1, k2, k3)) {
                         allMatchOuter = 0;
                     }
                 }
                 
                 if (allMatchOuter) {
                     processKey3Candidate(k0, k1, k2, k3);
                 }
             }
         }
     }
 }
 
 /*
  * processing a valid K3 candidate by deriving K4, K5 and validating the complete key
  */
 static void processKey3Candidate(uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3) {
     deriveAndValidateKey(k0, k1, k2, k3);
 }
 
 /*
  * deriving K4 and K5 from K0-K3, then validating the complete key against all known pairs
  */
 static int deriveAndValidateKey(uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3) {
     int numPairs = getPairCount();
     
    // using the first pair to derive K4 and K5
     uint32_t pLeft = getPlaintextLeft(0);
     uint32_t pRight = getPlaintextRight(0);
     uint32_t cLeft = getCiphertextLeft(0);
     uint32_t cRight = getCiphertextRight(0);
     
     // calculating intermediate values
     uint32_t y0 = fealFFunction(pLeft ^ pRight ^ k0);
     uint32_t y1 = fealFFunction(pLeft ^ y0 ^ k1);
     uint32_t y2 = fealFFunction(pLeft ^ pRight ^ y1 ^ k2);
     uint32_t y3 = fealFFunction(pLeft ^ y0 ^ y2 ^ k3);
     
     // deriving K4 and K5
     uint32_t k4 = pLeft ^ pRight ^ y1 ^ y3 ^ cLeft;
     uint32_t k5 = pRight ^ y1 ^ y3 ^ y0 ^ y2 ^ cRight;
     
     uint32_t fullKey[6] = {k0, k1, k2, k3, k4, k5};
     
     // validating against all known pairs
     uint8_t ciphertextBlock[8];
     for (int pairIdx = 0; pairIdx < numPairs; pairIdx++) {
         word32ToBytes(getCiphertextLeft(pairIdx), &ciphertextBlock[0]);
         word32ToBytes(getCiphertextRight(pairIdx), &ciphertextBlock[4]);
         fealDecryptBlock(ciphertextBlock, fullKey);
         uint32_t decryptedLeft = bytesToWord32(&ciphertextBlock[0]);
         uint32_t decryptedRight = bytesToWord32(&ciphertextBlock[4]);
         
         if (decryptedLeft != getPlaintextLeft(pairIdx) || 
             decryptedRight != getPlaintextRight(pairIdx)) {
             return 0; // validation failed
         }
     }
     
     // valid key found - output it
     printf("0x%08x\t0x%08x\t0x%08x\t0x%08x\t0x%08x\t0x%08x\n",
            k0, k1, k2, k3, k4, k5);
     
     validKeysDiscovered++;
     
     if (validKeysDiscovered >= MAX_VALID_KEYS) {
         clock_t endTime = clock();
         long elapsedMs = (endTime - attackStartTime) * 1000 / CLOCKS_PER_SEC;
         printf("\nAttack completed successfully!\n");
         printf("Found %d valid keys in %ld ms\n", validKeysDiscovered, elapsedMs);
         exit(0);
     }
     
     return 1;
 }
 
 /*
  * main attack function
  */
 int main(int argc, char **argv) {
     const char *inputFile = "known.txt";
     
     if (argc > 1) {
         inputFile = argv[1];
     }
 
     printf("FEAL-4 Linear Cryptanalysis Attack\n");
     printf("===================================\n");
     printf("Loading plaintext-ciphertext pairs from %s...\n", inputFile);
     
     int pairsLoaded = loadKnownPairs(inputFile);
     
     if (pairsLoaded == 0) {
         fprintf(stderr, "Error: No pairs loaded. Check file format.\n");
         return 1;
     }
 
     printf("Successfully loaded %d plaintext-ciphertext pairs\n", pairsLoaded);
     printf("Starting attack...\n\n");
     
     attackStartTime = clock();
     
     int numPairs = getPairCount();
     
     // searching for K0 candidates
     for (int innerIdx = 0; innerIdx < INNER_KEY_SPACE; innerIdx++) {
         uint32_t innerKey = constructInnerKeyCandidate(innerIdx);
         int firstResult = linearApproxK0Inner(0, innerKey);
         
         // checking if this inner key candidate is consistent across all pairs
         int consistent = 1;
         for (int pairIdx = 1; pairIdx < numPairs && consistent; pairIdx++) {
             if (firstResult != linearApproxK0Inner(pairIdx, innerKey)) {
                 consistent = 0;
             }
         }
         
         if (consistent) {
             // inner key candidate found, now searching for outer bytes
             for (int outerIdx = 0; outerIdx < OUTER_KEY_SPACE; outerIdx++) {
                 uint32_t k0 = constructOuterKeyCandidate(outerIdx, innerKey);
                 int firstOuter = linearApproxK0Outer(0, k0);
                 
                 // checking outer key candidate consistency
                 int consistentOuter = 1;
                 for (int pairIdx = 1; pairIdx < numPairs && consistentOuter; pairIdx++) {
                     if (firstOuter != linearApproxK0Outer(pairIdx, k0)) {
                         consistentOuter = 0;
                     }
                 }
                 
                 if (consistentOuter) {
                     // valid K0 candidate found, continue search
                     processKey0Candidate(k0);
                 }
             }
         }
     }
     
     // if we reach here, fewer than MAX_VALID_KEYS were found
     clock_t endTime = clock();
     long elapsedMs = (endTime - attackStartTime) * 1000 / CLOCKS_PER_SEC;
     printf("\nAttack completed.\n");
     printf("Found %d valid keys in %ld ms\n", validKeysDiscovered, elapsedMs);
     
     cleanupPairData();
     
     return 0;
 }