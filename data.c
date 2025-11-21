/*
 * plaintext-ciphertext data management,
 * handles loading and storage of known pairs for cryptanalysis,
 * uses dynamic memory allocation 
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 typedef unsigned int uint32_t;
 
 #define INITIAL_CAPACITY 50
 #define GROWTH_FACTOR 2
 
 // interleaved storage format for better cache locality
 typedef struct {
     uint32_t *plaintextLeftArray;   // all left halves of plaintexts
     uint32_t *plaintextRightArray;  // all right halves of plaintexts
     uint32_t *ciphertextLeftArray;  // all left halves of ciphertexts
     uint32_t *ciphertextRightArray; // all right halves of ciphertexts
     int capacity;                   // current allocated capacity
     int count;                      // number of pairs actually loaded
 } PairDataStorage;
 
 // global storage - dynamically allocated
 static PairDataStorage storage = {NULL, NULL, NULL, NULL, 0, 0};
 
 // initializing storage with initial capacity
 static int initializeStorage(int initialCapacity) {
     storage.plaintextLeftArray = (uint32_t *)malloc(initialCapacity * sizeof(uint32_t));
     storage.plaintextRightArray = (uint32_t *)malloc(initialCapacity * sizeof(uint32_t));
     storage.ciphertextLeftArray = (uint32_t *)malloc(initialCapacity * sizeof(uint32_t));
     storage.ciphertextRightArray = (uint32_t *)malloc(initialCapacity * sizeof(uint32_t));
     
         if (!storage.plaintextLeftArray || !storage.plaintextRightArray ||
         !storage.ciphertextLeftArray || !storage.ciphertextRightArray) {
         free(storage.plaintextLeftArray);
         free(storage.plaintextRightArray);
         free(storage.ciphertextLeftArray);
         free(storage.ciphertextRightArray);
         storage.plaintextLeftArray = NULL;
         return 0;
     }
     
     storage.capacity = initialCapacity;
     storage.count = 0;
     return 1;
 }
 
 static int expandStorage(void) {
     int newCapacity = storage.capacity * GROWTH_FACTOR;
     
     uint32_t *newLeftP = (uint32_t *)realloc(storage.plaintextLeftArray, newCapacity * sizeof(uint32_t));
     uint32_t *newRightP = (uint32_t *)realloc(storage.plaintextRightArray, newCapacity * sizeof(uint32_t));
     uint32_t *newLeftC = (uint32_t *)realloc(storage.ciphertextLeftArray, newCapacity * sizeof(uint32_t));
     uint32_t *newRightC = (uint32_t *)realloc(storage.ciphertextRightArray, newCapacity * sizeof(uint32_t));
     
     if (!newLeftP || !newRightP || !newLeftC || !newRightC) {
         return 0;
     }
     
     storage.plaintextLeftArray = newLeftP;
     storage.plaintextRightArray = newRightP;
     storage.ciphertextLeftArray = newLeftC;
     storage.ciphertextRightArray = newRightC;
     storage.capacity = newCapacity;
     return 1;
 }
 
 // storage cleanup
 void cleanupPairData(void) {
     free(storage.plaintextLeftArray);
     free(storage.plaintextRightArray);
     free(storage.ciphertextLeftArray);
     free(storage.ciphertextRightArray);
     storage.plaintextLeftArray = NULL;
     storage.plaintextRightArray = NULL;
     storage.ciphertextLeftArray = NULL;
     storage.ciphertextRightArray = NULL;
     storage.capacity = 0;
     storage.count = 0;
 }
 
 int getPairCount(void) {
     return storage.count;
 }
 
 uint32_t getPlaintextLeft(int index) {
     if (index < 0 || index >= storage.count || !storage.plaintextLeftArray) {
         return 0;
     }
     return storage.plaintextLeftArray[index];
 }
 
 uint32_t getPlaintextRight(int index) {
     if (index < 0 || index >= storage.count || !storage.plaintextRightArray) {
         return 0;
     }
     return storage.plaintextRightArray[index];
 }
 
 uint32_t getCiphertextLeft(int index) {
     if (index < 0 || index >= storage.count || !storage.ciphertextLeftArray) {
         return 0;
     }
     return storage.ciphertextLeftArray[index];
 }
 
 uint32_t getCiphertextRight(int index) {
     if (index < 0 || index >= storage.count || !storage.ciphertextRightArray) {
         return 0;
     }
     return storage.ciphertextRightArray[index];
 }
 
 // parsing hexadecimal string to 32-bit word
 static uint32_t parseHexWord(const char *hexStr, int length) {
     char temp[9] = {0};
     if (length > 8) length = 8;
     strncpy(temp, hexStr, length);
     temp[length] = '\0';
     return (uint32_t)strtoul(temp, NULL, 16);
 }
 
 // extracting hex value from line (handling both Plaintext= and Ciphertext=)
 static int extractHexFromLine(const char *line, char *output, int maxLen) {
     const char *hexStart = NULL;
     if (strncmp(line, "Plaintext=", 10) == 0) {
         hexStart = line + 10;
     } else if (strncmp(line, "Ciphertext=", 11) == 0) {
         hexStart = line + 11;
     } else {
         return 0;
     }
     
     while (*hexStart == ' ') hexStart++;
     
     int len = 0;
     while (*hexStart && len < maxLen - 1 && 
            ((*hexStart >= '0' && *hexStart <= '9') ||
             (*hexStart >= 'a' && *hexStart <= 'f') ||
             (*hexStart >= 'A' && *hexStart <= 'F'))) {
         output[len++] = *hexStart++;
     }
     output[len] = '\0';
     return len > 0;
 }
 
 // loading plaintext ciphertext pairs from known.txtfile
 int loadKnownPairs(const char *filename) {
     FILE *file = fopen(filename, "r");
     if (!file) {
         fprintf(stderr, "Error: Cannot open file %s\n", filename);
         return 0;
     }
 
     if (!storage.plaintextLeftArray) {
         if (!initializeStorage(INITIAL_CAPACITY)) {
             fclose(file);
             fprintf(stderr, "Error: Memory allocation failed\n");
             return 0;
         }
     }
 
     char buffer[256];
     char plaintextHex[32] = {0};
     char ciphertextHex[32] = {0};
     int expectingPlaintext = 1;
 
     while (fgets(buffer, sizeof(buffer), file)) {
         buffer[strcspn(buffer, "\n")] = 0;
         
         if (strlen(buffer) == 0) continue;
 
         if (expectingPlaintext) {
             if (extractHexFromLine(buffer, plaintextHex, sizeof(plaintextHex))) {
                 expectingPlaintext = 0;
             }
         } else {
             if (extractHexFromLine(buffer, ciphertextHex, sizeof(ciphertextHex))) {
                 if (storage.count >= storage.capacity) {
                     if (!expandStorage()) {
                         fclose(file);
                         fprintf(stderr, "Error: Memory reallocation failed\n");
                         return storage.count;
                     }
                 }
                 
                 storage.plaintextLeftArray[storage.count] = parseHexWord(plaintextHex, 8);
                 storage.plaintextRightArray[storage.count] = parseHexWord(plaintextHex + 8, 8);
                 storage.ciphertextLeftArray[storage.count] = parseHexWord(ciphertextHex, 8);
                 storage.ciphertextRightArray[storage.count] = parseHexWord(ciphertextHex + 8, 8);
                 
                 storage.count++;
                 expectingPlaintext = 1;
             }
         }
     }
 
     fclose(file);
     return storage.count;
 }
 