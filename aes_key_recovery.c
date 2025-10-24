#include "aes-128_attack.h"

const uint8_t SB_SR_REV[AES_128_KEY_SIZE] = {
    0, 5, 10, 15,
    4, 9, 14, 3,
    8, 13, 2, 7,
    12, 1, 6, 11};

// XOR two arrays and store result in dst
void xors(uint8_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        dst[i] ^= src[i];
    }
}

// Generate random bytes
void gen_keys(uint8_t *key, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        read(fd, key, len);
        close(fd);
    } else {
        for (size_t i = 0; i < len; i++) {
            key[i] = rand() & 0xFF;
        }
    }
}

// Generate a lambda set (one active byte at position 0)
void gen_lambda_set(uint8_t *lambda_set) {
    for (int i = 0; i < LAMBDA_SET_SIZE; i++) {
        memset(lambda_set + i * AES_BLOCK_SIZE, 0, AES_BLOCK_SIZE);
        lambda_set[i * AES_BLOCK_SIZE] = i; // Active byte at position 0
    }
}

// Print key in hex format
void print_key(const uint8_t *key, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("0x%02x", key[i]);
        if (i < len - 1) printf(", ");
    }
}

// Main key recovery function using square attack
void retrieve_key(uint8_t recovered_key[AES_BLOCK_SIZE], void (*oracle)(uint8_t res[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE])) {
    uint8_t lambda_set[LAMBDA_SET_SIZE * AES_BLOCK_SIZE];
    uint8_t guessed_key[AES_BLOCK_SIZE] = {0};
    
    gen_lambda_set(lambda_set);
    uint8_t ciphered_set[LAMBDA_SET_SIZE * AES_BLOCK_SIZE];
    
    // Encrypt the lambda set
    for (size_t i = 0; i < LAMBDA_SET_SIZE; i++)
        oracle(ciphered_set + (i * AES_BLOCK_SIZE), lambda_set + (i * AES_BLOCK_SIZE));
    
    // Try to recover each key byte
    for (uint8_t s = 0; s < AES_128_KEY_SIZE; s++) {
        for (size_t i = 0; i < 256; i++) {
            uint8_t sum[AES_BLOCK_SIZE] = {0};
            uint8_t block[AES_BLOCK_SIZE];
            
            for (size_t j = 0; j < LAMBDA_SET_SIZE; j++) {
                memcpy(block, ciphered_set + (j * AES_BLOCK_SIZE), AES_BLOCK_SIZE);
                xors(block, guessed_key, AES_BLOCK_SIZE);
                
                // Simple partial decryption approach
                block[s] ^= i;  // Try key guess i for position s
                xors(sum, block, AES_BLOCK_SIZE);
            }
            
            if (sum[SB_SR_REV[s]] == 0) {
                guessed_key[s] = i;
                break;
            }
        }
    }
    
    // Recover master key by going back through key schedule
    uint8_t temp_key[AES_128_KEY_SIZE];
    memcpy(temp_key, guessed_key, AES_128_KEY_SIZE);
    for (int round = 3; round >= 0; round--) {
        prev_aes128_round_key(temp_key, recovered_key, round);
        memcpy(temp_key, recovered_key, AES_128_KEY_SIZE);
    }
}

// Oracle and test functions
uint8_t oracle_key[AES_128_KEY_SIZE];

void oracle(uint8_t res[AES_BLOCK_SIZE], const uint8_t src[AES_BLOCK_SIZE]) {
    memcpy(res, src, AES_BLOCK_SIZE);
    aes128_enc(res, oracle_key, 4, 0);
}

void test() {
    for (uint8_t i = 0; i < NB_KEYS; i++) {
        uint8_t key[AES_128_KEY_SIZE];
        gen_keys(key, AES_128_KEY_SIZE);
        
        printf("- Testing key n. %d:\n", i);
        printf("Key: {");
        print_key(key, AES_128_KEY_SIZE);
        printf("}\n");
        
        memcpy(oracle_key, key, AES_128_KEY_SIZE);
        
        // Try to retrieve the key
        uint8_t recovered_key[AES_128_KEY_SIZE];
        retrieve_key(recovered_key, oracle);
        
        if (memcmp(key, recovered_key, AES_128_KEY_SIZE) == 0) {
            printf("Key recovered successfully\n");
        } else {
            printf("Key not recovered\n");
            exit(1);
        }
        printf("Test n. %d PASSED\n", i);
    }
    printf("All tests PASSED\n");
}

int main() {
    printf("Testing key_recovery..\n");
    test();
    return 0;
}