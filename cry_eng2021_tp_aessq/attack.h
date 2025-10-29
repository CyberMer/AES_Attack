#ifndef ATTACK_H
#define ATTACK_H

#include <stdint.h>
#include <stdbool.h>

// Constants
#define AES_BLOCK_SIZE 16
#define AES_LAMBDA_SET_SIZE 256
#define AES_KEY_BYTES_SIZE 256

// Function declarations
int build_random_lambda_set(uint8_t lambda_set[AES_LAMBDA_SET_SIZE][AES_BLOCK_SIZE]);
uint8_t byte_reverse_add_round_key(uint8_t block_byte, uint8_t key_byte);
uint8_t byte_reverse_sub_bytes(uint8_t block_byte, const uint8_t Sbox_inv[256]);
uint8_t partial_decrypt(uint8_t block_byte, uint8_t key_byte, const uint8_t Sbox_inv[256]);
bool distinguisher(uint8_t lambda_set[AES_LAMBDA_SET_SIZE][AES_BLOCK_SIZE],
                   size_t key_byte_index, uint8_t guessed_key_byte,
                   const uint8_t Sbox_inv[256]);
bool most_common(size_t key_byte_counter[AES_KEY_BYTES_SIZE], uint8_t *guessed_key_byte);
int aes128_attack(void);

#endif // ATTACK_H