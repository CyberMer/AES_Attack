#ifndef SQUARE_CRYPTO_H
#define SQUARE_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

/**
 * Square Attack Cryptanalysis Framework
 * =====================================
 * Original implementation for educational cryptanalysis
 */

// Configuration constants
#define BLOCK_LENGTH 16
#define LAMBDA_SET_CARDINALITY 256
#define MAX_KEY_CANDIDATES 256
#define AES_ROUNDS_3_5 4

// Data structures
typedef struct {
    uint8_t plaintexts[LAMBDA_SET_CARDINALITY][BLOCK_LENGTH];
    uint8_t ciphertexts[LAMBDA_SET_CARDINALITY][BLOCK_LENGTH];
    uint8_t active_position;
    bool is_valid;
} lambda_set_t;

typedef struct {
    uint8_t candidates[MAX_KEY_CANDIDATES];
    size_t count;
    uint8_t final_key;
    bool determined;
} key_byte_analysis_t;

typedef struct {
    key_byte_analysis_t bytes[BLOCK_LENGTH];
    uint8_t recovered_key[BLOCK_LENGTH];
    size_t lambda_sets_used;
    double execution_time;
    bool success;
} attack_result_t;

// Core cryptanalysis functions
lambda_set_t* create_lambda_set(uint8_t active_byte_position);
void destroy_lambda_set(lambda_set_t* set);

bool encrypt_lambda_set(lambda_set_t* set, const uint8_t* master_key);
bool analyze_key_byte(const lambda_set_t* set, uint8_t byte_position, key_byte_analysis_t* analysis);

attack_result_t* execute_square_attack(void);
void print_attack_summary(const attack_result_t* result);
void cleanup_attack_result(attack_result_t* result);

// Utility functions with unique implementations
bool secure_random_bytes(uint8_t* buffer, size_t length);
void format_hex_output(const uint8_t* data, size_t length, const char* label);
bool arrays_match(const uint8_t* arr1, const uint8_t* arr2, size_t length);
double get_timestamp_ms(void);

#endif // SQUARE_CRYPTO_H