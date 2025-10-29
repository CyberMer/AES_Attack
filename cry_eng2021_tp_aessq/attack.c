#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "attack.h"
#include "aes-128_enc.h"
#include "square_crypto.h"

/*
 * Generate a lambda set with unique structure
 * Uses 256 plaintexts where one byte varies through all values
 */
int build_random_lambda_set(
	uint8_t lambda_set[AES_LAMBDA_SET_SIZE][AES_BLOCK_SIZE]) {
	
	// Generate base pattern using secure randomness
	uint8_t base_pattern;
	if (!secure_random_bytes(&base_pattern, 1)) {
		return -1;
	}

	// Create initialization vector with base pattern
	uint8_t init_vector[AES_BLOCK_SIZE];
	for (int i = 0; i < AES_BLOCK_SIZE; i++) {
		init_vector[i] = base_pattern;
	}
	
	// Generate lambda set: first byte varies, others constant
	for (size_t i = 0; i < AES_LAMBDA_SET_SIZE; i++) {
		for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
			lambda_set[i][j] = init_vector[j];
		}
		lambda_set[i][0] = (uint8_t)i;  // Active byte position 0
	}

	return 0;
}

uint8_t byte_reverse_add_round_key(uint8_t block_byte, uint8_t key_byte) {
	return block_byte ^ key_byte;
}

uint8_t byte_reverse_sub_bytes(uint8_t block_byte,
							   const uint8_t Sbox_inv[256]) {
	return Sbox_inv[block_byte];
}

/*
 * partial_decrypt reverse AddRoundKey and SubBytes
 * We don't need to reverse ShiftRow.
 */
uint8_t partial_decrypt(uint8_t block_byte, uint8_t key_byte,
						const uint8_t Sbox_inv[256]) {
	return byte_reverse_sub_bytes(
		byte_reverse_add_round_key(block_byte, key_byte), Sbox_inv);
}

/*
 * Returns true if the distinguisher condition is verified.
 */
bool distinguisher(uint8_t lambda_set[AES_LAMBDA_SET_SIZE][AES_BLOCK_SIZE],
				   size_t key_byte_index, uint8_t guessed_key_byte,
				   const uint8_t Sbox_inv[256]) {
	// sum holds the xored values of the partially decrypted lambda set
	uint8_t sum = 0;
	for (size_t i = 0; i < AES_LAMBDA_SET_SIZE; ++i) {
		sum ^= partial_decrypt(lambda_set[i][key_byte_index], guessed_key_byte,
							   Sbox_inv);
	}

	return (sum == 0);
}

/*
 * Find the most common occurrence between all lambda sets.
 * @key_byte_counter holds the occurences of possible guessed key value for the
 * choosen key byte index
 * @returns true if there is only one most common occurrence
 */
bool most_common(size_t key_byte_counter[AES_KEY_BYTES_SIZE],
				 uint8_t *guessed_key_byte) {
	size_t max = 0;
	bool max_unique = true;
	size_t key_byte_count;
	for (uint16_t key_byte = 0; key_byte < AES_KEY_BYTES_SIZE; ++key_byte) {
		key_byte_count = key_byte_counter[key_byte];

		if (key_byte_count > max) {
			// New most common key byte
			max = key_byte_count;
			*guessed_key_byte = (uint8_t)key_byte;
			max_unique = true;
		} else if (key_byte_count == max) {
			// There are 2 key bytes with the same occurence
			// count
			max_unique = false;
		}
	}

	return max_unique;
}

int aes128_attack(void) {
	printf("=== Square Attack Implementation ===\n\n");
	
	// Generate random target key using secure randomness
	uint8_t key[AES_128_KEY_SIZE] = {0};

	if (!secure_random_bytes(key, AES_128_KEY_SIZE)) {
		printf("Error: Failed to generate random key\n");
		return -1;
	}

	// Decoded key after the attack
	uint8_t decoded_key[AES_128_KEY_SIZE] = {0};
	// Lambda set
	uint8_t lambda_set[AES_LAMBDA_SET_SIZE][AES_BLOCK_SIZE] = {{0}};
	// Counts the occurence of possible key bytes for all key bytes index
	// It is shared accross lambda sets.
	size_t key_bytes_counter[AES_128_KEY_SIZE][AES_KEY_BYTES_SIZE] = {{0}};
	// Counts the number of possible keys for a given byte
	size_t possible_key_byte_count[AES_128_KEY_SIZE] = {0};

	// counts the number of possible key byte guesses for a lambda set
	size_t key_byte_count;
	// holds the last possible key byte guess. When key_byte_count is equals to
	// 1, it holds the only possible key byte guess ie. the correct key byte.
	uint8_t guessed_key_byte;

	// Track attack progress with timing
	double start_time = get_timestamp_ms();
	size_t lambda_sets_used = 0;
	
	// Storage for key recovery analysis
	size_t key_bytes_guessed = 0;
	
	while (key_bytes_guessed < AES_128_KEY_SIZE) {
		lambda_sets_used++;
		
		// Generate lambda set with unique structure
		int generation_result = build_random_lambda_set(lambda_set);
		if (generation_result != 0) {
			printf("Error: Lambda set generation failed\n");
			return -1;
		}

		// Encrypt lambda set through 3.5 rounds
		for (size_t i = 0; i < AES_LAMBDA_SET_SIZE; ++i) {
			aes128_enc(lambda_set[i], key, 4, 0);
		}

		// Loop through the key bytes we try to guess
		for (size_t key_byte_index = 0; key_byte_index < AES_128_KEY_SIZE;
			 ++key_byte_index) {
			if (possible_key_byte_count[key_byte_index] == 1) {
				// The key byte was already found
				continue;
			}

			// (Re-)Initialize the count of key byte guesses for the current key
			// byte
			key_byte_count = 0;
			printf("Possible guess for byte %zu :", key_byte_index);
			for (uint16_t key_byte = 0; key_byte < AES_KEY_BYTES_SIZE;
				 ++key_byte) {
				if (distinguisher(lambda_set, key_byte_index, (uint8_t)key_byte,
								  Sinv)) {
					printf(" %x -", key_byte);
					// Increment the possible guesses counter for the next
					// iteration with a new lambda set
					key_bytes_counter[key_byte_index][key_byte]++;
					// Increment the possible guesses counter for the current
					// lambda set
					key_byte_count++;
					// Save the last guessed byte, used if there is only one
					// guess for this key byte
					guessed_key_byte = (uint8_t)key_byte;
				}
			}
			printf("\n");

			printf("Possible keys count : %zu \n", key_byte_count);
			if (key_byte_count == 1) {
				// There is only one guessed key byte, it is the correct key
				// byte
				decoded_key[key_byte_index] = guessed_key_byte;
				key_bytes_guessed++;
			} else if (possible_key_byte_count[key_byte_index] > 0) {
				// There are many key bytes guesses and we aren't using the
				// first lambda set

				if (most_common(key_bytes_counter[key_byte_index],
								&guessed_key_byte)) {
					// There is only one most common occurrence, we found the
					// correct key byte
					decoded_key[key_byte_index] = guessed_key_byte;
					key_byte_count = 1;
					key_bytes_guessed++;
				}
			}

			possible_key_byte_count[key_byte_index] = key_byte_count;
		}

		printf("\nProgress Report:\n");
		printf("Key bytes recovered: %zu/%d\n", key_bytes_guessed, AES_128_KEY_SIZE);
		printf("Lambda sets used: %zu\n", lambda_sets_used);
		printf("Remaining bytes: %zu\n\n", AES_128_KEY_SIZE - key_bytes_guessed);
	}

	// Display final results with timing
	double execution_time = get_timestamp_ms() - start_time;
	
	printf("=== Attack Results ===\n");
	format_hex_output(key, AES_128_KEY_SIZE, "Original Key");

	printf("\nDeriving master key from recovered 3rd round key...\n");
	format_hex_output(decoded_key, AES_128_KEY_SIZE, "3rd Round Key");

	// Derive master key using key schedule inversion
	uint8_t tmp[AES_128_KEY_SIZE];
	
	prev_aes128_round_key(decoded_key, tmp, 3);
	prev_aes128_round_key(tmp, decoded_key, 2);
	prev_aes128_round_key(decoded_key, tmp, 1);
	prev_aes128_round_key(tmp, decoded_key, 0);

	format_hex_output(decoded_key, AES_128_KEY_SIZE, "Recovered Master Key");

	// Verify attack success
	bool attack_success = arrays_match(decoded_key, key, AES_128_KEY_SIZE);
	
	printf("\n=== Attack Summary ===\n");
	printf("Execution time: %.2f ms\n", execution_time);
	printf("Lambda sets used: %zu\n", lambda_sets_used);
	printf("Success: %s\n", attack_success ? "YES" : "NO");

	return attack_success ? 0 : 1;
}

int main() {
	printf("Square Cryptanalysis Framework\n");
	printf("==============================\n");
	printf("3.5-round AES-128 Key Recovery Attack\n\n");
	
	int result = aes128_attack();
	
	printf("\n=== Final Status ===\n");
	if (result == 0) {
		printf("Attack completed successfully!\n");
		printf("Master key recovered with 100%% accuracy.\n");
	} else {
		printf(" Attack incomplete or failed.\n");
		printf("Error code: %d\n", result);
	}
	
	return result;
}