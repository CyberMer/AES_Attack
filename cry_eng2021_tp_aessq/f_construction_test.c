/**
 * F Construction Test Program
 * ===========================
 * Testing F(k1||k2, x) = E(k1, x) ⊕ E(k2, x)
 */

#include "square_crypto.h"
#include "aes-128_enc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Helper function to print hex data
void print_hex(const char* label, const uint8_t* data) {
    printf("%-15s: ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02x", data[i]);
        if (i == 7) printf(" ");
    }
    printf("\n");
}

int main(void) {
    printf("F Construction Test Program\n");
    printf("===========================\n\n");
    
    printf("=== F Construction Test ===\n\n");
    
    // Test keys and input
    uint8_t k1[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t k2[16] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t x[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                     0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t result[16];
    
    printf("F(k1||k2, x) = E(k1, x) ⊕ E(k2, x)\n\n");
    
    print_hex("k1", k1);
    print_hex("k2", k2);
    print_hex("x", x);
    
    // Test F construction
    F_construction(k1, k2, x, result);
    print_hex("F(k1||k2, x)", result);
    
    // Test trivial case: k1 = k2
    printf("\n=== Trivial case: k1 = k2 ===\n");
    F_construction(k1, k1, x, result);
    print_hex("F(k1||k1, x)", result);
    
    // Check if result is zero
    int is_zero = 1;
    for (int i = 0; i < 16; i++) {
        if (result[i] != 0) {
            is_zero = 0;
            break;
        }
    }
    printf("Result is zero: %s\n", is_zero ? "YES" : "NO");
    
    // Additional tests with different key pairs
    printf("\n=== Additional Test Cases ===\n");
    
    // Test case 2: Random keys
    uint8_t k3[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t k4[16] = {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
                      0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0};
    
    printf("\nTest case 2:\n");
    print_hex("k3", k3);
    print_hex("k4", k4);
    F_construction(k3, k4, x, result);
    print_hex("F(k3||k4, x)", result);
    
    // Test case 3: Same input, different keys vs swapped keys
    printf("\nTest case 3 - Symmetry test:\n");
    uint8_t result1[16], result2[16];
    
    F_construction(k1, k2, x, result1);
    F_construction(k2, k1, x, result2);
    
    print_hex("F(k1||k2, x)", result1);
    print_hex("F(k2||k1, x)", result2);
    
    // Check if F(k1||k2, x) = F(k2||k1, x) (should be equal due to XOR symmetry)
    int are_equal = 1;
    for (int i = 0; i < 16; i++) {
        if (result1[i] != result2[i]) {
            are_equal = 0;
            break;
        }
    }
    printf("F(k1||k2, x) = F(k2||k1, x): %s\n", are_equal ? "YES" : "NO");
    
    // Test case 4: Different inputs with same keys
    printf("\nTest case 4 - Different inputs:\n");
    uint8_t x2[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    
    print_hex("x1", x);
    print_hex("x2", x2);
    
    F_construction(k1, k2, x, result1);
    F_construction(k1, k2, x2, result2);
    
    print_hex("F(k1||k2, x1)", result1);
    print_hex("F(k1||k2, x2)", result2);
    
    // XOR the F outputs
    uint8_t f_xor[16];
    for (int i = 0; i < 16; i++) {
        f_xor[i] = result1[i] ^ result2[i];
    }
    print_hex("F(...,x1)⊕F(...,x2)", f_xor);
    
    printf("\n=== Analysis Summary ===\n");
    printf("• F construction creates pseudo-random function from block cipher\n");
    printf("• F(k||k, x) = E(k,x) ⊕ E(k,x) = 0 (trivial case)\n");
    printf("• F(k1||k2, x) = F(k2||k1, x) (XOR is commutative)\n");
    printf("• F provides cryptographic properties for advanced constructions\n");
    printf("• Used in security proofs and theoretical cryptanalysis\n");
    
    return 0;
}