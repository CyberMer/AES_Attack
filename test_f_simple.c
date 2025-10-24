#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "cry_eng2021_tp_aessq/aes-128_enc.h"

void print_hex(const char* label, const uint8_t *data)
{
    printf("%s: ", label);
    for (int i = 0; i < 16; i++) {
        printf("%02X ", data[i]);
        if (i == 7) printf(" ");
    }
    printf("\n");
}

int main()
{
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
    
    return 0;
}