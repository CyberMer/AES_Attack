#include "square_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>

bool secure_random_bytes(uint8_t* buffer, size_t length) {
    if (!buffer || length == 0) return false;
    
    int entropy_fd = open("/dev/urandom", O_RDONLY);
    if (entropy_fd < 0) {
        // Fallback to time-based seeding
        srand((unsigned int)time(NULL));
        for (size_t i = 0; i < length; i++) {
            buffer[i] = (uint8_t)(rand() & 0xFF);
        }
        return true;
    }
    
    ssize_t bytes_read = read(entropy_fd, buffer, length);
    close(entropy_fd);
    return (bytes_read == (ssize_t)length);
}

void format_hex_output(const uint8_t* data, size_t length, const char* label) {
    if (!data || !label) return;
    
    printf("%-20s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
        if (i == 7 && length == 16) printf(" ");
        else if (i < length - 1) printf(" ");
    }
    printf("\n");
}

bool arrays_match(const uint8_t* arr1, const uint8_t* arr2, size_t length) {
    if (!arr1 || !arr2) return false;
    return memcmp(arr1, arr2, length) == 0;
}

double get_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}