#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Global arrays and flags
volatile uint8_t spec_ok = 0; // Branch guard — must be zero at runtime
uint64_t publicarray_size = 16;
uint64_t publicarray_mask = 15;
uint8_t publicarray[16] = {
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
};
uint8_t publicarray2[256 * 512] = { 0 };
uint8_t secretarray[16] = {
    42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57
};

volatile uint8_t temp = 0;  // Used to prevent compiler optimization
volatile uint8_t passed = 0;

// Spectre-style case
void case_debug(uint64_t idx) {
    if (temp) {
        // Should never be true in normal execution
        passed = 1;  // Write to global to show you got here
        uint8_t secret = secretarray[idx & publicarray_mask];
        temp &= publicarray2[secret * 512];
    }
    else{
        passed = 2;
    }
}

// Entrypoint for analysis
int main(int argc, char** argv) {
    uint64_t input = 0;

    // Optional: Read attacker input from command line
    if (argc >= 2) {
        sscanf(argv[1], "%lu", &input);
    }

    // Call the spectre-style function
    case_debug(input);

    // Prevent optimizations
    printf("temp = %d\n", temp);
    return 0;
}
