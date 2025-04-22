#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

uint8_t publicarray[16] = {0};
uint8_t publicarray2[256 * 512] = {0};
uint8_t secretarray[16] = {
    10, 21, 32, 43, 54, 65, 76, 87,
    98, 109, 110, 121, 132, 143, 154, 165
};
volatile uint8_t temp = 0;

// Spectre PHT — direct speculative load
void case_0(uint64_t idx) {
    if (idx < 16) {
        temp &= publicarray2[secretarray[idx] * 512];
    }
}

// Spectre PHT — speculative read from nested condition
void case_1(uint64_t idx) {
    if (idx < 16) {
        if (publicarray[idx] < 128) {
            temp &= publicarray2[secretarray[idx] * 512];
        }
    }
}

// Spectre PHT — speculative read via attacker-controlled pointer offset
void case_2(uint64_t idx) {
    if (idx < 16) {
        uint8_t *ptr = &secretarray[0];
        temp &= publicarray2[ptr[idx] * 512];
    }
}

// Spectre PHT — masked + shifted index still attacker-controlled
void case_3(uint64_t idx) {
    if ((idx & 0xFF) < 16) {
        temp &= publicarray2[secretarray[idx & 0xF] * 512];
    }
}

// Spectre PHT — indirect load through public, resolves to secret
void case_4(uint64_t idx) {
    if (idx < 16) {
        uint8_t x = publicarray[idx];
        temp &= publicarray2[secretarray[x & 0xF] * 512];
    }
}

// Spectre PHT — speculative loop unroll
void case_5(uint64_t idx) {
    if (idx < 16) {
        for (int i = 0; i <= idx; i++) {
            temp &= publicarray2[secretarray[i & 0xF] * 512];
        }
    }
}

// Spectre PHT — nested gadget
void case_6(uint64_t idx) {
    if (idx < 16) {
        if (publicarray[idx] > 0) {
            uint8_t val = secretarray[idx];
            temp &= publicarray2[val * 512];
        }
    }
}

// === main function ===
int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <case_num> <idx>\n", argv[0]);
        return 1;
    }

    int case_num = atoi(argv[1]);
    uint64_t idx = (uint64_t)strtoull(argv[2], NULL, 0);

    switch (case_num) {
        case 0: case_0(idx); break;
        case 1: case_1(idx); break;
        case 2: case_2(idx); break;
        case 3: case_3(idx); break;
        case 4: case_4(idx); break;
        case 5: case_5(idx); break;
        case 6: case_6(idx); break;
        default:
            fprintf(stderr, "Invalid case %d\n", case_num);
            return 1;
    }

    return 0;
}
