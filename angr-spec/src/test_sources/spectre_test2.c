#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Setup
uint8_t publicarray[64] = {0};
uint8_t publicarray2[512 * 256];
uint8_t secretarray[64] = {42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57};
volatile uint8_t temp = 0;

uint64_t publicarray_size = 64;
uint64_t secretarray_size = 64;
uint64_t public_mask = 63;

void leak(uint8_t x) {
    temp &= publicarray2[x * 512];
}

void case_0(uint64_t idx) {
    // Classic Kocher-style leak
    if (idx < publicarray_size) {
        temp &= publicarray2[secretarray[idx] * 512];
    }
}

void case_1(uint64_t idx) {
    // Nested branch speculation with secret usage
    if (idx < publicarray_size) {
        if (secretarray[idx] > 10) {
            leak(secretarray[idx]);
        }
    }
}

void case_2(uint64_t idx) {
    // Double indexing: secret controls array access
    if (idx < publicarray_size) {
        uint8_t ptr = secretarray[idx];
        // temp &= publicarray2[publicarray[ptr] * 512];
    }
}

void case_3(uint64_t idx) {
    // Attacker controls loop exit — taint inside loop
    if (idx < publicarray_size) {
        for (uint64_t i = 0; i < idx; i++) {
            temp &= publicarray2[secretarray[i & public_mask] * 512];
        }
    }
}

void case_4(uint64_t idx) {
    // Safe bounds + masking — should NOT leak
    uint64_t safe_idx = idx & public_mask;
    if (safe_idx < publicarray_size) {
        temp &= publicarray2[publicarray[safe_idx] * 512];
    }
}

void case_5(uint64_t idx) {
    // Function inlining obfuscation — secret dependent
    if ((idx % 7) == 3) {
        uint8_t x = secretarray[(idx * 2) & public_mask];
        leak(x);
    }
}

void case_6(uint64_t idx) {
    // Complex conditional tree: only one path leaks
    if (idx > 5 && idx < 20) {
        if ((idx & 2) == 0) {
            leak(secretarray[idx]);
        } else {
            temp &= 0xAB;
        }
    }
}

void case_7(uint64_t idx) {
    // Indirect via pointer math
    uint8_t* ptr = &secretarray[0];
    if (idx < publicarray_size) {
        uint8_t val = *(ptr + idx);
        leak(val);
    }
}

void case_8(uint64_t idx) {
    // Redundant masking — no leakage
    if ((idx & 0xFFFFFFFF) < publicarray_size) {
        temp &= publicarray2[publicarray[idx] * 512];
    }
}

int main() {
    for (int i = 0; i < 9; i++) {
        uint64_t idx = (i * 11) % 64;
        switch(i) {
            case 0: case_0(idx); break;
            case 1: case_1(idx); break;
            case 2: case_2(idx); break;
            case 3: case_3(idx); break;
            case 4: case_4(idx); break;
            case 5: case_5(idx); break;
            case 6: case_6(idx); break;
            case 7: case_7(idx); break;
            case 8: case_8(idx); break;
        }
    }
    return 0;
}
