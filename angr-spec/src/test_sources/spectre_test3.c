#include <stdint.h>
#include <stddef.h>

// Simulated memory setup
uint8_t publicarray[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t publicarray2[256 * 512];
uint8_t secretarray[16] = {10,21,32,43,54,65,76,87,98,109,110,121,132,143,154,165};
volatile uint8_t temp = 0;

// Constants
uint64_t publicarray_size = 16;
uint64_t publicarray_mask = 15;
uint64_t secretarray_size = 16;

// 🔥 LEAKY
void case_1(uint64_t idx) {
    if (idx < publicarray_size) {
        temp &= publicarray2[publicarray[idx] * 512];
    }
}

// 🔥 LEAKY
void case_2(uint64_t idx) {
    if (idx < publicarray_size) {
        if (publicarray[idx] == 42) {
            temp &= 0xFF; // no memory read
        }
    }
}

// 🔥 LEAKY — Spectre v1 gadget: secret read under misprediction
void case_3(uint64_t idx) {
    if (idx < publicarray_size) {
        temp &= publicarray2[secretarray[idx] * 512];
    }
}

// 🔥 LEAKY — Slight variant, still vulnerable under speculation
void case_4(uint64_t idx) {
    if (idx < secretarray_size / 2) {
        uint8_t val = secretarray[(idx << 1)];
        temp &= publicarray2[val * 512];
    }
}

// ✅ SAFE — masked indexing to avoid attacker-controlled OOB access
void case_5(uint64_t idx) {
    uint64_t safe_idx = idx & publicarray_mask;
    if (idx < publicarray_size) {
        temp &= publicarray2[publicarray[safe_idx] * 512];
    }
}

// 🔥 LEAKY — attacker can control loop iteration and leak secret
void case_6(uint64_t idx) {
    if (idx < publicarray_size) {
        for (int i = 0; i <= idx; i++) {
            temp &= publicarray2[secretarray[i & 15] * 512];
        }
    }
}

// ✅ SAFE — dummy condition, speculation doesn't matter
void case_7(uint64_t idx) {
    if (idx == 0xBEEF) {
        temp &= 0x55;
    }
}

int main() {
    case_1(0);
    case_2(0);
    case_3(2);  // leaky
    case_4(3);  // leaky
    case_5(4);
    case_6(5);  // leaky
    case_7(6);
    return 0;
}
