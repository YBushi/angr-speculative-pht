#include <stdint.h>
#include <stddef.h>
#ifdef __MSVC__
#define FORCEDINLINE __forceinline
#define NOINLINE __declspec(noinline)
#else
#define FORCEDINLINE __attribute__((always_inline)) inline
#define NOINLINE __attribute__((noinline))
#endif

uint64_t publicarray_mask = 15;
uint64_t publicarray_size = 16;
uint8_t publicarray[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t publicarray2[512 * 256] = { 20 };

// The attacker's goal in all of these examples is to learn any of the secret data in secretarray
uint64_t secretarray_size = 16;
uint8_t secretarray[16] = { 10,21,32,43,54,65,76,87,98,109,110,121,132,143,154,165 };
volatile uint8_t temp = 0;

// 🔥 classic leaky Spectre v1
void case_0(uint64_t idx) {
    if (idx < publicarray_size) {
        temp &= publicarray2[secretarray[idx] * 512];
        return;
    }
}

// ✅ safe — uses masking to avoid OOB access
void case_1(uint64_t idx) {
    if (idx < publicarray_size) {
        temp &= publicarray2[publicarray[idx] * 512];
    }
}

// 🔥 leaky — double indexing via secret
void case_2(uint64_t idx) {
    if (idx < publicarray_size) {
        uint8_t s = secretarray[idx];
        temp &= publicarray2[publicarray[s] * 512];
    }
}

// ✅ safe — speculation on constant-time path
void case_3(uint64_t idx) {
    if (idx < publicarray_size) {
        temp &= 0xAA;
    }
}

// 🔥 leaky — speculatively bypasses check + pointer arithmetic
void case_4(uint64_t idx) {
    if (idx < secretarray_size) {
        uint8_t *ptr = secretarray + idx;
        temp &= publicarray2[(*ptr) * 512];
    }
}

// 🚫 not speculative — always taken
void case_5(uint64_t idx) {
    if (1) {
        temp &= 0x42;
    }
}

// 🔥 LEAKY
void case_6(uint64_t idx) {
    if (idx < secretarray_size) {
        uint8_t s = secretarray[idx];
        if (s == 42) {
            temp |= 0x1;
        }
    }
}

// 🔥 leaky — loop variant
void case_7(uint64_t idx) {
    for (uint64_t i = 0; i <= idx && i < publicarray_size; ++i) {
        temp &= publicarray2[secretarray[i] * 512];
    }
}

// 🔥 leaky — loop variant
void case_8(uint64_t idx) {
    for (uint64_t i = 0; i <= idx && i < publicarray_size; ++i) {
        temp &= publicarray2[publicarray[i] * 512];
    }
}

// 🚫 no branch at all
void case_9(uint64_t idx) {
    temp &= 0xFF;
}
int case_10(uint64_t idx) {
    int a = secretarray[0];
    int b = a ^ 1;
    int c = a ^ 2;
    int d = b ^ c ^ 3;
    if(d) {
        return idx;
    }
    return 2;
}

// This case is not leaky, because the speculative window expires before the mem_read is reached
void case_11(uint64_t idx) {
    if (idx < publicarray_size) {
        temp &= publicarray2[publicarray[idx] * 512];
    }
}


int main() {
    case_0(2);   // 🔥
    case_1(2);   // ✅
    case_2(2);   // 🔥
    case_3(2);   // ✅
    case_4(2);   // 🔥
    case_5(2);   // 🚫
    case_6(2);   // ✅
    case_7(2);   // 🔥
    case_8(2);   // ✅
    case_9(2);   // 🚫
    case_10(2);
    case_11(0);
    return 0;
}
