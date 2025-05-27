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

// this is mostly used to prevent the compiler from optimizing out certain operations
volatile uint8_t temp = 0;

// Secure, masking
void case_0(uint64_t idx) {
    if (idx < publicarray_size) {
        temp &= publicarray2[publicarray[idx & publicarray_mask] * 512];
    }
}

//CT: Secure | Spec-CT: Insecure
void case_1(uint64_t idx) {
    if (idx < publicarray_size) {
        uint8_t v = publicarray[idx];      
        temp &= publicarray2[v * 512];
    }
}

//CT: Insecure | Spec-CT: Insecure
void case_2(uint64_t idx) {
    if (idx < secretarray_size) {
        uint8_t s = secretarray[idx];
        temp &= publicarray2[s * 512];
    }
}

//CT: Secure | Spec-CT: Insecure
void case_3(uint64_t idx) {
    if (idx < publicarray_size) {
        uint64_t safe_idx = idx & (publicarray_size - 1);
        temp &= publicarray2[publicarray[safe_idx] * 512];
    }
}

//CT: Secure | Spec-CT: Secure -> Spec window will be 15, should run out 
void case_4(uint64_t idx) {
    if (idx < publicarray_size) {
        __asm__ __volatile__(
            "nop\n\t"  // 1
            "nop\n\t"  // 2
            "nop\n\t"  // 3
            "nop\n\t"  // 4
            "nop\n\t"  // 5
            "nop\n\t"  // 6
            "nop\n\t"  // 7
            "nop\n\t"  // 8
            "nop\n\t"  // 9
            "nop\n\t"  // 10
            "nop\n\t"  // 11
            "nop\n\t"  // 12
            "nop\n\t"  // 13
            "nop\n\t"  // 14
            "nop\n\t"  // 15
            "nop\n\t"  // 16
            "nop\n\t"  // 17
            "nop\n\t"  // 18
            "nop\n\t"  // 19
            "nop\n\t"  // 20
        );
        temp &= publicarray2[publicarray[idx] * 512];
    }
}
void case_5(uint64_t idx) {
    if (idx < 10) {
        __asm__ __volatile__(
            "nop\n\t"  // 1
            "nop\n\t"  // 2
            "nop\n\t"  // 3
            "nop\n\t"  // 4
            "nop\n\t"  // 5
        );
        if (idx < publicarray_size) {
            __asm__ __volatile__(
                "nop\n\t"  // 1
                "nop\n\t"  // 2
                "nop\n\t"  // 3
                "nop\n\t"  // 4
                "nop\n\t"  // 5
            );
            if (idx >= publicarray_size) {
                __asm__ __volatile__(
                    "nop\n\t"  // 1
                    "nop\n\t"  // 2
                    "nop\n\t"  // 3
                    "nop\n\t"  // 4
                    "nop\n\t"  // 5
                    "nop\n\t"  // 6
                    "nop\n\t"  // 7
                    "nop\n\t"  // 8
                    "nop\n\t"  // 9
                    "nop\n\t"  // 10
                    "nop\n\t"  // 11
                    "nop\n\t"  // 12
                    "nop\n\t"  // 13
                    "nop\n\t"  // 14
                    "nop\n\t"  // 15
                    "nop\n\t"  // 16
                    "nop\n\t"  // 17
                    "nop\n\t"  // 18
                    "nop\n\t"  // 19
                    "nop\n\t"  // 20
                );
                temp &= publicarray2[publicarray[idx] * 512]; 
            }
        }
    }
}

void case_6(uint64_t idx) {
    if (idx < 10) {
        __asm__ __volatile__(
            "nop\n\t"  // 1
            "nop\n\t"  // 2
            "nop\n\t"  // 3
            "nop\n\t"  // 4
            "nop\n\t"  // 5
        );
        if (idx < 20) {
            __asm__ __volatile__(
                "nop\n\t"  // 1
                "nop\n\t"  // 2
                "nop\n\t"  // 3
                "nop\n\t"  // 4
                "nop\n\t"  // 5
            );
            if (idx < publicarray_size) {
                __asm__ __volatile__(
                    "nop\n\t"  // 1
                    "nop\n\t"  // 2
                    "nop\n\t"  // 3
                    "nop\n\t"  // 4
                    "nop\n\t"  // 5
                );
                temp &= publicarray2[publicarray[idx] * 512]; 
                temp &= publicarray2[secretarray[idx] * 512];
            }
        }
    }
}
    

void case_7(uint64_t idx) {
    if (idx < publicarray_size){
        __asm__ __volatile__(
            "nop\n\t"  // 1
            "nop\n\t"  // 2
            "nop\n\t"  // 3
            "nop\n\t"  // 4
            "nop\n\t"  // 5
            "nop\n\t"  // 6
            "nop\n\t"  // 7
            "nop\n\t"  // 8
            "nop\n\t"  // 9
            "nop\n\t"  // 10
            "nop\n\t"  // 11
            "nop\n\t"  // 12
            "nop\n\t"  // 13
            "nop\n\t"  // 14
            "nop\n\t"  // 15
        );
        if (publicarray[idx] < 20) {
            __asm__ __volatile__(
                "nop\n\t"  // 1
                "nop\n\t"  // 2
                "nop\n\t"  // 3
                "nop\n\t"  // 4
                "nop\n\t"  // 5
                "nop\n\t"  // 6
                "nop\n\t"  // 7
                "nop\n\t"  // 8
                "nop\n\t"  // 9
                "nop\n\t"  // 10
            );
            temp &= secretarray[publicarray[idx]];
        }
    }
}


// 🔥 CT-violation only in non-speculative path via double indexing

int main(void) {
    // call each case with an out-of-bounds idx to trigger the leak in normal mode
    case_0(0);
    case_1(0);
    case_2(0);
    case_3(0);
    case_4(0);
    case_5(0);
    case_6(0);
    case_7(0);
    return 0;
}
