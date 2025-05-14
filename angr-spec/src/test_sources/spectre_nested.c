#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Public and secret arrays
uint8_t publicarray[16]       = {0};
uint8_t publicarray2[256 * 512];
uint8_t secretarray[16]       = {
    100,101,102,103,104,105,106,107,
    108,109,110,111,112,113,114,115
};
volatile uint8_t temp = 0;

uint64_t publicarray_size   = 16;
uint64_t secretarray_size   = 16;
uint64_t publicarray_mask   = 15;

// ────────────────
// case_deep1:
// three levels of nesting, all satisfiable
// ────────────────
void case_deep1(uint64_t idx) {
    if (idx < publicarray_size) {              // level 1
        if ((idx & 1) == 0) {                  // level 2
            if (idx < 8) {                    // level 3
                // --- heavy dummy work begins ---
                // do 200 integer ops to inflate instruction count
                volatile uint64_t x = idx;
                for (int j = 0; j < 200; j++) {
                    // arbitrary mix of arithmetic and memory ops
                    x = x * 3 + j;
                    temp ^= (uint8_t)(x & 0xFF);
                    temp |= publicarray[j & publicarray_mask];
                }
                // --- dummy work ends ---

                // now the real leak: secretarray[idx] taints temp,
                // then used to read publicarray
                temp ^= secretarray[idx];
                int a = publicarray[temp];
                (void)a;
            } else {
                temp ^= publicarray[idx & publicarray_mask];
            }
        } else {
            temp ^= 0xFF;
        }
    }
}

// ────────────────
// case_deep_unsat:
// inner branch impossible given outer guard
// ────────────────
void case_deep_unsat(uint64_t idx) {
    if (idx < 8) {                             // level 1
        if (idx >= 8) {                        // level 2 — unsatisfiable when idx<8
            // would leak secretarray[0], but unreachable
            temp &= secretarray[0];
        }
    }
}

// ────────────────
// case_deep2:
// mix of loops and nesting, satisfiable leak
// ────────────────
void case_deep2(uint64_t idx) {
    if (idx < publicarray_size) {              // level 1
        for (uint64_t i = 0; i < idx; i++) {   // level 2
            if ((idx ^ i) & 1) {              // level 3
                // leak secretbyte i
                temp |= secretarray[i];
            } else {
                temp |= publicarray[i];
            }
        }
    }
}

// ────────────────
// case_deep_unsat_loop:
// loop + inner unsat branch
// ────────────────
void case_deep_unsat_loop(uint64_t idx) {
    if (idx < publicarray_size) {              // level 1
        for (uint64_t i = 0; i <= idx; i++) {  // level 2
            if (i > idx) {                    // level 3 — always false
                // unreachable leak
                temp ^= secretarray[0];
            }
        }
    }
}

int main(void) {
    uint64_t test_idx = 3;

    case_deep1(test_idx);           // 🔥 nested leak (sat)
    case_deep_unsat(test_idx);      // 🚫 unreachable leak (unsat)
    case_deep2(test_idx);           // 🔥 loop + nested leak
    case_deep_unsat_loop(test_idx); // 🚫 unreachable inside loop

    // Prevent optimization
    printf("final temp = 0x%02x\n", temp);
    return 0;
}
