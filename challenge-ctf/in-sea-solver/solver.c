// compile : gcc -O2 -maes -mssse3 solver.c -o solver

#include <stdio.h>
#include <stdint.h>
#include <wmmintrin.h>

// Ciphertext 2 blocks (32 bytes)
uint8_t encrypted_flag[32] = {
    0xf4, 0x4c, 0x68, 0xee, 0x5e, 0xfc, 0x47, 0xb9,
    0x91, 0xe4, 0x7d, 0xa9, 0xe9, 0x5e, 0xd0, 0x39,
    0x41, 0x89, 0xc0, 0xdf, 0x11, 0x2b, 0x28, 0x1e,
    0x8a, 0xbe, 0x31, 0x9c, 0x66, 0x0c, 0x6b, 0x2a
};

// AES-128 key 16 bytes
uint8_t key_bytes[16] = {
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff
};

// Macro buat generate fungsi key expansion step dengan immediate rcon
#define KEY_EXP_STEP(rcon_val) \
__m128i aes_128_key_expansion_step_##rcon_val(__m128i key) { \
    __m128i keygen = _mm_aeskeygenassist_si128(key, rcon_val); \
    keygen = _mm_shuffle_epi32(keygen, _MM_SHUFFLE(3,3,3,3)); \
    __m128i temp = key; \
    temp = _mm_xor_si128(temp, _mm_slli_si128(temp, 4)); \
    temp = _mm_xor_si128(temp, _mm_slli_si128(temp, 4)); \
    temp = _mm_xor_si128(temp, _mm_slli_si128(temp, 4)); \
    return _mm_xor_si128(temp, keygen); \
}

KEY_EXP_STEP(0x01)
KEY_EXP_STEP(0x02)
KEY_EXP_STEP(0x04)
KEY_EXP_STEP(0x08)
KEY_EXP_STEP(0x10)
KEY_EXP_STEP(0x20)
KEY_EXP_STEP(0x40)
KEY_EXP_STEP(0x80)
KEY_EXP_STEP(0x1b)
KEY_EXP_STEP(0x36)

void key_expansion(const uint8_t *key, __m128i *round_keys) {
    round_keys[0] = _mm_loadu_si128((const __m128i*)key);
    round_keys[1] = aes_128_key_expansion_step_0x01(round_keys[0]);
    round_keys[2] = aes_128_key_expansion_step_0x02(round_keys[1]);
    round_keys[3] = aes_128_key_expansion_step_0x04(round_keys[2]);
    round_keys[4] = aes_128_key_expansion_step_0x08(round_keys[3]);
    round_keys[5] = aes_128_key_expansion_step_0x10(round_keys[4]);
    round_keys[6] = aes_128_key_expansion_step_0x20(round_keys[5]);
    round_keys[7] = aes_128_key_expansion_step_0x40(round_keys[6]);
    round_keys[8] = aes_128_key_expansion_step_0x80(round_keys[7]);
    round_keys[9] = aes_128_key_expansion_step_0x1b(round_keys[8]);
    round_keys[10] = aes_128_key_expansion_step_0x36(round_keys[9]);
}

void decrypt_block(const uint8_t *ciphertext, uint8_t *plaintext, const __m128i *round_keys) {
    __m128i m = _mm_loadu_si128((const __m128i*)ciphertext);

    // Initial AddRoundKey with last round key
    m = _mm_xor_si128(m, round_keys[10]);

    // 9 rounds
    for (int i = 9; i > 0; --i) {
        __m128i rk_inv = _mm_aesimc_si128(round_keys[i]); // invert round key for decryption
        m = _mm_aesdec_si128(m, rk_inv);
    }

    // Final round
    m = _mm_aesdeclast_si128(m, round_keys[0]);

    _mm_storeu_si128((__m128i*)plaintext, m);
}

int main() {
    __m128i round_keys[11];
    uint8_t decrypted_flag[32];

    key_expansion(key_bytes, round_keys);

    decrypt_block(encrypted_flag, decrypted_flag, round_keys);
    decrypt_block(encrypted_flag + 16, decrypted_flag + 16, round_keys);

    printf("Decrypted flag: ");
    for (int i = 0; i < 32; i++) {
        printf("%c", decrypted_flag[i]);
    }
    printf("\n");

    return 0;
}
