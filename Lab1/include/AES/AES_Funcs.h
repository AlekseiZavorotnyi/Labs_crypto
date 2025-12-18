#ifndef LABS_CRYPTO_AES_FUNCS_H
#define LABS_CRYPTO_AES_FUNCS_H

#include <cstdint>
#include <cstddef>

constexpr int perm16[16] = {
        0, 4, 8, 12,
        1, 5, 9, 13,
        2, 6, 10, 14,
        3, 7, 11, 15,
};

constexpr int perm24[24] = {
        0, 4, 8, 12, 16, 20,
        1, 5, 9, 13, 17, 21,
        2, 6, 10, 14, 18, 22,
        3, 7, 11, 15, 19, 23,
};

constexpr int perm32[32] = {
        0, 4, 8, 12, 16, 20, 24, 28,
        1, 5, 9, 13, 17, 21, 25, 29,
        2, 6, 10, 14, 18, 22, 26, 30,
        3, 7, 11, 15, 19, 23, 27, 31,
};

class AES_Funcs {
public:
    static void sub_bytes(uint8_t *state, size_t byte_len, const uint8_t* S_box);

    static void shift_rows(uint8_t *state, size_t byte_len, bool inverted);

    static void mix_columns(uint8_t *state, size_t byte_len, bool inverted);

    static void add_round_key(uint8_t *state, size_t byte_len, const uint8_t* r_key);
};


#endif //LABS_CRYPTO_AES_FUNCS_H
