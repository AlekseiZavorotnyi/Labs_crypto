#include <iostream>
#include <cstring>

#include "../include/AES/AESKeyExpansion.h"
#include "../include/AES/AES.h"
#include "../include/AES/AES_Funcs.h"


AES::AES(size_t block_len, size_t key_len, uint8_t* init_key_ptr) : key_len(key_len), block_len(block_len) {
    init_key = new uint8_t[key_len]();
    memcpy(init_key, init_key_ptr, key_len);

    uint16_t mod = 0x11B;
    for (int iter = 0; iter < 256; ++iter) {
        auto i = static_cast<uint8_t>(iter);
        uint8_t y = GF_Service::inverse_mod(i, mod);
        uint8_t y0 = (y >> 0) & 1;
        uint8_t y1 = (y >> 1) & 1;
        uint8_t y2 = (y >> 2) & 1;
        uint8_t y3 = (y >> 3) & 1;
        uint8_t y4 = (y >> 4) & 1;
        uint8_t y5 = (y >> 5) & 1;
        uint8_t y6 = (y >> 6) & 1;
        uint8_t y7 = (y >> 7) & 1;

        uint8_t z0 = y0 ^ y4 ^ y5 ^ y6 ^ y7 ^ 1;
        uint8_t z1 = y0 ^ y1 ^ y5 ^ y6 ^ y7 ^ 1;
        uint8_t z2 = y0 ^ y1 ^ y2 ^ y6 ^ y7 ^ 0;
        uint8_t z3 = y0 ^ y1 ^ y2 ^ y3 ^ y7 ^ 0;
        uint8_t z4 = y0 ^ y1 ^ y2 ^ y3 ^ y4 ^ 0;
        uint8_t z5 = y1 ^ y2 ^ y3 ^ y4 ^ y5 ^ 1;
        uint8_t z6 = y2 ^ y3 ^ y4 ^ y5 ^ y6 ^ 1;
        uint8_t z7 = y3 ^ y4 ^ y5 ^ y6 ^ y7 ^ 0;

        this->S_box[i] = z0 | (z1 << 1) | (z2 << 2) | (z3 << 3) | (z4 << 4) | (z5 << 5) | (z6 << 6) | (z7 << 7);
    }

    for (int i = 0; i < 256; ++i) {
        S_box_inv[S_box[i]] = i;
    }

    int rounds_cnt = key_len == 16 ? 10 : (key_len == 192 ? 12 : 14);
    size_t exp_key_size = (rounds_cnt + 1) * block_len;
    exp_key = new uint8_t[exp_key_size]();

    AESKeyExtension key_extenser(block_len, reinterpret_cast<uint8_t*>(&S_box));
    key_extenser.key_extension(init_key, key_len, exp_key, rounds_cnt);
}

AES::~AES() {
    delete[] exp_key;
    delete[] init_key;
}

void AES::encrypt(const uint8_t* input, uint8_t* output) {
    uint8_t state[32] = {0};
    std::memcpy(state, input, block_len);

    // Определяем количество раундов
    size_t rounds = 0;
    if (key_len == 16) rounds = 10;
    else if (key_len == 24) rounds = 12;
    else if (key_len == 32) rounds = 14;

    // Начальный AddRoundKey
    AES_Funcs::add_round_key(state, block_len, exp_key);

    // Основные раунды
    for (size_t i = 0; i < rounds; ++i) {
        AES_Funcs::sub_bytes(state, block_len, S_box);
        AES_Funcs::shift_rows(state, block_len, false);

        if (i != rounds - 1) {
            AES_Funcs::mix_columns(state, block_len, false);
        }

        AES_Funcs::add_round_key(state, block_len, exp_key + (i + 1) * block_len);
    }

    std::memcpy(output, state, block_len);
}

void AES::decrypt(const uint8_t* input, uint8_t* output) {
    uint8_t state[32] = {0};
    std::memcpy(state, input, block_len);

    // Определяем количество раундов
    size_t rounds = 0;
    if (key_len == 16) rounds = 10;
    else if (key_len == 24) rounds = 12;
    else if (key_len == 32) rounds = 14;

    // Начальный AddRoundKey (обратный порядок)
    AES_Funcs::add_round_key(state, block_len, exp_key + rounds * block_len);

    // Основные раунды в обратном порядке
    for (size_t i = 0; i < rounds; ++i) {
        AES_Funcs::shift_rows(state, block_len, true);
        AES_Funcs::sub_bytes(state, block_len, S_box_inv);
        AES_Funcs::add_round_key(state, block_len, exp_key + (rounds - i - 1) * block_len);

        if (i != rounds - 1) {
            AES_Funcs::mix_columns(state, block_len, true);
        }
    }

    std::memcpy(output, state, block_len);
}

std::size_t AES::blockSize() const {
    return block_len;
}

std::size_t AES::keySize() const {
    return key_len;
}

void AES::setupKeys([[maybe_unused]]const uint8_t *key, [[maybe_unused]]size_t cur_key_len) {

}