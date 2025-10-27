#include <algorithm>
#include "Interfaces.h"
#include <vector>

class DES : public IEncryptionRound, IKeyExpansion{
public:
    mass_b encryptRound(mass_b& inputBlock, mass_b& roundKey) override {

        mass_b expanded = applyE(inputBlock);

        mass_b xored = xorWithKey(expanded, roundKey);

        mass_b sboxed = applySboxes(xored);

        mass_b result = applyP(sboxed);

        return result;
    }

    mass_mass_b key_extension(mass_b& input_key) override{
        if (input_key.size() != 8) {
            throw std::invalid_argument("DES key must be 8 bytes (64 bits)");
        }
        std::vector<std::vector<byte>> RES_KEYS(16);
        mass_i PC1 = {
                57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
        };
        mass_i PC2 = {
                14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
        };
        mass_b res_PC1 = P_block(input_key, PC1, bit_order, StartIndex::ONE);
        std::bitset<56> res_PC1_bits = bytesToBitset<56>(res_PC1);
        std::pair<std::bitset<28>, std::bitset<28>> C_D = splitBitset<56, 28>(res_PC1_bits);
        std::bitset<28> C = C_D.first, D = C_D.second;
        for (int i = 1; i <= 16; i++){
            if (i == 1 || i == 2 || i == 9 || i == 16){
                C << 1;
                D << 1;
            }
            else{
                C << 2;
                D << 2;
            }
            std::bitset<56> comb_C_D = combineBitsets<28, 28>(C, D);
            RES_KEYS[i - 1] = P_block(bitsetToBytes<56>(comb_C_D), PC2, bit_order, StartIndex::ONE);
        }
        return RES_KEYS;
    }

    void set_bitorder(BitOrder new_bit_order){
        bit_order = new_bit_order;
    }

private:
    BitOrder bit_order = BitOrder::BIG_ENDIAN;

    mass_b applyE(mass_b& inputBlock){
        mass_i E = {
                31,  0,  1,  2,  3,  4,
                3,  4,  5,  6,  7,  8,
                7,  8,  9, 10, 11, 12,
                11, 12, 13, 14, 15, 16,
                15, 16, 17, 18, 19, 20,
                19, 20, 21, 22, 23, 24,
                23, 24, 25, 26, 27, 28,
                27, 28, 29, 30, 31,  0
        };
        return P_block(inputBlock, E, BitOrder::BIG_ENDIAN, StartIndex::ZERO);
    }

    mass_b xorWithKey(mass_b& data, mass_b& key){
        if (data.size() != key.size()) {
            throw std::invalid_argument("Arrays must have the same size");
        }

        std::vector<byte> result;
        result.reserve(data.size());

        for (size_t i = 0; i < data.size(); i++) {
            result.push_back(data[i] ^ key[i]);
        }

        return result;
    }

    mass_b applySboxes(mass_b& input48){
        mass_mass_mass_i S_BOXES = {
                {
                        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
                        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
                        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
                        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
                },
                {
                        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
                        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
                        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8,  12, 6,  9,  3,  2, 15},
                        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
                },
                {
                        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
                        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
                        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
                        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
                },
                {
                        { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
                        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
                        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
                        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
                },
                {
                        { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
                        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
                        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
                        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
                },
                {
                        {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
                        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
                        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
                        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
                },
                {
                        { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
                        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
                        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
                        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
                },
                {
                        {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
                        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
                        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
                        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
                }
        };
        std::bitset<48> inputBits = bytesToBitset<48>(input48);
        std::bitset<32> outputBits;

        for (int sbox = 0; sbox < 8; sbox++) {
            int startBit = sbox * 6;

            int row = (inputBits[47 - startBit] ? 2 : 0) |
                      (inputBits[47 - startBit - 5] ? 1 : 0);

            int col = 0;
            for (int i = 0; i < 4; i++) {
                if (inputBits[47 - startBit - 1 - i]) {
                    col |= (1 << (3 - i));
                }
            }

            int sboxValue = S_BOXES[sbox][row][col];

            for (int i = 0; i < 4; i++) {
                outputBits[31 - (sbox * 4 + i)] = (sboxValue >> (3 - i)) & 1;
            }
        }

        return bitsetToBytes<32>(outputBits);
    }

    mass_b applyP(mass_b& input32) {
        if (input32.size() != 4) {
            throw std::invalid_argument("P permutation input must be 32 bits (4 bytes)");
        }

        mass_i P_TABLE = {
                15,  6, 19, 20, 28, 11, 27, 16,
                0, 14, 22, 25,  4, 17, 30,  9,
                1,  7, 23, 13, 31, 26,  2,  8,
                18, 12, 29,  5, 21, 10,  3, 24
        };

        return P_block(input32, P_TABLE, bit_order, StartIndex::ZERO);
    }

    template<size_t N>
    std::bitset<N> bytesToBitset(mass_b& input) {
        size_t expected_bytes = (N + 7) / 8;
        if (input.size() != expected_bytes) {
            throw std::invalid_argument("Input size doesn't match bitset size");
        }

        std::bitset<N> result;

        if (bit_order == BitOrder::BIG_ENDIAN) {
            for (size_t i = 0; i < expected_bytes; i++) {
                auto byte_val = static_cast<uint8_t>(input[i]);
                for (int j = 0; j < 8; j++) {
                    size_t bit_pos = (expected_bytes - 1 - i) * 8 + (7 - j);
                    if (bit_pos < N) {
                        result[bit_pos] = (byte_val >> j) & 1;
                    }
                }
            }
        } else {
            for (size_t i = 0; i < expected_bytes; i++) {
                auto byte_val = static_cast<uint8_t>(input[i]);
                for (int j = 0; j < 8; j++) {
                    size_t bit_pos = i * 8 + j;
                    if (bit_pos < N) {
                        result[bit_pos] = (byte_val >> j) & 1;
                    }
                }
            }
        }

        return result;
    }

    template<size_t N>
    mass_b bitsetToBytes(std::bitset<N>& bs) {
        size_t byte_count = (N + 7) / 8;
        mass_b result(byte_count, byte{0});

        if (bit_order == BitOrder::BIG_ENDIAN) {
            for (size_t i = 0; i < N; i++) {
                if (bs[i]) {
                    size_t byte_index = (N - 1 - i) / 8;
                    size_t bit_index = 7 - ((N - 1 - i) % 8);
                    result[byte_index] |= std::byte{1} << bit_index;
                }
            }
        } else {
            for (size_t i = 0; i < N; i++) {
                if (bs[i]) {
                    size_t byte_index = i / 8;
                    size_t bit_index = i % 8;
                    result[byte_index] |= std::byte{1} << bit_index;
                }
            }
        }

        return result;
    }

    template<size_t N, size_t M>
    std::pair<std::bitset<M>, std::bitset<N - M>> splitBitset(std::bitset<N>& input) {
        static_assert(M < N, "First part size must be less than total size");

        std::bitset<M> left;
        std::bitset<N - M> right;

        for (size_t i = 0; i < M; i++) {
            left[i] = input[i + (N - M)];
        }

        for (size_t i = 0; i < N - M; i++) {
            right[i] = input[i];
        }

        return {left, right};
    }

    template<size_t N, size_t M>
    std::bitset<N + M> combineBitsets(std::bitset<N>& left, std::bitset<M>& right) {
        std::bitset<N + M> result;

        for (size_t i = 0; i < N; i++) {
            result[i + M] = left[i];
        }

        for (size_t i = 0; i < M; i++) {
            result[i] = right[i];
        }

        return result;
    }

    mass_b P_block(mass_b st, mass_i p_bl, BitOrder order = BitOrder::BIG_ENDIAN, StartIndex num_st = StartIndex::ZERO){
        if (p_bl.size() % 8 != 0){
            throw std::invalid_argument("P block must be divisible by 8");
        }
        size_t size_byte = p_bl.size() / 8;
        mass_b res(size_byte, byte{0});
        for (size_t i = 0; i < size_byte; i++){
            for (size_t j = 0; j < 8; j++) {
                size_t byte_index_res = i, bit_index_res = j;
                size_t bit_index = p_bl[byte_index_res * 8 + bit_index_res];
                if (num_st == StartIndex::ONE){
                    bit_index--;
                }
                size_t byte_index_st = bit_index / 8;
                size_t bit_index_st = bit_index % 8;
                if (order == BitOrder::BIG_ENDIAN) {
                    bit_index_res = 7 - bit_index_res;
                    bit_index_st = 7 - bit_index_st;
                }
                uint8_t cur_bit = (static_cast<uint8_t>(st[byte_index_st]) >> bit_index_st) & 1;
                if (cur_bit) {
                    res[byte_index_res] |= std::byte{1} << bit_index_res;
                }
            }
        }
        return res;
    }

};


class Feistel_network : public ISymmetricCipher{
private:
    std::unique_ptr<IKeyExpansion> key;
    std::unique_ptr<IEncryptionRound> F;
    mass_mass_b roundKeys_;
    bool were_keysSetup = false;

    mass_b en_de_crypt(mass_b& block, bool encrypt) {
        if (!were_keysSetup){
            throw std::runtime_error("Keys not setup. Call setupKeys() first.");
        }
        size_t n = block.size();
        if (n % 2 != 0) {
            throw std::invalid_argument("Block size must be even");
        }
        auto keys = roundKeys_;
        if (!encrypt){
            std::reverse(keys.begin(), keys.end());
        }
        mass_b L_prev(block.begin(), block.begin() + n / 2), R_prev(block.begin() + n / 2, block.end());
        for (auto K_cur : keys){
            mass_b temp = R_prev;
            mass_b res_F = F->encryptRound(R_prev, K_cur);
            for (size_t j = 0; j < n; j++){
                R_prev[j] =  L_prev[j] ^ res_F[j];
            }
            L_prev = temp;
        }
        mass_b res = R_prev;
        res.insert(res.end(), L_prev.begin(), L_prev.end());
        return res;
    }
public:
    Feistel_network(std::unique_ptr<IKeyExpansion> Key, std::unique_ptr<IEncryptionRound> F) :
        key(std::move(Key)), F(std::move(F)){}

    mass_b encrypt(mass_b& block) override {
        return en_de_crypt(block, true);
    }

    mass_b decrypt(mass_b& block) override {
        return en_de_crypt(block, false);
    }

    void setupKeys(mass_b& en_de_crypt_key) override{
        were_keysSetup = true;
        roundKeys_ = key->key_extension(en_de_crypt_key);
    }
};