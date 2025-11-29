#include "./DES/DESKeyExpansion.h"

DESKeyExpansion::DESKeyExpansion(ByteOrder order) : byte_order(order) {}

void DESKeyExpansion::key_extension(const uint8_t* input_key, size_t key_len, uint8_t* round_keys, [[maybe_unused]]size_t rounds) {
    if (key_len != 8) {
        throw std::invalid_argument("DES key must be 8 bytes (64 bits)");
    }

    static const int PC1_C[] = {
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36
    };

    static const int PC1_D[] = {
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    };

    static const int PC2[] = {
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    };

    uint8_t C[4] = {0}, D[4] = {0};
    P_block(input_key, 8, PC1_C, 28, C, byte_order, StartIndex::ONE);
    P_block(input_key, 8, PC1_D, 28, D, byte_order, StartIndex::ONE);

    uint32_t Ci = *(reinterpret_cast<uint32_t*>(C));
    uint32_t Di = *(reinterpret_cast<uint32_t*>(D));

    uint32_t mask = (1u << 28) - 1;

    for (int i = 1; i <= 16; i++) {
        size_t shift;
        if (i == 1 || i == 2 || i == 9 || i == 16) {
            shift = 1;
        } else {
            shift = 2;
        }

        Ci = ((Ci << shift) | (Ci >> (28 - shift))) & mask;
        Di = ((Di << shift) | (Di >> (28 - shift))) & mask;

        uint64_t CiDi = 0;
        uint64_t CiShift = Ci;
        CiShift = CiShift << 28;
        CiDi = CiShift | (Di & mask);

        auto* CiDiArr = reinterpret_cast<uint8_t*>(&CiDi);

        uint8_t* round_key = round_keys + ((i-1) * 6);
        P_block(CiDiArr, 7, PC2, 48, round_key, byte_order, StartIndex::ONE);
    }
}