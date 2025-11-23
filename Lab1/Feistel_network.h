#include "Bit_operations.h"
#include <algorithm>
#include <stdexcept>
#include <vector>
#include <cstring>

class Feistel_network {
private:
    std::unique_ptr<IKeyExpansion> key_expansion;
    std::unique_ptr<IEncryptionRound> round_function;
    std::unique_ptr<uint8_t[]> round_keys;
    size_t num_rounds;
    size_t block_size;
    size_t key_size;
    bool were_keysSetup = false;

public:
    Feistel_network(std::unique_ptr<IKeyExpansion> key_expansion,
                    std::unique_ptr<IEncryptionRound> round_function,
                    size_t rounds, size_t blk_size, size_t k_size)
            : key_expansion(std::move(key_expansion)),
              round_function(std::move(round_function)),
              num_rounds(rounds),
              block_size(blk_size),
              key_size(k_size),
              round_keys(new uint8_t[rounds * k_size]) {}

    void en_de_crypt(const uint8_t* block, uint8_t* output, bool encrypt) {
        if (!were_keysSetup) {
            throw std::runtime_error("Keys not setup. Call setupKeys() first.");
        }
        if (block_size % 2 != 0) {
            throw std::invalid_argument("Block size must be even");
        }

        size_t half_size = block_size / 2;
        std::unique_ptr<uint8_t[]> L_prev(new uint8_t[half_size]);
        std::unique_ptr<uint8_t[]> R_prev(new uint8_t[half_size]);
        std::unique_ptr<uint8_t[]> temp(new uint8_t[half_size]);
        std::unique_ptr<uint8_t[]> res_F(new uint8_t[half_size]);

        std::copy(block, block + half_size, L_prev.get());
        std::copy(block + half_size, block + block_size, R_prev.get());

        for (size_t i = 0; i < num_rounds; i++) {
            size_t round_idx = encrypt ? i : num_rounds - 1 - i;
            const uint8_t* current_key = round_keys.get() + (round_idx * key_size);

            std::copy(R_prev.get(), R_prev.get() + half_size, temp.get());
            round_function->encryptRound(R_prev.get(), current_key, res_F.get());

            for (size_t j = 0; j < half_size; j++) {
                R_prev[j] = L_prev[j] ^ res_F[j];
            }
            std::copy(temp.get(), temp.get() + half_size, L_prev.get());
        }

        std::copy(R_prev.get(), R_prev.get() + half_size, output);
        std::copy(L_prev.get(), L_prev.get() + half_size, output + half_size);
    }

    void setupKeys(const uint8_t* key, size_t key_len) {
        were_keysSetup = true;
        key_expansion->key_extension(key, key_len, round_keys.get(), num_rounds);
    }
};


class DESRound : public IEncryptionRound {
private:
    ByteOrder byte_order;

public:
    explicit DESRound(ByteOrder order = ByteOrder::BIG_ENDIAN) : byte_order(order) {}

    void applyE(const uint8_t* inputBlock, uint8_t* output) {
        static const int E[] = {
                31,  0,  1,  2,  3,  4,  3,  4,  5,  6,  7,  8,
                7,  8,  9, 10, 11, 12, 11, 12, 13, 14, 15, 16,
                15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24,
                23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31,  0
        };
        P_block(inputBlock, 4, E, 48, output, ByteOrder::BIG_ENDIAN, StartIndex::ZERO);
    }

    void applySboxes(const uint8_t* input48, uint8_t* output32) {
        static const uint8_t S_BOXES[8][4][16] = {
                {
                        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
                        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
                        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
                        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
                },
                {
                        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
                        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
                        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
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
                        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5,  11, 12,  7,  2, 14}
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

        uint64_t input64 = 0;
        for (int i = 0; i < 6; i++) {
            input64 = (input64 << 8) | input48[i];
        }
        input64 <<= 16;
        uint32_t result = 0;

        for (int sbox = 0; sbox < 8; sbox++) {
            // Извлекаем 6 бит для S-блока (старшие 48 бит input64)
            int startBit = 16 + (7 - sbox) * 6; // Начинаем с старших битов

            // Получаем строку и столбец
            int row = ((input64 >> (startBit + 5)) & 1) << 1; // Первый бит
            row |= ((input64 >> (startBit + 0)) & 1);          // Последний бит

            int col = (input64 >> (startBit + 1)) & 0xF;       // Средние 4 бита

            int sboxValue = S_BOXES[sbox][row][col];

            // Записываем 4 бита результата
            result = (result << 4) | sboxValue;
        }

        // Преобразуем результат в байты
        for (int i = 0; i < 4; i++) {
            output32[i] = (result >> (24 - i * 8)) & 0xFF;
        }
    }

    void applyP(const uint8_t* input32, uint8_t* output32) {
        static const int P_TABLE[] = {
                15,  6, 19, 20, 28, 11, 27, 16,  0, 14, 22, 25,  4, 17, 30,  9,
                1,  7, 23, 13, 31, 26,  2,  8, 18, 12, 29,  5, 21, 10,  3, 24
        };
        P_block(input32, 4, P_TABLE, 32, output32, byte_order, StartIndex::ZERO);
    }

    void encryptRound(const uint8_t* inputBlock, const uint8_t* roundKey, uint8_t* output) override {
        uint8_t expanded[6];
        uint8_t xored[6];
        uint8_t sboxed[4];

        applyE(inputBlock, expanded);

        // XOR с ключом
        for (size_t i = 0; i < 6; i++) {
            xored[i] = expanded[i] ^ roundKey[i];
        }

        applySboxes(xored, sboxed);
        applyP(sboxed, output);
    }
};

class DESKeyExpansion : public IKeyExpansion {
private:
    ByteOrder byte_order;

public:
    explicit DESKeyExpansion(ByteOrder order = ByteOrder::BIG_ENDIAN) : byte_order(order) {}

    void key_extension(const uint8_t* input_key, size_t key_len, uint8_t* round_keys, size_t rounds) override {
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
};

class DES : public ISymmetricCipher {
private:
    Feistel_network feistel;
    ByteOrder byte_order;

public:
    explicit DES(ByteOrder byte_order = ByteOrder::BIG_ENDIAN) : byte_order(byte_order),
    feistel(std::make_unique<DESKeyExpansion>(byte_order),
            std::make_unique<DESRound>(byte_order), 16, 8, 6) {}

    void encrypt(const uint8_t* input, uint8_t* output) override {
        feistel.en_de_crypt(input, output, true);
    }

    void decrypt(const uint8_t* input, uint8_t* output) override {
        feistel.en_de_crypt(input, output, false);
    }

    void setupKeys(const uint8_t* key, size_t key_len) override {
        feistel.setupKeys(key, key_len);
    }

    size_t blockSize() const override { return 8; }
    size_t keySize() const override { return 8; }
};

class DESAdapter {
private:
    DES des_impl;

public:
    void encrypt(const uint8_t* data, const uint8_t* key, uint8_t* output) {
        des_impl.setupKeys(key, 8);
        des_impl.encrypt(data, output);
    }

    void decrypt(const uint8_t* data, const uint8_t* key, uint8_t* output) {
        des_impl.setupKeys(key, 8);
        des_impl.decrypt(data, output);
    }
};

class DEALRound : public IEncryptionRound {
private:
    DESAdapter des_adapter_;
    ByteOrder byte_order;

    void modifyKey(const uint8_t* originalKey, uint8_t modifier, uint8_t* modifiedKey) {
        for (size_t i = 0; i < 8; i++) {
            modifiedKey[i] = originalKey[i] ^ modifier;
        }
    }

public:
    explicit DEALRound(ByteOrder order = ByteOrder::BIG_ENDIAN) : byte_order(order) {}

    void encryptRound(const uint8_t* inputBlock, const uint8_t* roundKey, uint8_t* output) override {
        uint8_t temp1[8], temp2[8];
        uint8_t modifiedKey1[8], modifiedKey2[8];

        // Создаем модифицированные ключи
        modifyKey(roundKey, 0x0F, modifiedKey1);
        modifyKey(roundKey, 0xF0, modifiedKey2);

        // 3DES-like структура: E-D-E
        des_adapter_.encrypt(inputBlock, roundKey, temp1);
        des_adapter_.decrypt(temp1, modifiedKey1, temp2);
        des_adapter_.encrypt(temp2, modifiedKey2, output);
    }
};

class DEALKeyExpansion : public IKeyExpansion {
private:
    ByteOrder byte_order;

public:
    explicit DEALKeyExpansion(ByteOrder order = ByteOrder::BIG_ENDIAN) : byte_order(order) {}

    void key_extension(const uint8_t* input_key, size_t key_len, uint8_t* round_keys, size_t rounds) override {
        if (key_len != 16 && key_len != 24 && key_len != 32) {
            throw std::invalid_argument("DEAL key must be 16/24/32 bytes (128/192/256 bits)");
        }

        // Разбиваем ключ на части по 8 байт
        const uint8_t* parts[4] = { nullptr, nullptr, nullptr, nullptr };
        size_t parts_count = 0;

        if (key_len == 16) {
            // 128-битный ключ: K1, K2, K1, K2
            parts[0] = input_key;
            parts[1] = input_key + 8;
            parts[2] = input_key;       // повтор K1
            parts[3] = input_key + 8;   // повтор K2
            parts_count = 4;
        } else if (key_len == 24) {
            // 192-битный ключ: K1, K2, K3, K1
            parts[0] = input_key;
            parts[1] = input_key + 8;
            parts[2] = input_key + 16;
            parts[3] = input_key;       // повтор K1
            parts_count = 4;
        } else { // 256 бит
            parts[0] = input_key;
            parts[1] = input_key + 8;
            parts[2] = input_key + 16;
            parts[3] = input_key + 24;
            parts_count = 4;
        }

        // Генерация раундовых ключей
        for (size_t r = 0; r < rounds; ++r) {
            uint8_t* rk = round_keys + (r * 8);
            for (size_t b = 0; b < 8; ++b) {
                uint8_t val = 0;
                for (size_t p = 0; p < parts_count; ++p) {
                    val ^= parts[p][b]; // XOR всех частей
                }
                val ^= static_cast<uint8_t>(r + 1); // добавляем номер раунда
                rk[b] = val;
            }
        }
    }
};

class DEAL : public ISymmetricCipher {
private:
    Feistel_network feistel;
    ByteOrder byte_order;
    size_t actual_key_size;

public:
    explicit DEAL(size_t key_size = 16, ByteOrder byte_order = ByteOrder::BIG_ENDIAN)
            : byte_order(byte_order), actual_key_size(key_size),
              feistel(std::make_unique<DEALKeyExpansion>(byte_order),
                      std::make_unique<DEALRound>(byte_order),
                      6, 16, 8) {

        if (key_size != 16 && key_size != 24 && key_size != 32) {
            throw std::invalid_argument("DEAL key must be 16/24/32 bytes (128/192/256 bits)");
        }
    }

    void encrypt(const uint8_t* input, uint8_t* output) override {
        feistel.en_de_crypt(input, output, true);
    }

    void decrypt(const uint8_t* input, uint8_t* output) override {
        feistel.en_de_crypt(input, output, false);
    }

    void setupKeys(const uint8_t* key, size_t key_len) override {
        if (key_len != actual_key_size) {
            throw std::invalid_argument("Provided key size doesn't match expected key size");
        }
        feistel.setupKeys(key, key_len);
    }

    size_t blockSize() const override { return 16; }
    size_t keySize() const override { return actual_key_size; }
};