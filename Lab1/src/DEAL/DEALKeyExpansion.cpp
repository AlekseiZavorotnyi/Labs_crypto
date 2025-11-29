#include "DEAL/DEALKeyExpansion.h"

DEALKeyExpansion::DEALKeyExpansion(ByteOrder order) : byte_order(order) {}

void DEALKeyExpansion::key_extension(const uint8_t* input_key, size_t key_len, uint8_t* round_keys, size_t rounds) {
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