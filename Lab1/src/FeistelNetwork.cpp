#include "./FeistelNetwork.h"
#include <cstring>
#include <stdexcept>

// Конструктор
Feistel_network::Feistel_network(std::unique_ptr<IKeyExpansion> key_expansion,
                                 std::unique_ptr<IEncryptionRound> round_function,
                                 size_t rounds, size_t blk_size, size_t k_size)
        : key_expansion(std::move(key_expansion)),
          round_function(std::move(round_function)),
          num_rounds(rounds),
          block_size(blk_size),
          key_size(k_size),
          round_keys(std::unique_ptr<uint8_t[]>(new uint8_t[rounds * k_size])) {}

void Feistel_network::en_de_crypt(const uint8_t* block, uint8_t* output, bool encrypt) {
    if (!were_keysSetup) {
        throw std::runtime_error("Keys not setup. Call setupKeys() first.");
    }
    if (block_size % 2 != 0) {
        throw std::invalid_argument("Block size must be even");
    }

    const size_t half_size = block_size / 2;

    // Выделяем только два рабочих буфера
    uint8_t* L = new uint8_t[half_size];
    uint8_t* R = new uint8_t[half_size];
    uint8_t* F = new uint8_t[half_size];

    // Инициализация
    std::memcpy(L, block, half_size);
    std::memcpy(R, block + half_size, half_size);

    for (size_t i = 0; i < num_rounds; ++i) {
        size_t round_idx = encrypt ? i : num_rounds - 1 - i;
        const uint8_t* current_key = round_keys.get() + (round_idx * key_size);

        // F(R, K)
        round_function->encryptRound(R, current_key, F);

        // Новый L и R: (L,R) -> (R, L xor F(R,K))
        for (size_t j = 0; j < half_size; ++j) {
            uint8_t newR = L[j] ^ F[j];
            L[j] = R[j];   // старый R становится новым L
            R[j] = newR;   // новый R
        }
    }

    // Собираем результат: (R,L)
    std::memcpy(output, R, half_size);
    std::memcpy(output + half_size, L, half_size);

    delete[] L;
    delete[] R;
    delete[] F;
}

void Feistel_network::setupKeys(const uint8_t* key, size_t key_len) {
    were_keysSetup = true;
    key_expansion->key_extension(key, key_len, round_keys.get(), num_rounds);
}