#include "./FeistelNetwork.h"

// Конструктор
Feistel_network::Feistel_network(std::unique_ptr<IKeyExpansion> key_expansion,
                                 std::unique_ptr<IEncryptionRound> round_function,
                                 size_t rounds, size_t blk_size, size_t k_size)
        : key_expansion(std::move(key_expansion)),
          round_function(std::move(round_function)),
          num_rounds(rounds),
          block_size(blk_size),
          key_size(k_size),
          round_keys(new uint8_t[rounds * k_size]) {}

// Метод шифрования/расшифрования
void Feistel_network::en_de_crypt(const uint8_t* block, uint8_t* output, bool encrypt) {
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

// Метод установки ключей
void Feistel_network::setupKeys(const uint8_t* key, size_t key_len) {
    were_keysSetup = true;
    key_expansion->key_extension(key, key_len, round_keys.get(), num_rounds);
}