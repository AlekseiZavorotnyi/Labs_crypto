#ifndef LABS_CRYPTO_FEISTELNETWORK_H
#define LABS_CRYPTO_FEISTELNETWORK_H
#include <cstddef>
#include <memory>
#include "./Interfaces/IKeyExpansion.h"
#include "./Interfaces/IEncryptionRound.h"
#include "./Bit_operations.h"

class Feistel_network {
private:
    std::unique_ptr<IKeyExpansion> key_expansion;
    std::unique_ptr<IEncryptionRound> round_function;
    size_t num_rounds;
    size_t block_size;
    size_t key_size;
    std::unique_ptr<uint8_t[]> round_keys;
    bool were_keysSetup = false;

public:
    Feistel_network(std::unique_ptr<IKeyExpansion> key_expansion,
                    std::unique_ptr<IEncryptionRound> round_function,
                    size_t rounds, size_t blk_size, size_t k_size);

    void en_de_crypt(const uint8_t* block, uint8_t* output, bool encrypt);
    void setupKeys(const uint8_t* key, size_t key_len);
};
#endif //LABS_CRYPTO_FEISTELNETWORK_H
