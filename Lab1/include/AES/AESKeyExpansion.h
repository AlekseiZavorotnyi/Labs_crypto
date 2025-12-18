#ifndef LABS_CRYPTO_AESKEYEXPANSION_H
#define LABS_CRYPTO_AESKEYEXPANSION_H
#include "../Interfaces/IKeyExpansion.h"
#include <cstddef>

class AESKeyExtension : public IKeyExpansion {
private:
    std::size_t block_len = 0;
    uint8_t *S_box;

public:
    AESKeyExtension(std::size_t block_len, uint8_t *S_box_ptr) : block_len(block_len), S_box(S_box_ptr) {
    }

    void key_extension(const uint8_t *input_key, std::size_t key_len, uint8_t* round_keys, std::size_t rounds) override;
};

#endif //LABS_CRYPTO_AESKEYEXPANSION_H
