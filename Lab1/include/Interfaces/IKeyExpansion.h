#ifndef LABS_CRYPTO_IKEYEXPANSION_H
#define LABS_CRYPTO_IKEYEXPANSION_H
#include <cstdint>

class IKeyExpansion {
public:
    virtual ~IKeyExpansion() = default;
    virtual void key_extension(const uint8_t* input_key, std::size_t key_len, uint8_t* round_keys, std::size_t rounds) = 0;
};

#endif //LABS_CRYPTO_IKEYEXPANSION_H
