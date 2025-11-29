#ifndef LABS_CRYPTO_DEALKEYEXPANSION_H
#define LABS_CRYPTO_DEALKEYEXPANSION_H
#include "DESAdaptrer.h"

class DEALKeyExpansion : public IKeyExpansion {
private:
    ByteOrder byte_order;

public:
    explicit DEALKeyExpansion(ByteOrder order = ByteOrder::BIG_ENDIAN);

    void key_extension(const uint8_t* input_key, size_t key_len, uint8_t* round_keys, size_t rounds) override;
};
#endif //LABS_CRYPTO_DEALKEYEXPANSION_H
