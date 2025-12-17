#ifndef LABS_CRYPTO_DESKEYEXPANSION_H
#define LABS_CRYPTO_DESKEYEXPANSION_H
#include "FeistelNetwork.h"

class DESKeyExpansion : public IKeyExpansion {
private:
    ByteOrder byte_order;

public:
    explicit DESKeyExpansion(ByteOrder order = ByteOrder::BIG_END);

    void key_extension(const uint8_t* input_key, size_t key_len, uint8_t* round_keys, size_t rounds) override;
};

#endif //LABS_CRYPTO_DESKEYEXPANSION_H
