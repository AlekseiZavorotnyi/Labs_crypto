#ifndef LABS_CRYPTO_DESROUND_H
#define LABS_CRYPTO_DESROUND_H
#include "FeistelNetwork.h"

class DESRound : public IEncryptionRound {
private:
    ByteOrder byte_order;

public:
    explicit DESRound(ByteOrder order = ByteOrder::BIG_END);

    void encryptRound(const uint8_t* inputBlock, const uint8_t* roundKey, uint8_t* output) override;

private:
    void applyE(const uint8_t* inputBlock, uint8_t* output);
    void applySboxes(const uint8_t* input48, uint8_t* output32);
    void applyP(const uint8_t* input32, uint8_t* output32);
};
#endif //LABS_CRYPTO_DESROUND_H
