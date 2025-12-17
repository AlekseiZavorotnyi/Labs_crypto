#ifndef LABS_CRYPTO_DEALROUND_H
#define LABS_CRYPTO_DEALROUND_H
#include "DESAdaptrer.h"

class DEALRound : public IEncryptionRound {
private:
    ByteOrder byte_order;

    void modifyKey(const uint8_t* originalKey, uint8_t modifier, uint8_t* modifiedKey);

public:
    explicit DEALRound(ByteOrder order = ByteOrder::BIG_END);

    void encryptRound(const uint8_t* inputBlock, const uint8_t* roundKey, uint8_t* output) override;
};
#endif //LABS_CRYPTO_DEALROUND_H