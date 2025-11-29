#ifndef LABS_CRYPTO_IENCRYPTIONROUND_H
#define LABS_CRYPTO_IENCRYPTIONROUND_H
#include <cstdint>

class IEncryptionRound {
public:
    virtual ~IEncryptionRound() = default;
    virtual void encryptRound(const uint8_t* inputBlock, const uint8_t* roundKey, uint8_t* output) = 0;
};

#endif //LABS_CRYPTO_IENCRYPTIONROUND_H
