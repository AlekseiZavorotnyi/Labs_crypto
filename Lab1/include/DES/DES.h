#ifndef LABS_CRYPTO_DES_H
#define LABS_CRYPTO_DES_H
#include "FeistelNetwork.h"
#include "Interfaces/ISymmetricCipher.h"
#include "DESRound.h"
#include "DESKeyExpansion.h"

class DES : public ISymmetricCipher {
private:
    ByteOrder byte_order;
    Feistel_network feistel;

public:
    explicit DES(ByteOrder byte_order = ByteOrder::BIG_END);

    void encrypt(const uint8_t* input, uint8_t* output) override;
    void decrypt(const uint8_t* input, uint8_t* output) override;
    void setupKeys(const uint8_t* key, size_t key_len) override;
    size_t blockSize() const override;
    size_t keySize() const override;
};
#endif //LABS_CRYPTO_DES_H
