#ifndef LABS_CRYPTO_DEAL_H
#define LABS_CRYPTO_DEAL_H
#include "FeistelNetwork.h"
#include "Interfaces/ISymmetricCipher.h"
#include "DEAL/DEALRound.h"
#include "DEAL/DEALKeyExpansion.h"

class DEAL : public ISymmetricCipher {
private:
    ByteOrder byte_order;
    size_t actual_key_size;
    Feistel_network feistel;

public:
    explicit DEAL(size_t key_size = 16, ByteOrder byte_order = ByteOrder::BIG_ENDIAN);

    void encrypt(const uint8_t* input, uint8_t* output) override;
    void decrypt(const uint8_t* input, uint8_t* output) override;
    void setupKeys(const uint8_t* key, size_t key_len) override;
    size_t blockSize() const override;
    size_t keySize() const override;
};
#endif //LABS_CRYPTO_DEAL_H
