#ifndef LABS_CRYPTO_TRIPLEDES_H
#define LABS_CRYPTO_TRIPLEDES_H

#include "../Interfaces/ISymmetricCipher.h"
#include "../../include/DEAL/DESAdaptrer.h"
#include <vector>

class TripleDES : public ISymmetricCipher {
private:
    ByteOrder byte_order;
    std::unique_ptr<DESAdapter> des_adapt;
    std::vector<uint8_t> stored_key;
    const uint8_t* key_24;
public:
    explicit TripleDES(size_t key_size, ByteOrder byte_order = ByteOrder::BIG_END);
    void encrypt(const uint8_t* input, uint8_t* output) override;
    void decrypt(const uint8_t* input, uint8_t* output) override;
    void setupKeys(const uint8_t* key, size_t key_len) override;
    size_t blockSize() const override;
    size_t keySize() const override;
};


#endif //LABS_CRYPTO_TRIPLEDES_H
