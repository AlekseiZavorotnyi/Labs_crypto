#ifndef LABS_CRYPTO_AES_H
#define LABS_CRYPTO_AES_H
#include <cstddef>
#include "../Interfaces/ISymmetricCipher.h"
#include "GF_Service.h"

class AES : public ISymmetricCipher {
private:
    uint8_t* init_key;

public:
    uint8_t* exp_key;
    size_t key_len;
    size_t block_len;
    uint8_t S_box[256] = {};
    uint8_t S_box_inv[256] = {};

    AES(size_t block_len, size_t key_len, const uint8_t* init_key);

    ~AES();

    void encrypt(const uint8_t* input, uint8_t* output) override;
    void decrypt(const uint8_t* input, uint8_t* output) override;
    void setupKeys(const uint8_t* key, size_t key_len) override;
    size_t blockSize() const override;
    size_t keySize() const override;
};
#endif //LABS_CRYPTO_AES_H
