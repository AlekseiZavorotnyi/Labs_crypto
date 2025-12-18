#ifndef LABS_CRYPTO_ISYMMETRICCIPHER_H
#define LABS_CRYPTO_ISYMMETRICCIPHER_H
#include <cstdint>

class ISymmetricCipher  {
public:
    virtual ~ISymmetricCipher() = default;
    virtual void encrypt(const uint8_t* input, uint8_t* output) = 0;
    virtual void decrypt(const uint8_t* input, uint8_t* output) = 0;
    virtual void setupKeys(const uint8_t* key, std::size_t key_len) = 0;
    [[nodiscard]] virtual std::size_t blockSize() const = 0;
    [[nodiscard]] virtual std::size_t keySize() const = 0;
};
#endif //LABS_CRYPTO_ISYMMETRICCIPHER_H
