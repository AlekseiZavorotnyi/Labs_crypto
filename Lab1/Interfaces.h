#ifndef LABS_CRYPTO_INTERFACES_H
#define LABS_CRYPTO_INTERFACES_H

#include <cstddef>
#include <cstdint>
#include <memory>

using byte = std::byte;

enum class ByteOrder {
    BIG_ENDIAN,
    LITTLE_ENDIAN
};

enum class StartIndex {
    ZERO,
    ONE
};

enum class encryption_modes{
    ECB, CBC, PCBC, CFB, OFB, CTR, Random_Delta
};

enum class padding_modes{
    Zeros,
    ANSI, //ANSI X.923
    PKCS7,
    ISO // ISO 10126
};


class IKeyExpansion {
public:
    virtual void key_extension(const uint8_t* input_key, size_t key_len, uint8_t* round_keys, size_t rounds) = 0;
};

class IEncryptionRound {
public:
    virtual void encryptRound(const uint8_t* inputBlock, const uint8_t* roundKey, uint8_t* output) = 0;
};

class ISymmetricCipher  {
public:
    virtual void encrypt(const uint8_t* input, uint8_t* output) = 0;
    virtual void decrypt(const uint8_t* input, uint8_t* output) = 0;
    virtual void setupKeys(const uint8_t* key, size_t key_len) = 0;
    virtual size_t blockSize() const = 0;
    virtual size_t keySize() const = 0;
};


#endif //LABS_CRYPTO_INTERFACES_H