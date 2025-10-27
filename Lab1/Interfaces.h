#ifndef LABS_CRYPTO_INTERFACES_H
#define LABS_CRYPTO_INTERFACES_H

#include <iostream>
#include <vector>
#include <cstddef>
#include <vector>
#include <cstddef>
#include <stdexcept>
#include <bitset>
#include <cstdint>
#include <fstream>
#include <memory>

using byte = std::byte;
using mass_b = std::vector<byte>;
using mass_i = std::vector<int>;
using mass_mass_mass_i = std::vector<std::vector<std::vector<int>>>;

enum class BitOrder {
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

enum class packing_modes{
    Zeros,
    ANSI, //ANSI X.923
    PKCS7,
    ISO // ISO 10126
};

using byte = std::byte;
using mass_b = std::vector<byte>;
using mass_mass_b = std::vector<std::vector<byte>>;
using mass_i = std::vector<int>;

class IKeyExpansion {
public:
    virtual mass_mass_b key_extension(mass_b& input_key) = 0;
};

class IEncryptionRound {
public:
    virtual mass_b encryptRound(mass_b& inputBlock, mass_b& roundKey) = 0;
};

class ISymmetricCipher  {
public:
    virtual mass_b encrypt(mass_b& block) = 0;
    virtual mass_b decrypt(mass_b& block) = 0;
    virtual void setupKeys(mass_b& en_de_crypt_key) = 0;
};


#endif //LABS_CRYPTO_INTERFACES_H
