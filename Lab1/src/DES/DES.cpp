#include "DES/DES.h"

DES::DES(ByteOrder byte_order) : byte_order(byte_order),
                                 feistel(std::make_unique<DESKeyExpansion>(byte_order),
                                         std::make_unique<DESRound>(byte_order), 16, 8, 6) {}

void DES::encrypt(const uint8_t* input, uint8_t* output) {
    feistel.en_de_crypt(input, output, true);
}

void DES::decrypt(const uint8_t* input, uint8_t* output) {
    feistel.en_de_crypt(input, output, false);
}

void DES::setupKeys(const uint8_t* key, size_t key_len) {
    feistel.setupKeys(key, key_len);
}

size_t DES::blockSize() const { return 8; }

size_t DES::keySize() const { return 8; }