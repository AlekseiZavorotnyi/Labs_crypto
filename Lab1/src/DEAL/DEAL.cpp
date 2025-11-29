#include "DEAL/DEAL.h"

DEAL::DEAL(size_t key_size, ByteOrder byte_order)
        : byte_order(byte_order),
          actual_key_size(key_size),
          feistel(std::make_unique<DEALKeyExpansion>(byte_order),
                  std::make_unique<DEALRound>(byte_order),
                  6, 16, 8) {

    if (key_size != 16 && key_size != 24 && key_size != 32) {
        throw std::invalid_argument("DEAL key must be 16/24/32 bytes (128/192/256 bits)");
    }
}

void DEAL::encrypt(const uint8_t* input, uint8_t* output) {
    feistel.en_de_crypt(input, output, true);
}

void DEAL::decrypt(const uint8_t* input, uint8_t* output) {
    feistel.en_de_crypt(input, output, false);
}

void DEAL::setupKeys(const uint8_t* key, size_t key_len) {
    if (key_len != actual_key_size) {
        throw std::invalid_argument("Provided key size doesn't match expected key size");
    }
    feistel.setupKeys(key, key_len);
}

size_t DEAL::blockSize() const { return 16; }

size_t DEAL::keySize() const { return actual_key_size; }