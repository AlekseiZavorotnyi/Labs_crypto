#include "../../include/DES/TripleDES.h"
#include <memory>
#include <cstring>

TripleDES::TripleDES(size_t key_size, ByteOrder byte_order) : byte_order(byte_order),key_24(nullptr){
    if (key_size != 24) {
        throw std::invalid_argument("TripleDES key must be 24 bytes (3-key)");
    }
    des_adapt = std::make_unique<DESAdapter>();
    stored_key.reserve(key_size);
}

void TripleDES::encrypt(const uint8_t* input, uint8_t* output) {
    const uint8_t* k1 = stored_key.data();
    const uint8_t* k2 = stored_key.data() + 8;
    const uint8_t* k3 = stored_key.data() + 16;
    uint8_t temp1[8] = { 0 };
    uint8_t temp2[8] = { 0 };
    des_adapt->encrypt(input, k1, temp1);
    des_adapt->decrypt(temp1, k2, temp2);
    des_adapt->encrypt(temp2, k3, output);
}

void TripleDES::decrypt(const uint8_t* input, uint8_t* output) {
    const uint8_t* k1 = stored_key.data();
    const uint8_t* k2 = stored_key.data() + 8;
    const uint8_t* k3 = stored_key.data() + 16;
    uint8_t temp1[8] = { 0 };
    uint8_t temp2[8] = { 0 };
    des_adapt->decrypt(input, k3, temp1);
    des_adapt->encrypt(temp1, k2, temp2);
    des_adapt->decrypt(temp2, k1, output);
}

void TripleDES::setupKeys(const uint8_t* key, size_t key_len) {
    if (key_len != 24) {
        throw std::invalid_argument("TripleDES key must be 24 bytes (3-key)");
    }
    stored_key.resize(key_len);
    std::memcpy(stored_key.data(), key, key_len);
}

size_t TripleDES::blockSize() const {
    return 8;
}

size_t TripleDES::keySize() const {
    return 24;
}