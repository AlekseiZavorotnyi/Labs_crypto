#include "./PaddingModes/PKCS7Padding.h"
#include <stdexcept>
#include <cstring>
#include <iostream>

void PKCS7Padding::apply(uint8_t*& data, size_t& length, size_t block_size) {
    size_t rem = length % block_size;
    size_t padding_size = (rem == 0) ? block_size : (block_size - rem);

    uint8_t* new_data = new uint8_t[length + padding_size];

    if (length > 0) {
        std::memcpy(new_data, data, length);
    }

    std::memset(new_data + length, static_cast<int>(padding_size), padding_size);

    delete[] data;

    data = new_data;
    length += padding_size;
}

void PKCS7Padding::remove(uint8_t* data, size_t& length, size_t block_size) {
    if (length == 0) return;
    size_t padding_size = data[length - 1];
    if (padding_size == 0 || padding_size > block_size || padding_size > length) {
        throw std::runtime_error("Invalid PKCS7 padding");
    }

    for (size_t i = length - padding_size; i < length; ++i) {
        if (data[i] != padding_size) {
            throw std::runtime_error("Invalid PKCS7 padding - inconsistent padding bytes");
        }
    }

    length -= padding_size;
}
