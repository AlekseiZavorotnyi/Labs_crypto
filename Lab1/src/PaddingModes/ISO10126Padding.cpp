#include "PaddingModes/ISO10126Padding.h"
#include <cstdlib>
#include <cstring>
#include <stdexcept>

void ISO10126Padding::apply(uint8_t*& data, size_t& length, size_t block_size) {
    size_t rem = length % block_size;
    size_t padding_size = (rem == 0) ? block_size : (block_size - rem);

    uint8_t* new_data = new uint8_t[length + padding_size];

    if (length > 0) {
        std::memcpy(new_data, data, length);
    }

    // Заполняем случайными байтами все кроме последнего
    for (size_t i = length; i < length + padding_size - 1; ++i) {
        new_data[i] = static_cast<uint8_t>(std::rand() % 256);
    }
    // Последний байт = размер паддинга
    new_data[length + padding_size - 1] = static_cast<uint8_t>(padding_size);

    delete[] data;
    data = new_data;
    length += padding_size;
}

void ISO10126Padding::remove(uint8_t* data, size_t& length, size_t block_size) {
    if (length == 0) return;

    size_t padding_size = data[length - 1];
    if (padding_size == 0 || padding_size > block_size || padding_size > length) {
        throw std::runtime_error("Invalid ISO 10126 padding");
    }

    // Случайные байты не проверяются, просто уменьшаем длину
    length -= padding_size;
}
