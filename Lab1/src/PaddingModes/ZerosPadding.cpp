#include "PaddingModes/ZerosPadding.h"
#include <cstring>

void ZerosPadding::apply(uint8_t*& data, size_t& length, size_t block_size) {
    size_t padding_size = block_size - (length % block_size);
    if (padding_size == block_size) padding_size = 0;

    if (padding_size > 0) {
        uint8_t* new_data = new uint8_t[length + padding_size];
        if (length > 0) {
            std::memcpy(new_data, data, length);
        }
        std::memset(new_data + length, 0x00, padding_size);

        delete[] data;
        data = new_data;
        length += padding_size;
    }
}

void ZerosPadding::remove(uint8_t* data, size_t& length, size_t /*block_size*/) {
    if (length == 0) return;

    size_t padding_size = 0;
    for (size_t i = length; i > 0; --i) {
        if (data[i - 1] == 0x00) {
            padding_size++;
        } else {
            break;
        }
    }
    if (padding_size > 0) {
        length -= padding_size;
    }
}