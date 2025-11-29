#include "PaddingModes/ANSIX923Padding.h"


void ANSIX923Padding::apply(uint8_t*& data, size_t& length, size_t block_size) {
    size_t rem = length % block_size;
    size_t padding_size = (rem == 0) ? block_size : (block_size - rem);

    std::unique_ptr<uint8_t[]> new_data(new uint8_t[length + padding_size]);
    std::copy(data, data + length, new_data.get());
    std::fill(new_data.get() + length, new_data.get() + length + padding_size - 1, 0x00);
    new_data[length + padding_size - 1] = static_cast<uint8_t>(padding_size);

    data = new_data.release();
    length += padding_size;
}

void ANSIX923Padding::remove(uint8_t* data, size_t& length, size_t block_size) {
    if (length == 0) return;

    size_t padding_size = data[length - 1];
    if (padding_size == 0 || padding_size > block_size || padding_size > length)
        throw std::runtime_error("Invalid ANSI X.923 padding");

    for (size_t i = length - padding_size; i < length - 1; ++i) {
        if (data[i] != 0x00)
            throw std::runtime_error("Invalid ANSI X.923 padding - non-zero bytes found");
    }

    length -= padding_size;
}