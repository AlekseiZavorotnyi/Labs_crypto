#include "./PaddingModes/ZerosPadding.h"

void ZerosPadding::apply(uint8_t*& data, size_t& length, size_t block_size) {
    size_t padding_size = block_size - (length % block_size);
    if (padding_size == block_size) padding_size = 0;

    if (padding_size > 0) {
        std::unique_ptr<uint8_t[]> new_data(new uint8_t[length + padding_size]);
        std::copy(data, data + length, new_data.get());
        std::fill(new_data.get() + length, new_data.get() + length + padding_size, 0x00);

        data = new_data.release();
        length += padding_size;
    }
}

void ZerosPadding::remove(uint8_t* data, size_t& length, [[maybe_unused]]size_t block_size) {
    if (length == 0) return;

    size_t padding_size = 0;
    for (size_t i = length; i > 0; --i) {
        if (data[i - 1] == 0x00) padding_size++;
        else break;
    }
    if (padding_size > 0) length -= padding_size;
}