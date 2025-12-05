#include "Bit_operations.h"

void P_block(const uint8_t* input, size_t input_len, const int* perm_table, size_t table_size,
             uint8_t* output, ByteOrder order = ByteOrder::BIG_ENDIAN, StartIndex start = StartIndex::ZERO) {

    size_t out_bytes = table_size / 8;

    for (size_t i = 0; i < out_bytes; i++) {
        output[i] = 0;
    }

    for (size_t i = 0; i < out_bytes; i++) {
        for (size_t j = 0; j < 8; j++) {
            size_t res_bit_pos = 7 - j;
            size_t res_bit_idx = i * 8 + res_bit_pos;

            size_t src_bit_idx = perm_table[res_bit_idx];
            if (start == StartIndex::ONE) {
                src_bit_idx--;
            }

            size_t src_byte = src_bit_idx / 8;
            size_t src_bit = src_bit_idx % 8;

            if (order == ByteOrder::LITTLE_ENDIAN) {
                src_byte = (input_len - 1) - src_byte;
            }

            if (src_byte >= input_len) {
                throw std::out_of_range("Index out of range");
            }

            bool bit_set = (input[src_byte] >> src_bit) & 1;
            if (bit_set) {
                output[i] |= (1 << res_bit_pos);
            }
        }
    }
}