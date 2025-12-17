#ifndef BIT_OPERATIONS_H
#define BIT_OPERATIONS_H
#include <cstdint>
#include <stdexcept>

enum class ByteOrder {
    BIG_END,
    LITTLE_END
};

enum class StartIndex {
    ZERO,
    ONE
};

void P_block(const uint8_t* input, size_t input_len, const int* perm_table, size_t table_size,
             uint8_t* output, ByteOrder order, StartIndex start);
#endif //BIT_OPERATIONS_H