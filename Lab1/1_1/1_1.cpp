#include <iostream>
#include <vector>
#include <cstddef>
#include <vector>
#include <cstddef>
#include <stdexcept>
#include <bitset>
#include <cstdint>
#include <fstream>

using byte = std::byte;
using mass_b = std::vector<byte>;
using mass_i = std::vector<int>;

enum class BitOrder {
    LIT_TO_BIG,
    BIG_TO_LIT
};

enum class StartIndex {
    ZERO,
    ONE
};

mass_b read_f(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    mass_b buffer;

    if (file) {
        byte byte;
        while (buffer.size() < 8 && file.read(reinterpret_cast<char*>(&byte), 1)) {
            buffer.push_back(byte);
        }
    }

    return buffer;
}

mass_b P_block(mass_b st, mass_i p_bl, BitOrder big_end = BitOrder::BIG_TO_LIT, StartIndex num_st = StartIndex::ZERO){
    size_t size_byte = st.size();
    mass_b res(size_byte, byte{0});
    for (size_t i = 0; i < size_byte; i++){
        for (size_t j = 0; j < 8; j++) {
            size_t byte_index_res = i, bit_index_res = j;
            size_t bit_index = p_bl[byte_index_res * 8 + bit_index_res];
            if (num_st == StartIndex::ONE){
                bit_index--;
            }
            size_t byte_index_st = bit_index / 8;
            size_t bit_index_st = bit_index % 8;
            if (big_end == BitOrder::BIG_TO_LIT) {
                bit_index_res = 7 - bit_index_res;
                bit_index_st = 7 - bit_index_st;
            }
            uint8_t cur_bit = (static_cast<uint8_t>(st[byte_index_st]) >> bit_index_st) & 1;
            if (cur_bit) {
                res[byte_index_res] |= std::byte{1} << bit_index_res;
            }
        }
    }
    return res;
}

int main() {
    mass_b res = read_f("text.txt");
    for (size_t i = 0; i < res.size(); ++i) {
        std::cout << "Byte " << i << ": " << std::bitset<8>(static_cast<unsigned char>(res[i]))
                  << " (0x" << std::hex << static_cast<int>(res[i]) << ")" << std::dec << std::endl;
    }
    std::cout<< '\n';
    res = P_block(res, {0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15}, BitOrder::BIG_TO_LIT, StartIndex::ZERO);
    for (size_t i = 0; i < res.size(); ++i) {
        std::cout << "Byte " << i << ": " << std::bitset<8>(static_cast<unsigned char>(res[i]))
                  << " (0x" << std::hex << static_cast<int>(res[i]) << ")" << std::dec << std::endl;
    }
    return 0;
}