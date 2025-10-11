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
    LIT_TO_BIG,  // Младший бит (LSB) имеет индекс 0
    BIG_TO_LIT   // Старший бит (MSB) имеет индекс 0
};

enum class StartIndex {
    ZERO,        // Нумерация битов начинается с 0
    ONE          // Нумерация битов начинается с 1
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
    for (size_t byte_index_res = 0; byte_index_res < size_byte; byte_index_res++){
        for (size_t bit_index_res = 0; bit_index_res < 8; bit_index_res++) {
            size_t bit_index = p_bl[byte_index_res * 8 + bit_index_res];
            if (num_st == StartIndex::ONE){
                bit_index--;
            }
            size_t byte_index_st = bit_index / 8;
            size_t bit_index_st = bit_index % 8;
            size_t bit_index_res_fnl = bit_index_res;
            if (big_end == BitOrder::BIG_TO_LIT) {
                bit_index_res_fnl = 7 - bit_index_res;
                bit_index_st = 7 - bit_index_st;
            }
            uint8_t cur_bit = (static_cast<uint8_t>(st[byte_index_st]) >> bit_index_st) & 1;
            if (cur_bit) {
                res[byte_index_res] |= std::byte{1} << bit_index_res_fnl;
            }
        }
    }
    return res;
}

mass_b P_block_reverse(mass_b st, mass_i p_bl, BitOrder big_end = BitOrder::BIG_TO_LIT, StartIndex num_st = StartIndex::ZERO){
    size_t size_byte = st.size();
    mass_b res(size_byte, byte{0});
    for (size_t byte_index_res = 0; byte_index_res < size_byte; byte_index_res++){
        for (size_t bit_index_res = 0; bit_index_res < 8; bit_index_res++) {
            size_t bit_index = p_bl[byte_index_res * 8 + bit_index_res];
            if (num_st == StartIndex::ONE){
                bit_index--;
            }
            size_t byte_index_st = bit_index / 8;
            size_t bit_index_st = bit_index % 8;
            size_t bit_index_res_fnl = bit_index_res;
            if (big_end == BitOrder::BIG_TO_LIT) {
                bit_index_res_fnl = 7 - bit_index_res;
                bit_index_st = 7 - bit_index_st;
            }
            uint8_t cur_bit = (static_cast<uint8_t>(st[byte_index_st]) >> bit_index_st) & 1;
            if (cur_bit) {
                res[byte_index_res] |= std::byte{1} << bit_index_res_fnl;
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
    res = P_block(res, {8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7});
    for (size_t i = 0; i < res.size(); ++i) {
        std::cout << "Byte " << i << ": " << std::bitset<8>(static_cast<unsigned char>(res[i]))
                  << " (0x" << std::hex << static_cast<int>(res[i]) << ")" << std::dec << std::endl;
    }
    return 0;
}