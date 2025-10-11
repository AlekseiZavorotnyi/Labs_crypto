#include <iostream>
#include <vector>
#include <cstddef>
#include <vector>
#include <cstddef>
#include <stdexcept>
#include <bitset>
#include <cstdint>
#include <fstream>

using mass_b = std::vector<std::byte>;

enum class BitOrder {
    LSB_TO_MSB,  // Младший бит (LSB) имеет индекс 0
    MSB_TO_LSB   // Старший бит (MSB) имеет индекс 0
};

enum class StartIndex {
    ZERO,        // Нумерация битов начинается с 0
    ONE          // Нумерация битов начинается с 1
};

mass_b read_f(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    mass_b buffer;

    if (file) {
        std::byte byte;
        while (buffer.size() < 8 && file.read(reinterpret_cast<char*>(&byte), 1)) {
            buffer.push_back(byte);
        }
    }

    return buffer;
}

mass_b P_block(){

}

int main() {
    mass_b res = read_f("text.txt");
    for (size_t i = 0; i < res.size(); ++i) {
        std::cout << "Byte " << i << ": " << std::bitset<8>(static_cast<unsigned char>(res[i]))
                  << " (0x" << std::hex << static_cast<int>(res[i]) << ")" << std::dec << std::endl;
    }
    return 0;
}