#include "./CipherModes/CBCMode.h"
#include <cstring>
#include <stdexcept>

void CBCMode::processBlocks(uint8_t* data, size_t& length,
                            ISymmetricCipher* cipher,
                            const uint8_t* iv,
                            bool encrypt,
                            size_t /*user_threads*/)
{
    const size_t block_size = cipher->blockSize();
    if (length % block_size != 0) {
        throw std::runtime_error("CBC requires length to be multiple of block size");
    }

    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;
    if (!iv) throw std::runtime_error("CBC requires non-null IV");

    uint8_t* prev = new uint8_t[block_size];
    std::memcpy(prev, iv, block_size);

    uint8_t* tmpC = encrypt ? nullptr : new uint8_t[block_size];

    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t* block = data + i * block_size;

        if (encrypt) {
            // XOR с prev
            for (size_t j = 0; j < block_size; ++j) block[j] ^= prev[j];
            // E
            cipher->encrypt(block, block);
            // prev = C
            std::memcpy(prev, block, block_size);
        } else {
            // Сохранить C
            std::memcpy(tmpC, block, block_size);
            // D
            cipher->decrypt(block, block);
            // XOR с prev => P
            for (size_t j = 0; j < block_size; ++j) block[j] ^= prev[j];
            // prev = C (исходный)
            std::memcpy(prev, tmpC, block_size);
        }
    }

    delete[] prev;
    delete[] tmpC;
}

bool CBCMode::canParallelize() const { return false; }
bool CBCMode::requiresIV() const { return true; }
