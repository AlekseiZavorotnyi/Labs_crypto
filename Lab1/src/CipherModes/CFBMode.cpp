#include <thread>
#include <memory>
#include <algorithm>
#include "./CipherModes/CFBMode.h"

// CFBMode implementation
void CFBMode::processBlocks(uint8_t* data, size_t& length,
                            ISymmetricCipher* cipher,
                            const uint8_t* iv,
                            bool encrypt)
{
    const size_t block_size = cipher->blockSize();
    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;

    std::unique_ptr<uint8_t[]> shift(new uint8_t[block_size]);
    std::copy(iv, iv + block_size, shift.get());

    std::unique_ptr<uint8_t[]> ks(new uint8_t[block_size]);

    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t* block = data + i * block_size;

        cipher->encrypt(shift.get(), ks.get());

        for (size_t j = 0; j < block_size; ++j)
            block[j] ^= ks[j];

        if (encrypt) {
            std::copy(block, block + block_size, shift.get());
        } else {
            std::copy(data + i * block_size, data + (i + 1) * block_size, shift.get());
        }
    }
}

bool CFBMode::canParallelize() const { return false; }
bool CFBMode::requiresIV() const { return true; }