#include "./CipherModes/CBCMode.h"
#include <thread>
#include <memory>
#include <algorithm>

// CBCMode implementation
void CBCMode::processBlocks(uint8_t* data, size_t& length,
                            ISymmetricCipher* cipher,
                            const uint8_t* iv,
                            bool encrypt)
{
    const size_t block_size = cipher->blockSize();
    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;

    std::unique_ptr<uint8_t[]> prev_block(new uint8_t[block_size]);
    std::copy(iv, iv + block_size, prev_block.get());

    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t* block = data + i * block_size;

        if (encrypt) {
            for (size_t j = 0; j < block_size; ++j)
                block[j] ^= prev_block[j];
            cipher->encrypt(block, block);
            std::copy(block, block + block_size, prev_block.get());
        } else {
            std::unique_ptr<uint8_t[]> ctmp(new uint8_t[block_size]);
            std::copy(block, block + block_size, ctmp.get());

            cipher->decrypt(block, block);
            for (size_t j = 0; j < block_size; ++j)
                block[j] ^= prev_block[j];
            std::copy(ctmp.get(), ctmp.get() + block_size, prev_block.get());
        }
    }
}

bool CBCMode::canParallelize() const { return false; }
bool CBCMode::requiresIV() const { return true; }
