#include <thread>
#include <memory>
#include <algorithm>
#include "./CipherModes/PCBCMode.h"

// PCBCMode implementation
void PCBCMode::processBlocks(uint8_t* data, size_t& length,
                             ISymmetricCipher* cipher,
                             const uint8_t* iv,
                             bool encrypt)
{
    const size_t block_size = cipher->blockSize();
    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;

    std::unique_ptr<uint8_t[]> prev_in(new uint8_t[block_size]);
    std::unique_ptr<uint8_t[]> prev_out(new uint8_t[block_size]);
    std::copy(iv, iv + block_size, prev_in.get());
    std::copy(iv, iv + block_size, prev_out.get());

    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t* block = data + i * block_size;

        if (encrypt) {
            for (size_t j = 0; j < block_size; ++j)
                block[j] ^= (prev_in[j] ^ prev_out[j]);
            cipher->encrypt(block, block);
            std::copy(data + i * block_size, data + (i + 1) * block_size, prev_in.get());
            std::copy(block, block + block_size, prev_out.get());
        } else {
            std::unique_ptr<uint8_t[]> ctmp(new uint8_t[block_size]);
            std::copy(block, block + block_size, ctmp.get());

            cipher->decrypt(block, block);
            for (size_t j = 0; j < block_size; ++j)
                block[j] ^= (prev_in[j] ^ prev_out[j]);

            std::copy(block, block + block_size, prev_in.get());
            std::copy(ctmp.get(), ctmp.get() + block_size, prev_out.get());
        }
    }
}

bool PCBCMode::canParallelize() const { return false; }
bool PCBCMode::requiresIV() const { return true; }