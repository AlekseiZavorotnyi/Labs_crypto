#include <thread>
#include <memory>
#include <algorithm>
#include "./CipherModes/OFBMode.h"

// OFBMode implementation
void OFBMode::processBlocks(uint8_t* data, size_t& length,
                            ISymmetricCipher* cipher,
                            const uint8_t* iv,
                            bool /*encrypt*/)
{
    const size_t block_size = cipher->blockSize();
    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;

    std::unique_ptr<uint8_t[]> stream(new uint8_t[block_size]);
    std::unique_ptr<uint8_t[]> next_stream(new uint8_t[block_size]);
    std::copy(iv, iv + block_size, stream.get());

    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t* block = data + i * block_size;

        cipher->encrypt(stream.get(), next_stream.get());

        for (size_t j = 0; j < block_size; ++j)
            block[j] ^= next_stream[j];

        std::copy(next_stream.get(), next_stream.get() + block_size, stream.get());
    }
}

bool OFBMode::canParallelize() const { return false; }
bool OFBMode::requiresIV() const { return true; }