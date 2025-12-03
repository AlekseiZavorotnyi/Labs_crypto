#include "./CipherModes/OFBMode.h"
#include <cstring>
#include <stdexcept>

void OFBMode::processBlocks(uint8_t* data, size_t& length,
                            ISymmetricCipher* cipher,
                            const uint8_t* iv,
                            bool /*encrypt*/,
                            size_t /*user_threads*/)
{
    const size_t block_size = cipher->blockSize();
    if (length % block_size != 0) {
        throw std::runtime_error("OFB expects length multiple of block size when padding is enforced");
    }

    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;
    if (!iv) throw std::runtime_error("OFB requires non-null IV");

    uint8_t* stream = new uint8_t[block_size];
    uint8_t* next   = new uint8_t[block_size];
    std::memcpy(stream, iv, block_size);

    for (size_t i = 0; i < num_blocks; ++i) {
        cipher->encrypt(stream, next);
        uint8_t* block = data + i * block_size;
        for (size_t j = 0; j < block_size; ++j) {
            block[j] ^= next[j];
        }
        std::memcpy(stream, next, block_size);
    }

    delete[] stream;
    delete[] next;
}

bool OFBMode::canParallelize() const { return false; }
bool OFBMode::requiresIV() const { return true; }