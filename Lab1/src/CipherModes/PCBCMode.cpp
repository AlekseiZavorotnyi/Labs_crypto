#include "./CipherModes/PCBCMode.h"
#include <cstring>
#include <stdexcept>

void PCBCMode::processBlocks(uint8_t* data, size_t& length,
                             ISymmetricCipher* cipher,
                             const uint8_t* iv,
                             bool encrypt,
                             size_t /*user_threads*/)
{
    const size_t block_size = cipher->blockSize();
    if (length % block_size != 0) {
        throw std::runtime_error("PCBC requires length to be multiple of block size");
    }

    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;
    if (!iv) throw std::runtime_error("PCBC requires non-null IV");

    uint8_t* prev_cipher = new uint8_t[block_size];
    uint8_t* prev_plain  = new uint8_t[block_size];
    std::memcpy(prev_cipher, iv, block_size);
    std::memset(prev_plain, 0, block_size);

    uint8_t* tmp   = new uint8_t[block_size];
    uint8_t* mixed = new uint8_t[block_size];

    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t* block = data + i * block_size;

        if (encrypt) {
            std::memcpy(tmp, block, block_size);

            for (size_t j = 0; j < block_size; ++j) {
                mixed[j] = tmp[j] ^ prev_cipher[j] ^ prev_plain[j];
            }

            cipher->encrypt(mixed, block);

            std::memcpy(prev_plain, tmp,   block_size);
            std::memcpy(prev_cipher, block, block_size);

        } else {
            std::memcpy(tmp, block, block_size);

            cipher->decrypt(block, mixed);

            for (size_t j = 0; j < block_size; ++j) {
                block[j] = mixed[j] ^ prev_cipher[j] ^ prev_plain[j];
            }

            std::memcpy(prev_plain, block, block_size);
            std::memcpy(prev_cipher, tmp,  block_size);
        }
    }

    delete[] prev_cipher;
    delete[] prev_plain;
    delete[] tmp;
    delete[] mixed;
}

bool PCBCMode::canParallelize() const { return false; }
bool PCBCMode::requiresIV() const { return true; }
