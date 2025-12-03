#include "./CipherModes/PCBCMode.h"
#include <cstring>
#include <stdexcept>

void PCBCMode::processBlocks(uint8_t* data, size_t& length,
                             ISymmetricCipher* cipher,
                             const uint8_t* iv,
                             bool encrypt)
{
    const size_t block_size = cipher->blockSize();
    if (length % block_size != 0) {
        throw std::runtime_error("PCBC requires length to be multiple of block size");
    }

    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;
    if (!iv) throw std::runtime_error("PCBC requires non-null IV");

    uint8_t* prev_in  = new uint8_t[block_size];
    uint8_t* prev_out = new uint8_t[block_size];
    std::memcpy(prev_in, iv, block_size);
    std::memcpy(prev_out, iv, block_size);

    uint8_t* tmp = new uint8_t[block_size];

    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t* block = data + i * block_size;

        if (encrypt) {
            // P' = P xor (prev_in xor prev_out)
            for (size_t j = 0; j < block_size; ++j) {
                block[j] ^= (prev_in[j] ^ prev_out[j]);
            }
            // Save P' (как «вход» для prev_in на следующем шаге)
            std::memcpy(tmp, block, block_size);

            // C = E(P')
            cipher->encrypt(block, block);

            // prev_in := P' ; prev_out := C
            std::memcpy(prev_in,  tmp,   block_size);
            std::memcpy(prev_out, block, block_size);
        } else {
            // Сохранить C
            std::memcpy(tmp, block, block_size);

            // P' = D(C)
            cipher->decrypt(block, block);

            // P = P' xor (prev_in xor prev_out)
            for (size_t j = 0; j < block_size; ++j) {
                block[j] ^= (prev_in[j] ^ prev_out[j]);
            }

            // prev_in := P ; prev_out := C
            std::memcpy(prev_in,  block, block_size);
            std::memcpy(prev_out, tmp,   block_size);
        }
    }

    delete[] prev_in;
    delete[] prev_out;
    delete[] tmp;
}

bool PCBCMode::canParallelize() const { return false; }
bool PCBCMode::requiresIV() const { return true; }
