#include "./CipherModes/CFBMode.h"
#include <cstring>
#include <stdexcept>
#include <cstdint>

void CFBMode::processBlocks(uint8_t* data, size_t& length,
                            ISymmetricCipher* cipher,
                            const uint8_t* iv,
                            bool encrypt)
{
    const size_t block_size = cipher->blockSize();
    if (length % block_size != 0) {
        throw std::runtime_error("CFB expects length multiple of block size when padding is enforced");
    }

    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;
    if (!iv) throw std::runtime_error("CFB requires non-null IV");

    uint8_t* shift = new uint8_t[block_size];
    std::memcpy(shift, iv, block_size);

    uint8_t* ks = new uint8_t[block_size];

    const bool aligned8 =
            (reinterpret_cast<uintptr_t>(data) % 8 == 0) &&
            (reinterpret_cast<uintptr_t>(shift) % 8 == 0) &&
            (reinterpret_cast<uintptr_t>(ks) % 8 == 0) &&
            (block_size % 8 == 0);

    for (size_t i = 0; i < num_blocks; ++i) {
        uint8_t* block = data + i * block_size;

        cipher->encrypt(shift, ks);

        if (encrypt) {
            if (aligned8) {
                auto* pB = reinterpret_cast<uint64_t*>(block);
                auto* pK = reinterpret_cast<uint64_t*>(ks);
                auto* pS = reinterpret_cast<uint64_t*>(shift);
                const size_t words = block_size / 8;
                for (size_t w = 0; w < words; ++w) {
                    uint64_t c = pB[w] ^ pK[w];
                    pB[w] = c;
                    pS[w] = c;
                }
            } else {
                for (size_t j = 0; j < block_size; ++j) {
                    uint8_t c = static_cast<uint8_t>(block[j] ^ ks[j]);
                    block[j] = c;
                    shift[j] = c;
                }
            }
        } else {
            if (aligned8) {
                auto* pB = reinterpret_cast<uint64_t*>(block);
                auto* pK = reinterpret_cast<uint64_t*>(ks);
                auto* pS = reinterpret_cast<uint64_t*>(shift);
                const size_t words = block_size / 8;
                for (size_t w = 0; w < words; ++w) {
                    uint64_t C = pB[w];
                    uint64_t P = C ^ pK[w];
                    pB[w] = P;
                    pS[w] = C;
                }
            } else {
                for (size_t j = 0; j < block_size; ++j) {
                    uint8_t C = block[j];
                    uint8_t P = static_cast<uint8_t>(C ^ ks[j]);
                    block[j] = P;
                    shift[j] = C;
                }
            }
        }
    }

    delete[] shift;
    delete[] ks;
}

bool CFBMode::canParallelize() const { return false; }
bool CFBMode::requiresIV() const { return true; }