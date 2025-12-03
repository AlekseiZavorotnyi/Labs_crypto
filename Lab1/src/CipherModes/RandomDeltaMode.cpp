#include "./CipherModes/RandomDeltaMode.h"
#include <thread>
#include <vector>
#include <algorithm>
#include <cstring>
#include <stdexcept>

void RandomDeltaMode::processBlocks(uint8_t* data, size_t& length,
                                    ISymmetricCipher* cipher,
                                    const uint8_t* /*iv*/,
                                    bool encrypt,
                                    size_t user_threads)
{
    const size_t block_size = cipher->blockSize();
    if (length % block_size != 0) {
        throw std::runtime_error("RandomDelta requires length to be multiple of block size");
    }

    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;

    size_t threads_to_use = (user_threads > 0) ? user_threads : std::thread::hardware_concurrency();
    if (threads_to_use == 0) threads_to_use = 1;
    const size_t num_threads = std::min(threads_to_use, num_blocks);
    const size_t blocks_per_thread = (num_blocks + num_threads - 1) / num_threads;

    if (num_threads == 1 || num_blocks < 4) {
        uint8_t* delta = new uint8_t[block_size];
        for (size_t i = 0; i < num_blocks; ++i) {
            uint8_t* block = data + i * block_size;
            std::memset(delta, static_cast<int>(i & 0xFF), block_size);
            if (encrypt) {
                for (size_t j = 0; j < block_size; ++j) block[j] ^= delta[j];
                cipher->encrypt(block, block);
            } else {
                cipher->decrypt(block, block);
                for (size_t j = 0; j < block_size; ++j) block[j] ^= delta[j];
            }
        }
        delete[] delta;
        return;
    }

    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    for (size_t t = 0; t < num_threads; ++t) {
        threads.emplace_back([=]() {
            uint8_t* delta = new uint8_t[block_size];
            const size_t start = t * blocks_per_thread;
            const size_t end   = std::min((t + 1) * blocks_per_thread, num_blocks);

            for (size_t i = start; i < end; ++i) {
                uint8_t* block = data + i * block_size;
                std::memset(delta, static_cast<int>(i & 0xFF), block_size);

                if (encrypt) {
                    for (size_t j = 0; j < block_size; ++j) block[j] ^= delta[j];
                    cipher->encrypt(block, block);
                } else {
                    cipher->decrypt(block, block);
                    for (size_t j = 0; j < block_size; ++j) block[j] ^= delta[j];
                }
            }
            delete[] delta;
        });
    }

    for (auto& thead : threads) thead.join();
}

bool RandomDeltaMode::canParallelize() const { return true; }
bool RandomDeltaMode::requiresIV() const { return false; }
