#include <thread>
#include <memory>
#include <algorithm>
#include <iostream>
#include <vector>
#include "./CipherModes/ECBMode.h"

void ECBMode::processBlocks(uint8_t* data, size_t& length,
                            ISymmetricCipher* cipher,
                            [[maybe_unused]]const uint8_t* iv,
                            bool encrypt,
                            size_t user_threads)
{
    const size_t block_size = cipher->blockSize();
    if (length % block_size != 0) {
        throw std::runtime_error("ECB mode requires input length to be multiple of block size");
    }
    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;

    size_t threads_to_use = (user_threads > 0) ? user_threads : std::thread::hardware_concurrency();
    if (threads_to_use == 0) threads_to_use = 1;
    const size_t num_threads = std::min(threads_to_use, num_blocks);

    const size_t blocks_per_thread = (num_blocks + num_threads - 1) / num_threads;

    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    for (size_t t = 0; t < num_threads; ++t) {
        threads.emplace_back([=]() {
            const size_t start_block = t * blocks_per_thread;
            const size_t end_block = std::min((t + 1) * blocks_per_thread, num_blocks);

            for (size_t i = start_block; i < end_block; ++i) {
                uint8_t* block = data + i * block_size;
                if (encrypt) cipher->encrypt(block, block);
                else cipher->decrypt(block, block);
            }
        });
    }

    for (auto& thread : threads) thread.join();
}

bool ECBMode::canParallelize() const { return true; }
bool ECBMode::requiresIV() const { return false; }
