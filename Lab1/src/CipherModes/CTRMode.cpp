#include <thread>
#include <memory>
#include <algorithm>
#include <iostream>
#include "./CipherModes/CTRMode.h"

// CTRMode implementation
void CTRMode::processBlocks(uint8_t* data, size_t& length,
                            ISymmetricCipher* cipher,
                            const uint8_t* iv,
                            bool /*encrypt*/)
{
    const size_t block_size = cipher->blockSize();
    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;

    const unsigned hw = std::thread::hardware_concurrency();
    const size_t num_threads = std::max<size_t>(1, std::min<size_t>(hw ? hw : 1, num_blocks));
    const size_t blocks_per_thread = (num_blocks + num_threads - 1) / num_threads;

    std::unique_ptr<std::thread[]> threads(new std::thread[num_threads]);

    for (size_t t = 0; t < num_threads; ++t) {
        threads[t] = std::thread([=]() {
            std::unique_ptr<uint8_t[]> counter(new uint8_t[block_size]);
            std::copy(iv, iv + block_size, counter.get());

            std::unique_ptr<uint8_t[]> ks(new uint8_t[block_size]);

            const size_t start_block = t * blocks_per_thread;
            const size_t end_block = std::min((t + 1) * blocks_per_thread, num_blocks);

            for (size_t i = start_block; i < end_block; ++i) {
                addToCounter(counter.get(), block_size, i);

                cipher->encrypt(counter.get(), ks.get());

                uint8_t* block = data + i * block_size;
                for (size_t j = 0; j < block_size; ++j)
                    block[j] ^= ks[j];
            }
        });
    }
    for (size_t t = 0; t < num_threads; ++t) threads[t].join();
}

bool CTRMode::canParallelize() const { return true; }
bool CTRMode::requiresIV() const { return true; }

void CTRMode::addToCounter(uint8_t* counter, size_t counter_len, size_t add) {
    size_t carry = add;
    for (size_t k = 0; k < counter_len && carry > 0; ++k) {
        size_t pos = counter_len - 1 - k;
        size_t sum = static_cast<size_t>(counter[pos]) + (carry & 0xFF);
        counter[pos] = static_cast<uint8_t>(sum & 0xFF);
        carry >>= 8;
        if (sum > 0xFF && pos > 0) {
            size_t p = pos - 1;
            while (p < counter_len) {
                unsigned val = counter[p] + 1;
                counter[p] = static_cast<uint8_t>(val & 0xFF);
                if (val <= 0xFF) break;
                if (p == 0) break;
                --p;
            }
        }
    }
}