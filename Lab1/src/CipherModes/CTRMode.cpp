#include "./CipherModes/CTRMode.h"
#include <thread>
#include <vector>
#include <algorithm>
#include <cstring>
#include <stdexcept>

static inline void addToCounterRange(uint8_t* counter, size_t counter_len, size_t add) {
    // counter := counter + add (big-endian)
    size_t carry = add;
    for (size_t k = 0; k < counter_len && carry > 0; ++k) {
        size_t pos = counter_len - 1 - k;
        size_t sum = static_cast<size_t>(counter[pos]) + (carry & 0xFF);
        counter[pos] = static_cast<uint8_t>(sum & 0xFF);
        carry >>= 8;
        if (sum > 0xFF && pos > 0) {
            // инкремент по переносу
            size_t p = pos - 1;
            while (true) {
                unsigned val = counter[p] + 1;
                counter[p] = static_cast<uint8_t>(val & 0xFF);
                if (val <= 0xFF || p == 0) break;
                --p;
            }
        }
    }
}

void CTRMode::processBlocks(uint8_t* data, size_t& length,
                            ISymmetricCipher* cipher,
                            const uint8_t* iv,
                            bool /*encrypt*/,
                            size_t user_threads)
{
    const size_t block_size = cipher->blockSize();
    if (length % block_size != 0) {
        throw std::runtime_error("CTR expects length to be multiple of block size when padding is enforced");
    }

    const size_t num_blocks = length / block_size;
    if (num_blocks == 0) return;
    if (!iv) throw std::runtime_error("CTR requires non-null IV");

    size_t threads_to_use = (user_threads > 0) ? user_threads : std::thread::hardware_concurrency();
    if (threads_to_use == 0) threads_to_use = 1;
    const size_t num_threads = std::min(threads_to_use, num_blocks);

    if (num_threads == 1 || num_blocks < 4) {
        uint8_t* counter = new uint8_t[block_size];
        uint8_t* ks      = new uint8_t[block_size];
        std::memcpy(counter, iv, block_size);

        for (size_t i = 0; i < num_blocks; ++i) {
            addToCounterRange(counter, block_size, 1); // IV+1, IV+2, ...
            cipher->encrypt(counter, ks);
            uint8_t* block = data + i * block_size;
            for (size_t j = 0; j < block_size; ++j) block[j] ^= ks[j];
        }
        delete[] counter;
        delete[] ks;
        return;
    }

    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    for (size_t t = 0; t < num_threads; ++t) {
        threads.emplace_back([=]() {
            uint8_t* counter = new uint8_t[block_size];
            uint8_t* ks      = new uint8_t[block_size];
            std::memcpy(counter, iv, block_size);

            const size_t start = t * blocks_per_thread;
            const size_t end   = std::min((t + 1) * blocks_per_thread, num_blocks);

            // counter := iv + start (сдвиг для стартового блока потока)
            addToCounterRange(counter, block_size, start);

            for (size_t i = start; i < end; ++i) {
                // для каждого блока: counter := counter + 1
                addToCounterRange(counter, block_size, 1);
                cipher->encrypt(counter, ks);

                uint8_t* block = data + i * block_size;
                for (size_t j = 0; j < block_size; ++j) block[j] ^= ks[j];
            }
            delete[] counter;
            delete[] ks;
        });
    }

    for (auto& thead : threads) thead.join();
}

bool CTRMode::canParallelize() const { return true; }
bool CTRMode::requiresIV() const { return true; }
