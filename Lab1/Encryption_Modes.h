// CipherModes.h
#pragma once
#include <vector>
#include <cstdint>
#include <memory>
#include <thread>
#include <algorithm>
#include "Interfaces.h"

class ICipherMode {
public:
    virtual ~ICipherMode() = default;
    virtual void processBlocks(std::vector<uint8_t>& data, ISymmetricCipher* cipher,
                               const std::vector<uint8_t>& iv, bool encrypt) = 0;
    virtual bool canParallelize() const = 0;
    virtual bool requiresIV() const = 0;
};

class ECBMode : public ICipherMode {
public:
    void processBlocks(std::vector<uint8_t>& data, ISymmetricCipher* cipher,
                       const std::vector<uint8_t>& iv, bool encrypt) override {
        size_t block_size = cipher->blockSize();
        size_t num_blocks = data.size() / block_size;

        // Параллельная обработка для ECB
        if (num_blocks > 1) {
            processBlocksParallel(data, cipher, encrypt);
        } else {
            for (size_t i = 0; i < num_blocks; i++) {
                uint8_t* block = data.data() + i * block_size;
                if (encrypt) cipher->encrypt(block, block);
                else cipher->decrypt(block, block);
            }
        }
    }

    bool canParallelize() const override { return true; }
    bool requiresIV() const override { return false; }

private:
    void processBlocksParallel(std::vector<uint8_t>& data, ISymmetricCipher* cipher, bool encrypt) {
        size_t block_size = cipher->blockSize();
        size_t num_blocks = data.size() / block_size;
        size_t possible_threads = std::thread::hardware_concurrency();

        size_t num_threads = std::min(possible_threads, num_blocks);
        if (num_threads == 0) num_threads = 1;

        std::vector<std::thread> threads;
        size_t blocks_per_thread = (num_blocks + num_threads - 1) / num_threads;

        for (size_t t = 0; t < num_threads; t++) {
            threads.emplace_back([&, t, encrypt]() {
                size_t start_block = t * blocks_per_thread;
                size_t end_block = std::min((t + 1) * blocks_per_thread, num_blocks);

                for (size_t i = start_block; i < end_block; i++) {
                    uint8_t* block = data.data() + i * block_size;
                    if (encrypt) cipher->encrypt(block, block);
                    else cipher->decrypt(block, block);
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }
    }
};

class CBCMode : public ICipherMode {
public:
    void processBlocks(std::vector<uint8_t>& data, ISymmetricCipher* cipher,
                       const std::vector<uint8_t>& iv, bool encrypt) override {
        size_t block_size = cipher->blockSize();
        size_t num_blocks = data.size() / block_size;
        std::vector<uint8_t> prev_block = iv;

        for (size_t i = 0; i < num_blocks; i++) {
            uint8_t* block = data.data() + i * block_size;

            if (encrypt) {
                // XOR с предыдущим блоком -> шифрование
                for (size_t j = 0; j < block_size; j++) {
                    block[j] ^= prev_block[j];
                }
                cipher->encrypt(block, block);
                prev_block.assign(block, block + block_size);
            } else {
                // Дешифрование -> XOR с предыдущим блоком
                std::vector<uint8_t> temp_block(block, block + block_size);
                cipher->decrypt(block, block);
                for (size_t j = 0; j < block_size; j++) {
                    block[j] ^= prev_block[j];
                }
                prev_block = temp_block;
            }
        }
    }

    bool canParallelize() const override { return false; }
    bool requiresIV() const override { return true; }
};

class PCBCMode : public ICipherMode {
public:
    void processBlocks(std::vector<uint8_t>& data, ISymmetricCipher* cipher,
                       const std::vector<uint8_t>& iv, bool encrypt) override {
        size_t block_size = cipher->blockSize();
        size_t num_blocks = data.size() / block_size;
        std::vector<uint8_t> prev_input = iv;
        std::vector<uint8_t> prev_output = iv;

        for (size_t i = 0; i < num_blocks; i++) {
            uint8_t* block = data.data() + i * block_size;

            if (encrypt) {
                // XOR: input ^ prev_input ^ prev_output
                for (size_t j = 0; j < block_size; j++) {
                    block[j] ^= prev_input[j] ^ prev_output[j];
                }
                cipher->encrypt(block, block);
                prev_input.assign(data.data() + i * block_size, data.data() + (i + 1) * block_size);
                prev_output.assign(block, block + block_size);
            } else {
                std::vector<uint8_t> temp_block(block, block + block_size);
                cipher->decrypt(block, block);
                // XOR: decrypted ^ prev_input ^ prev_output
                for (size_t j = 0; j < block_size; j++) {
                    block[j] ^= prev_input[j] ^ prev_output[j];
                }
                prev_input.assign(block, block + block_size);
                prev_output = temp_block;
            }
        }
    }

    bool canParallelize() const override { return false; }
    bool requiresIV() const override { return true; }
};

class CFBMode : public ICipherMode {
public:
    void processBlocks(std::vector<uint8_t>& data, ISymmetricCipher* cipher,
                       const std::vector<uint8_t>& iv, bool encrypt) override {
        size_t block_size = cipher->blockSize();
        size_t num_blocks = data.size() / block_size;
        std::vector<uint8_t> shift_register = iv;

        for (size_t i = 0; i < num_blocks; i++) {
            uint8_t* block = data.data() + i * block_size;

            // Шифруем регистр сдвига
            std::vector<uint8_t> encrypted(block_size);
            cipher->encrypt(shift_register.data(), encrypted.data());

            // XOR с входными данными
            for (size_t j = 0; j < block_size; j++) {
                block[j] ^= encrypted[j];
            }

            // Обновляем регистр сдвига
            if (encrypt) {
                shift_register.assign(block, block + block_size);
            } else {
                shift_register.assign(data.data() + i * block_size, data.data() + (i + 1) * block_size);
            }
        }
    }

    bool canParallelize() const override { return false; }
    bool requiresIV() const override { return true; }
};

class OFBMode : public ICipherMode {
public:
    void processBlocks(std::vector<uint8_t>& data, ISymmetricCipher* cipher,
                       const std::vector<uint8_t>& iv, bool encrypt) override {
        size_t block_size = cipher->blockSize();
        size_t num_blocks = data.size() / block_size;
        std::vector<uint8_t> key_stream = iv;

        for (size_t i = 0; i < num_blocks; i++) {
            uint8_t* block = data.data() + i * block_size;

            // Генерируем следующий ключевой поток
            std::vector<uint8_t> new_key_stream(block_size);
            cipher->encrypt(key_stream.data(), new_key_stream.data());

            // XOR с ключевым потоком
            for (size_t j = 0; j < block_size; j++) {
                block[j] ^= new_key_stream[j];
            }

            key_stream = std::move(new_key_stream);
        }
    }

    bool canParallelize() const override { return false; }
    bool requiresIV() const override { return true; }
};

class CTRMode : public ICipherMode {
public:
    void processBlocks(std::vector<uint8_t>& data, ISymmetricCipher* cipher,
                       const std::vector<uint8_t>& iv, bool encrypt) override {
        size_t block_size = cipher->blockSize();
        size_t num_blocks = data.size() / block_size;

        // Параллельная обработка для CTR
        if (num_blocks > 1) {
            processBlocksParallel(data, cipher, iv);
        } else {
            for (size_t i = 0; i < num_blocks; i++) {
                processSingleBlock(data, cipher, iv, i);
            }
        }
    }

    bool canParallelize() const override { return true; }
    bool requiresIV() const override { return true; }

private:
    void processBlocksParallel(std::vector<uint8_t>& data, ISymmetricCipher* cipher,
                               const std::vector<uint8_t>& iv) {
        size_t block_size = cipher->blockSize();
        size_t num_blocks = data.size() / block_size;
        size_t possible_threads = std::thread::hardware_concurrency();

        size_t num_threads = std::min(possible_threads, num_blocks);
        if (num_threads == 0) num_threads = 1;

        std::vector<std::thread> threads;
        size_t blocks_per_thread = (num_blocks + num_threads - 1) / num_threads;

        for (size_t t = 0; t < num_threads; t++) {
            threads.emplace_back([&, t]() {
                size_t start_block = t * blocks_per_thread;
                size_t end_block = std::min((t + 1) * blocks_per_thread, num_blocks);

                for (size_t i = start_block; i < end_block; i++) {
                    processSingleBlock(data, cipher, iv, i);
                }
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }
    }

    void processSingleBlock(std::vector<uint8_t>& data, ISymmetricCipher* cipher,
                            const std::vector<uint8_t>& iv, size_t block_index) {
        size_t block_size = cipher->blockSize();
        uint8_t* block = data.data() + block_index * block_size;

        std::vector<uint8_t> counter = iv;
        // Увеличиваем счетчик на номер блока
        for (size_t i = 0; i < sizeof(size_t); i++) {
            size_t byte_pos = counter.size() - 1 - i;
            uint8_t add_val = (block_index >> (i * 8)) & 0xFF;
            uint16_t sum = counter[byte_pos] + add_val;
            counter[byte_pos] = sum & 0xFF;
            if (sum > 0xFF && byte_pos > 0) {
                counter[byte_pos - 1] += 1;
            }
        }

        // Генерируем ключевой поток
        std::vector<uint8_t> key_stream(block_size);
        cipher->encrypt(counter.data(), key_stream.data());

        // XOR с данными
        for (size_t j = 0; j < block_size; j++) {
            block[j] ^= key_stream[j];
        }
    }
};

class RandomDeltaMode : public ICipherMode {
public:
    void processBlocks(std::vector<uint8_t>& data, ISymmetricCipher* cipher,
                       const std::vector<uint8_t>& iv, bool encrypt) override {
        size_t block_size = cipher->blockSize();
        size_t num_blocks = data.size() / block_size;

        for (size_t i = 0; i < num_blocks; i++) {
            uint8_t* block = data.data() + i * block_size;

            // Генерируем delta на основе номера блока
            std::vector<uint8_t> delta(block_size);
            std::fill(delta.begin(), delta.end(), static_cast<uint8_t>(i & 0xFF));

            if (encrypt) {
                // XOR с delta -> шифрование
                for (size_t j = 0; j < block_size; j++) {
                    block[j] ^= delta[j];
                }
                cipher->encrypt(block, block);
            } else {
                // Дешифрование -> XOR с delta
                cipher->decrypt(block, block);
                for (size_t j = 0; j < block_size; j++) {
                    block[j] ^= delta[j];
                }
            }
        }
    }

    bool canParallelize() const override { return true; }
    bool requiresIV() const override { return true; }
};