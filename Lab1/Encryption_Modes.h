// Encryption_Modes.h
#pragma once
#include <thread>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include "Interfaces.h"

class ICipherMode {
public:
    virtual ~ICipherMode() = default;

    // data: указатель на массив байтов, length: текущая длина (в байтах)
    // iv: указатель на IV, размер IV = cipher->blockSize()
    // encrypt: true -> шифрование, false -> расшифрование
    virtual void processBlocks(uint8_t* data, size_t& length,
                               ISymmetricCipher* cipher,
                               const uint8_t* iv,
                               bool encrypt) = 0;

    virtual bool canParallelize() const = 0;
    virtual bool requiresIV() const = 0;
};


class ECBMode : public ICipherMode {
public:
    void processBlocks(uint8_t* data, size_t& length,
                       ISymmetricCipher* cipher,
                       const uint8_t* /*iv*/,
                       bool encrypt) override
    {
        const size_t block_size = cipher->blockSize();
        const size_t num_blocks = length / block_size;

        if (num_blocks == 0) return;

        const unsigned hw = std::thread::hardware_concurrency();
        const size_t num_threads = std::max<size_t>(1, std::min<size_t>(hw ? hw : 1, num_blocks));
        const size_t blocks_per_thread = (num_blocks + num_threads - 1) / num_threads;

        // Параллельная обработка независимых блоков
        std::unique_ptr<std::thread[]> threads(new std::thread[num_threads]);

        for (size_t t = 0; t < num_threads; ++t) {
            threads[t] = std::thread([=]() {
                const size_t start_block = t * blocks_per_thread;
                const size_t end_block = std::min((t + 1) * blocks_per_thread, num_blocks);

                for (size_t i = start_block; i < end_block; ++i) {
                    uint8_t* block = data + i * block_size;
                    if (encrypt) cipher->encrypt(block, block);
                    else cipher->decrypt(block, block);
                }
            });
        }
        for (size_t t = 0; t < num_threads; ++t) threads[t].join();
    }

    bool canParallelize() const override { return true; }
    bool requiresIV() const override { return false; }
};


class CBCMode : public ICipherMode {
public:
    void processBlocks(uint8_t* data, size_t& length,
                       ISymmetricCipher* cipher,
                       const uint8_t* iv,
                       bool encrypt) override
    {
        const size_t block_size = cipher->blockSize();
        const size_t num_blocks = length / block_size;
        if (num_blocks == 0) return;

        // prev_block хранится как локальный буфер фиксированной длины
        std::unique_ptr<uint8_t[]> prev_block(new uint8_t[block_size]);
        std::copy(iv, iv + block_size, prev_block.get());

        for (size_t i = 0; i < num_blocks; ++i) {
            uint8_t* block = data + i * block_size;

            if (encrypt) {
                for (size_t j = 0; j < block_size; ++j)
                    block[j] ^= prev_block[j];
                cipher->encrypt(block, block);
                std::copy(block, block + block_size, prev_block.get());
            } else {
                // Сохранить текущий шифртекстовый блок
                std::unique_ptr<uint8_t[]> ctmp(new uint8_t[block_size]);
                std::copy(block, block + block_size, ctmp.get());

                cipher->decrypt(block, block);
                for (size_t j = 0; j < block_size; ++j)
                    block[j] ^= prev_block[j];
                std::copy(ctmp.get(), ctmp.get() + block_size, prev_block.get());
            }
        }
    }

    bool canParallelize() const override { return false; }
    bool requiresIV() const override { return true; }
};

class PCBCMode : public ICipherMode {
public:
    void processBlocks(uint8_t* data, size_t& length,
                       ISymmetricCipher* cipher,
                       const uint8_t* iv,
                       bool encrypt) override
    {
        const size_t block_size = cipher->blockSize();
        const size_t num_blocks = length / block_size;
        if (num_blocks == 0) return;

        std::unique_ptr<uint8_t[]> prev_in(new uint8_t[block_size]);
        std::unique_ptr<uint8_t[]> prev_out(new uint8_t[block_size]);
        std::copy(iv, iv + block_size, prev_in.get());
        std::copy(iv, iv + block_size, prev_out.get());

        for (size_t i = 0; i < num_blocks; ++i) {
            uint8_t* block = data + i * block_size;

            if (encrypt) {
                for (size_t j = 0; j < block_size; ++j)
                    block[j] ^= (prev_in[j] ^ prev_out[j]);
                cipher->encrypt(block, block);
                std::copy(data + i * block_size, data + (i + 1) * block_size, prev_in.get());
                std::copy(block, block + block_size, prev_out.get());
            } else {
                std::unique_ptr<uint8_t[]> ctmp(new uint8_t[block_size]);
                std::copy(block, block + block_size, ctmp.get());

                cipher->decrypt(block, block);
                for (size_t j = 0; j < block_size; ++j)
                    block[j] ^= (prev_in[j] ^ prev_out[j]);

                std::copy(block, block + block_size, prev_in.get());
                std::copy(ctmp.get(), ctmp.get() + block_size, prev_out.get());
            }
        }
    }

    bool canParallelize() const override { return false; }
    bool requiresIV() const override { return true; }
};

class CFBMode : public ICipherMode {
public:
    void processBlocks(uint8_t* data, size_t& length,
                       ISymmetricCipher* cipher,
                       const uint8_t* iv,
                       bool encrypt) override
    {
        const size_t block_size = cipher->blockSize();
        const size_t num_blocks = length / block_size;
        if (num_blocks == 0) return;

        std::unique_ptr<uint8_t[]> shift(new uint8_t[block_size]);
        std::copy(iv, iv + block_size, shift.get());

        std::unique_ptr<uint8_t[]> ks(new uint8_t[block_size]);

        for (size_t i = 0; i < num_blocks; ++i) {
            uint8_t* block = data + i * block_size;

            cipher->encrypt(shift.get(), ks.get()); // шифруем регистр

            for (size_t j = 0; j < block_size; ++j)
                block[j] ^= ks[j];

            // обновляем регистр
            if (encrypt) {
                std::copy(block, block + block_size, shift.get());
            } else {
                std::copy(data + i * block_size, data + (i + 1) * block_size, shift.get());
            }
        }
    }

    bool canParallelize() const override { return false; }
    bool requiresIV() const override { return true; }
};


class OFBMode : public ICipherMode {
public:
    void processBlocks(uint8_t* data, size_t& length,
                       ISymmetricCipher* cipher,
                       const uint8_t* iv,
                       bool /*encrypt*/) override
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

    bool canParallelize() const override { return false; }
    bool requiresIV() const override { return true; }
};


class CTRMode : public ICipherMode {
public:
    void processBlocks(uint8_t* data, size_t& length,
                       ISymmetricCipher* cipher,
                       const uint8_t* iv,
                       bool /*encrypt*/) override
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

                // локальный буфер для ключевого потока
                std::unique_ptr<uint8_t[]> ks(new uint8_t[block_size]);

                const size_t start_block = t * blocks_per_thread;
                const size_t end_block = std::min((t + 1) * blocks_per_thread, num_blocks);

                for (size_t i = start_block; i < end_block; ++i) {
                    // counter = iv + i (big-endian инкремент)
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

    bool canParallelize() const override { return true; }
    bool requiresIV() const override { return true; }

private:
    static void addToCounter(uint8_t* counter, size_t counter_len, size_t add) {
        // big-endian: инкремент с конца, учитывая переносы
        size_t carry = add;
        for (size_t k = 0; k < counter_len && carry > 0; ++k) {
            size_t pos = counter_len - 1 - k;
            size_t sum = static_cast<size_t>(counter[pos]) + (carry & 0xFF);
            counter[pos] = static_cast<uint8_t>(sum & 0xFF);
            carry >>= 8;
            if (sum > 0xFF && pos > 0) {
                // перенос
                size_t p = pos - 1;
                while (p < counter_len) { // защита от size_t underflow
                    unsigned val = counter[p] + 1;
                    counter[p] = static_cast<uint8_t>(val & 0xFF);
                    if (val <= 0xFF) break;
                    if (p == 0) break;
                    --p;
                }
            }
        }
    }
};


class RandomDeltaMode : public ICipherMode {
public:
    void processBlocks(uint8_t* data, size_t& length,
                       ISymmetricCipher* cipher,
                       const uint8_t* /*iv*/,
                       bool encrypt) override
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
                std::unique_ptr<uint8_t[]> delta(new uint8_t[block_size]);

                const size_t start_block = t * blocks_per_thread;
                const size_t end_block = std::min((t + 1) * blocks_per_thread, num_blocks);

                for (size_t i = start_block; i < end_block; ++i) {
                    uint8_t* block = data + i * block_size;

                    // Заполняем delta значением номера блока (мод 256)
                    std::fill(delta.get(), delta.get() + block_size, static_cast<uint8_t>(i & 0xFF));

                    if (encrypt) {
                        for (size_t j = 0; j < block_size; ++j)
                            block[j] ^= delta[j];
                        cipher->encrypt(block, block);
                    } else {
                        cipher->decrypt(block, block);
                        for (size_t j = 0; j < block_size; ++j)
                            block[j] ^= delta[j];
                    }
                }
            });
        }

        for (size_t t = 0; t < num_threads; ++t) threads[t].join();
    }

    bool canParallelize() const override { return true; }
    bool requiresIV() const override { return false; } // IV реально не используется
};
