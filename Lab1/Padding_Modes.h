// Padding.h
#pragma once
#include <cstdint>
#include <stdexcept>
#include <memory>
#include <algorithm>
#include <cstdlib>

class IPadding {
public:
    virtual ~IPadding() = default;

    // apply: принимает указатель на данные и их длину,
    // возвращает новый буфер с паддингом и обновляет длину
    virtual void apply(uint8_t*& data, size_t& length, size_t block_size) = 0;

    // remove: принимает указатель на данные и длину,
    // уменьшает длину (буфер остаётся тем же)
    virtual void remove(uint8_t* data, size_t& length, size_t block_size) = 0;
};

class ZerosPadding : public IPadding {
public:
    void apply(uint8_t*& data, size_t& length, size_t block_size) override {
        size_t padding_size = block_size - (length % block_size);
        if (padding_size == block_size) padding_size = 0;

        if (padding_size > 0) {
            std::unique_ptr<uint8_t[]> new_data(new uint8_t[length + padding_size]);
            std::copy(data, data + length, new_data.get());
            std::fill(new_data.get() + length, new_data.get() + length + padding_size, 0x00);

            data = new_data.release();
            length += padding_size;
        }
    }

    void remove(uint8_t* data, size_t& length, size_t block_size) override {
        if (length == 0) return;

        size_t padding_size = 0;
        for (size_t i = length; i > 0; --i) {
            if (data[i - 1] == 0x00) padding_size++;
            else break;
        }
        if (padding_size > 0) length -= padding_size;
    }
};

class ANSIX923Padding : public IPadding {
public:
    void apply(uint8_t*& data, size_t& length, size_t block_size) override {
        size_t rem = length % block_size;
        size_t padding_size = (rem == 0) ? block_size : (block_size - rem);

        std::unique_ptr<uint8_t[]> new_data(new uint8_t[length + padding_size]);
        std::copy(data, data + length, new_data.get());
        std::fill(new_data.get() + length, new_data.get() + length + padding_size - 1, 0x00);
        new_data[length + padding_size - 1] = static_cast<uint8_t>(padding_size);

        data = new_data.release();
        length += padding_size;
    }

    void remove(uint8_t* data, size_t& length, size_t block_size) override {
        if (length == 0) return;

        size_t padding_size = data[length - 1];
        if (padding_size == 0 || padding_size > block_size || padding_size > length)
            throw std::runtime_error("Invalid ANSI X.923 padding");

        for (size_t i = length - padding_size; i < length - 1; ++i) {
            if (data[i] != 0x00)
                throw std::runtime_error("Invalid ANSI X.923 padding - non-zero bytes found");
        }

        length -= padding_size;
    }
};

class PKCS7Padding : public IPadding {
public:
    void apply(uint8_t*& data, size_t& length, size_t block_size) override {
        size_t rem = length % block_size;
        size_t padding_size = (rem == 0) ? block_size : (block_size - rem);

        std::unique_ptr<uint8_t[]> new_data(new uint8_t[length + padding_size]);
        std::copy(data, data + length, new_data.get());
        std::fill(new_data.get() + length, new_data.get() + length + padding_size,
                  static_cast<uint8_t>(padding_size));

        data = new_data.release();
        length += padding_size;
    }

    void remove(uint8_t* data, size_t& length, size_t block_size) override {
        if (length == 0) return;

        size_t padding_size = data[length - 1];
        if (padding_size == 0 || padding_size > block_size || padding_size > length)
            throw std::runtime_error("Invalid PKCS7 padding");

        for (size_t i = length - padding_size; i < length; ++i) {
            if (data[i] != padding_size)
                throw std::runtime_error("Invalid PKCS7 padding - inconsistent padding bytes");
        }

        length -= padding_size;
    }
};

class ISO10126Padding : public IPadding {
public:
    void apply(uint8_t*& data, size_t& length, size_t block_size) override {
        size_t rem = length % block_size;
        size_t padding_size = (rem == 0) ? block_size : (block_size - rem);

        std::unique_ptr<uint8_t[]> new_data(new uint8_t[length + padding_size]);
        std::copy(data, data + length, new_data.get());

        for (size_t i = length; i < length + padding_size - 1; ++i) {
            new_data[i] = static_cast<uint8_t>(rand() % 256);
        }
        new_data[length + padding_size - 1] = static_cast<uint8_t>(padding_size);

        data = new_data.release();
        length += padding_size;
    }

    void remove(uint8_t* data, size_t& length, size_t block_size) override {
        if (length == 0) return;

        size_t padding_size = data[length - 1];
        if (padding_size == 0 || padding_size > block_size || padding_size > length)
            throw std::runtime_error("Invalid ISO 10126 padding");

        length -= padding_size;
    }
};

