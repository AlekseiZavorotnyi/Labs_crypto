// Padding.h - исправленная версия
#pragma once
#include <vector>
#include <cstdint>
#include <stdexcept>

class IPadding {
public:
    virtual ~IPadding() = default;
    virtual void apply(std::vector<uint8_t>& data, size_t block_size) = 0;
    virtual void remove(std::vector<uint8_t>& data, size_t block_size) = 0;
};

class ZerosPadding : public IPadding {
public:
    void apply(std::vector<uint8_t>& data, size_t block_size) override {
        size_t padding_size = block_size - (data.size() % block_size);
        if (padding_size == block_size) padding_size = 0;

        if (padding_size > 0) {
            size_t old_size = data.size();
            data.resize(old_size + padding_size);
            std::fill(data.begin() + old_size, data.end(), 0x00);
        }
    }

    void remove(std::vector<uint8_t>& data, size_t block_size) override {
        if (data.empty()) return;

        // Ищем первый ненулевой байт с конца
        size_t padding_size = 0;
        for (auto it = data.rbegin(); it != data.rend(); ++it) {
            if (*it != 0) {
                padding_size = std::distance(data.rbegin(), it);
                break;
            }
        }

        if (padding_size > 0) {
            data.resize(data.size() - padding_size);
        }
    }
};

class ANSIX923Padding : public IPadding {
public:
    void apply(std::vector<uint8_t>& data, size_t block_size) override {
        size_t padding_size = block_size - (data.size() % block_size);
        if (padding_size == block_size) padding_size = 0;

        if (padding_size > 0) {
            size_t old_size = data.size();
            data.resize(old_size + padding_size);
            std::fill(data.begin() + old_size, data.end() - 1, 0x00);
            data.back() = static_cast<uint8_t>(padding_size);
        }
    }

    void remove(std::vector<uint8_t>& data, size_t block_size) override {
        if (data.empty()) return;

        size_t padding_size = data.back();

        // Проверяем валидность padding
        if (padding_size == 0 || padding_size > block_size || padding_size > data.size()) {
            throw std::runtime_error("Invalid ANSI X.923 padding");
        }

        // Проверяем, что все байты padding кроме последнего равны 0
        for (size_t i = data.size() - padding_size; i < data.size() - 1; i++) {
            if (data[i] != 0x00) {
                throw std::runtime_error("Invalid ANSI X.923 padding - non-zero bytes found");
            }
        }

        data.resize(data.size() - padding_size);
    }
};

class PKCS7Padding : public IPadding {
public:
    void apply(std::vector<uint8_t>& data, size_t block_size) override {
        size_t padding_size = block_size - (data.size() % block_size);
        if (padding_size == block_size) padding_size = 0;

        if (padding_size > 0) {
            size_t old_size = data.size();
            data.resize(old_size + padding_size);
            std::fill(data.begin() + old_size, data.end(), static_cast<uint8_t>(padding_size));
        }
    }

    void remove(std::vector<uint8_t>& data, size_t block_size) override {
        if (data.empty()) return;

        size_t padding_size = data.back();

        // Проверяем валидность padding
        if (padding_size == 0 || padding_size > block_size || padding_size > data.size()) {
            throw std::runtime_error("Invalid PKCS7 padding");
        }

        // Проверяем, что все байты padding равны значению padding_size
        for (size_t i = data.size() - padding_size; i < data.size(); i++) {
            if (data[i] != padding_size) {
                throw std::runtime_error("Invalid PKCS7 padding - inconsistent padding bytes");
            }
        }

        data.resize(data.size() - padding_size);
    }
};

class ISO10126Padding : public IPadding {
public:
    void apply(std::vector<uint8_t>& data, size_t block_size) override {
        size_t padding_size = block_size - (data.size() % block_size);
        if (padding_size == block_size) padding_size = 0;

        if (padding_size > 0) {
            size_t old_size = data.size();
            data.resize(old_size + padding_size);
            // В реальной реализации здесь должны быть случайные байты
            for (size_t i = old_size; i < data.size() - 1; i++) {
                data[i] = static_cast<uint8_t>(rand() % 256); // Простые случайные значения
            }
            data.back() = static_cast<uint8_t>(padding_size);
        }
    }

    void remove(std::vector<uint8_t>& data, size_t block_size) override {
        if (data.empty()) return;

        size_t padding_size = data.back();

        // Проверяем валидность padding
        if (padding_size == 0 || padding_size > block_size || padding_size > data.size()) {
            throw std::runtime_error("Invalid ISO 10126 padding");
        }

        // Для ISO 10126 проверяем только последний байт
        // (случайные байты не проверяем, так как они могут быть любыми)

        data.resize(data.size() - padding_size);
    }
};