// SymmetricCipherContext.h
#pragma once
#include <memory>
#include <thread>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <functional>
#include <stdexcept>
#include "Interfaces.h"
#include "Feistel_network.h"
#include "Encryption_Modes.h"
#include "Padding_Modes.h"
#include <variant>
#include <iostream>

enum class CipherMode { ECB, CBC, PCBC, CFB, OFB, CTR, RANDOM_DELTA };
enum class PaddingMode { ZEROS, ANSI_X923, PKCS7, ISO_10126 };
enum class CipherAlgorithm { DES, DEAL };

using AdditionalParam = std::variant<int, std::string, std::unique_ptr<uint8_t[]>>;

class SymmetricCipherContext {
private:
    std::unique_ptr<ISymmetricCipher> cipher;
    std::unique_ptr<ICipherMode> mode;
    std::unique_ptr<IPadding> padding;
    std::unique_ptr<uint8_t[]> iv;
    ByteOrder byte_order;
    size_t key_size;
    size_t block_size;

    std::unique_ptr<ICipherMode> createCipherMode(CipherMode mode) {
        switch (mode) {
            case CipherMode::ECB: return std::make_unique<ECBMode>();
            case CipherMode::CBC: return std::make_unique<CBCMode>();
            case CipherMode::PCBC: return std::make_unique<PCBCMode>();
            case CipherMode::CFB: return std::make_unique<CFBMode>();
            case CipherMode::OFB: return std::make_unique<OFBMode>();
            case CipherMode::CTR: return std::make_unique<CTRMode>();
            case CipherMode::RANDOM_DELTA: return std::make_unique<RandomDeltaMode>();
            default: throw std::invalid_argument("Unsupported cipher mode");
        }
    }

    bool requiresIV(CipherMode mode) const { return mode != CipherMode::ECB; }

    std::unique_ptr<IPadding> createPadding(PaddingMode padding_mode) {
        switch (padding_mode) {
            case PaddingMode::ZEROS: return std::make_unique<ZerosPadding>();
            case PaddingMode::ANSI_X923: return std::make_unique<ANSIX923Padding>();
            case PaddingMode::PKCS7: return std::make_unique<PKCS7Padding>();
            case PaddingMode::ISO_10126: return std::make_unique<ISO10126Padding>();
            default: throw std::invalid_argument("Unsupported padding mode");
        }
    }

    void processData(uint8_t*& data, size_t& length, bool encrypt) {
        if (encrypt) {
            padding->apply(data, length, block_size);
            mode->processBlocks(data, length, cipher.get(), iv.get(), true);
        } else {
            mode->processBlocks(data, length, cipher.get(), iv.get(), false);
            padding->remove(data, length, block_size);
        }
    }

    void processFile(const std::string& input_file, const std::string& output_file, bool encrypt) {
        std::ifstream in_file(input_file, std::ios::binary | std::ios::ate);
        if (!in_file) throw std::runtime_error("Cannot open input file: " + input_file);

        size_t file_size = static_cast<size_t>(in_file.tellg());
        in_file.seekg(0, std::ios::beg);

        uint8_t* data = new uint8_t[file_size];
        in_file.read(reinterpret_cast<char*>(data), file_size);
        in_file.close();

        // ВАЖНО: указатель по ссылке
        processData(data, file_size, encrypt);

        std::ofstream out_file(output_file, std::ios::binary);
        if (!out_file) {
            delete[] data;
            throw std::runtime_error("Cannot open output file: " + output_file);
        }
        out_file.write(reinterpret_cast<const char*>(data), file_size);
        out_file.close();

        delete[] data;
    }


public:
    SymmetricCipherContext(
            CipherAlgorithm algorithm,
            CipherMode c_mode,
            PaddingMode p_mode,
            const uint8_t* key,
            size_t key_len,
            const uint8_t* initialization_vector = nullptr,
            size_t iv_len = 0,
            const std::vector<AdditionalParam>& additional_params = {}
    ) : byte_order(ByteOrder::BIG_ENDIAN) {
        switch (algorithm) {
            case CipherAlgorithm::DES:
                cipher = std::make_unique<DES>(byte_order);
                key_size = 8;
                break;
            case CipherAlgorithm::DEAL:
                key_size = key_len;
                cipher = std::make_unique<DEAL>(key_size, byte_order);
                break;
            default:
                throw std::invalid_argument("Unsupported cipher algorithm");
        }

        if (key_len != cipher->keySize())
            throw std::invalid_argument("Key size doesn't match algorithm requirements");

        cipher->setupKeys(key, key_len);

        mode = createCipherMode(c_mode);
        padding = createPadding(p_mode);

        block_size = cipher->blockSize();

        if (requiresIV(c_mode)) {
            iv = std::make_unique<uint8_t[]>(block_size);
            if (initialization_vector && iv_len == block_size) {
                std::copy(initialization_vector, initialization_vector + block_size, iv.get());
            } else {
                std::fill(iv.get(), iv.get() + block_size, 0);
            }
        }
    }

    // Основные методы
    void encrypt(const uint8_t* input, size_t in_len, uint8_t* output, size_t& out_len) {
        // рабочий буфер
        uint8_t* buf = new uint8_t[in_len];
        std::copy(input, input + in_len, buf);

        size_t len = in_len;
        processData(buf, len, true);

        std::copy(buf, buf + len, output);
        out_len = len;

        delete[] buf;
    }

    void decrypt(const uint8_t* input, size_t in_len, uint8_t* output, size_t& out_len) {
        uint8_t* buf = new uint8_t[in_len];
        std::copy(input, input + in_len, buf);

        size_t len = in_len;
        processData(buf, len, false);

        std::copy(buf, buf + len, output);
        out_len = len;

        delete[] buf;
    }

    void encrypt(const std::string& input_file, const std::string& output_file, size_t& out_len) {
        std::ifstream in_file(input_file, std::ios::binary | std::ios::ate);
        if (!in_file) throw std::runtime_error("Cannot open input file: " + input_file);

        size_t file_size = static_cast<size_t>(in_file.tellg());
        in_file.seekg(0, std::ios::beg);

        uint8_t* data = new uint8_t[file_size];
        in_file.read(reinterpret_cast<char*>(data), file_size);
        in_file.close();

        processData(data, file_size, true);

        std::ofstream out_file(output_file, std::ios::binary);
        if (!out_file) {
            delete[] data;
            throw std::runtime_error("Cannot open output file: " + output_file);
        }
        out_file.write(reinterpret_cast<const char*>(data), file_size);
        out_file.close();

        out_len = file_size; // записываем фактическую длину
        delete[] data;
    }

    void decrypt(const std::string& input_file, const std::string& output_file, size_t& out_len) {
        std::ifstream in_file(input_file, std::ios::binary | std::ios::ate);
        if (!in_file) throw std::runtime_error("Cannot open input file: " + input_file);

        size_t file_size = static_cast<size_t>(in_file.tellg());
        in_file.seekg(0, std::ios::beg);

        uint8_t* data = new uint8_t[file_size];
        in_file.read(reinterpret_cast<char*>(data), file_size);
        in_file.close();

        processData(data, file_size, false);

        std::ofstream out_file(output_file, std::ios::binary);
        if (!out_file) {
            delete[] data;
            throw std::runtime_error("Cannot open output file: " + output_file);
        }
        out_file.write(reinterpret_cast<const char*>(data), file_size);
        out_file.close();

        out_len = file_size; // записываем фактическую длину
        delete[] data;
    }

    // Асинхронные версии
    void encryptAsync(const uint8_t* input, size_t in_len, uint8_t* output, size_t& out_len) {
        std::thread([this, input, in_len, output, &out_len]() {
            this->encrypt(input, in_len, output, out_len);
        }).detach();
    }

    void decryptAsync(const uint8_t* input, size_t in_len, uint8_t* output, size_t& out_len) {
        std::thread([this, input, in_len, output, &out_len]() {
            this->decrypt(input, in_len, output, out_len);
        }).detach();
    }

    void encryptAsync(const std::string& input_file, const std::string& output_file, size_t& out_len) {
        std::thread([this, input_file, output_file, &out_len]() {
            this->encrypt(input_file, output_file, out_len);
        }).detach();
    }

    void decryptAsync(const std::string& input_file, const std::string& output_file, size_t& out_len) {
        std::thread([this, input_file, output_file, &out_len]() {
            this->decrypt(input_file, output_file, out_len);
        }).detach();
    }
};
