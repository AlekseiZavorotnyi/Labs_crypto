// SymmetricCipherContext.cpp
#include "SymmetricCipherContext.h"
#include "PaddingModes/ANSIX923Padding.h"
#include "PaddingModes/ISO10126Padding.h"
#include "PaddingModes/PKCS7Padding.h"
#include "PaddingModes/ZerosPadding.h"
#include "CipherModes/CBCMode.h"
#include "CipherModes/ECBMode.h"
#include "CipherModes/OFBMode.h"
#include "CipherModes/CFBMode.h"
#include "CipherModes/CTRMode.h"
#include "CipherModes/PCBCMode.h"
#include "CipherModes/RandomDeltaMode.h"

#include <cstring>
#include <stdexcept>
#include <fstream>

// Фабрика режимов
std::unique_ptr<ICipherMode> SymmetricCipherContext::createCipherMode(CipherMode CipherMode) {
    switch (CipherMode) {
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

// Требуется ли IV
bool SymmetricCipherContext::requiresIV(CipherMode CipherMode) const {
    return CipherMode != CipherMode::ECB;
}

// Фабрика паддинга
std::unique_ptr<IPadding> SymmetricCipherContext::createPadding(PaddingMode padding_mode) {
    switch (padding_mode) {
        case PaddingMode::ZEROS: return std::make_unique<ZerosPadding>();
        case PaddingMode::ANSI_X923: return std::make_unique<ANSIX923Padding>();
        case PaddingMode::PKCS7: return std::make_unique<PKCS7Padding>();
        case PaddingMode::ISO_10126: return std::make_unique<ISO10126Padding>();
        default: throw std::invalid_argument("Unsupported padding mode");
    }
}

// Обработка данных (всегда применяем паддинг перед шифрованием и снимаем после расшифрования)
void SymmetricCipherContext::processData(uint8_t*& data, size_t& length, bool encrypt) {
    if (encrypt) {
        padding->apply(data, length, block_size);
        mode->processBlocks(data, length, cipher.get(), iv ? iv.get() : nullptr, true, user_threads);
    } else {
        mode->processBlocks(data, length, cipher.get(), iv ? iv.get() : nullptr, false, user_threads);
        padding->remove(data, length, block_size);
    }
}

// Обработка файла целиком (корректно учитываем изменившуюся длину после паддинга/снятия)
void SymmetricCipherContext::processFile(const std::string& input_file, const std::string& output_file, bool encrypt) {
    std::ifstream in_file(input_file, std::ios::binary | std::ios::ate);
    if (!in_file) throw std::runtime_error("Cannot open input file: " + input_file);

    size_t file_size = static_cast<size_t>(in_file.tellg());
    in_file.seekg(0, std::ios::beg);

    uint8_t* data = nullptr;
    if (file_size > 0) {
        data = new uint8_t[file_size];
        in_file.read(reinterpret_cast<char*>(data), file_size);
        if (!in_file) {
            delete[] data;
            throw std::runtime_error("Failed to read input file: " + input_file);
        }
    }
    in_file.close();

    // ВАЖНО: length может измениться после паддинга/снятия
    size_t length = file_size;
    processData(data, length, encrypt);

    std::ofstream out_file(output_file, std::ios::binary);
    if (!out_file) {
        delete[] data;
        throw std::runtime_error("Cannot open output file: " + output_file);
    }
    if (length > 0 && data) {
        out_file.write(reinterpret_cast<const char*>(data), length);
        if (!out_file) {
            delete[] data;
            throw std::runtime_error("Failed to write output file: " + output_file);
        }
    }
    out_file.close();

    delete[] data;
}

// Конструктор
SymmetricCipherContext::SymmetricCipherContext(
        CipherAlgorithm algorithm,
        CipherMode c_mode,
        PaddingMode p_mode,
        const uint8_t* key,
        size_t key_len,
        const uint8_t* initialization_vector,
        size_t iv_len,
        const std::vector<std::any>& additionalParams
) : byte_order(ByteOrder::BIG_ENDIAN) {
    processAdditionalParams(additionalParams);
    switch (algorithm) {
        case CipherAlgorithm::DES:
            cipher = std::make_unique<DES>(byte_order);
            key_size = 8;
            break;
        case CipherAlgorithm::DEAL:
            key_size = key_len; // DEAL принимает длину ключа по факту
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
            std::memcpy(iv.get(), initialization_vector, block_size);
        } else {
            std::memset(iv.get(), 0, block_size);
        }
    } else {
        iv.reset(); // для ECB IV не нужно
    }
}

void SymmetricCipherContext::processAdditionalParams(const std::vector<std::any>& params) {
    for (const auto& param : params) {
        if (param.type() == typeid(int)) {
            int val = std::any_cast<int>(param);
            if (val > 0) user_threads = static_cast<size_t>(val);
        } else if (param.type() == typeid(size_t)) {
            size_t val = std::any_cast<size_t>(param);
            if (val > 0) user_threads = val;
        }
    }
}

size_t SymmetricCipherContext::get_user_threads(){
    return user_threads;
}

// Основные методы (буферные версии)
void SymmetricCipherContext::encrypt(const uint8_t* input, size_t in_len, uint8_t* output, size_t& out_len) {
    // рабочий буфер: копируем вход ровно один раз
    uint8_t* buf = nullptr;
    if (in_len > 0) {
        buf = new uint8_t[in_len];
        std::memcpy(buf, input, in_len);
    }

    size_t len = in_len;
    processData(buf, len, true);

    // ВНИМАНИЕ: вызывающий должен выделить output >= in_len + block_size
    if (len > 0) {
        std::memcpy(output, buf, len);
    }
    out_len = len;

    delete[] buf;
}

void SymmetricCipherContext::decrypt(const uint8_t* input, size_t in_len, uint8_t* output, size_t& out_len) {
    uint8_t* buf = nullptr;
    if (in_len > 0) {
        buf = new uint8_t[in_len];
        std::memcpy(buf, input, in_len);
    }

    size_t len = in_len;
    processData(buf, len, false);

    if (len > 0) {
        std::memcpy(output, buf, len);
    }
    out_len = len;

    delete[] buf;
}

// Файловые версии
void SymmetricCipherContext::encrypt(const std::string& input_file, const std::string& output_file, size_t& out_len) {
    std::ifstream in_file(input_file, std::ios::binary | std::ios::ate);
    if (!in_file) throw std::runtime_error("Cannot open input file: " + input_file);

    size_t file_size = static_cast<size_t>(in_file.tellg());
    in_file.seekg(0, std::ios::beg);

    uint8_t* data = nullptr;
    if (file_size > 0) {
        data = new uint8_t[file_size];
        in_file.read(reinterpret_cast<char*>(data), file_size);
        if (!in_file) {
            delete[] data;
            throw std::runtime_error("Failed to read input file: " + input_file);
        }
    }
    in_file.close();

    size_t length = file_size;
    processData(data, length, true);

    std::ofstream out_file(output_file, std::ios::binary);
    if (!out_file) {
        delete[] data;
        throw std::runtime_error("Cannot open output file: " + output_file);
    }
    if (length > 0 && data) {
        out_file.write(reinterpret_cast<const char*>(data), length);
        if (!out_file) {
            delete[] data;
            throw std::runtime_error("Failed to write output file: " + output_file);
        }
    }
    out_file.close();

    out_len = length;
    delete[] data;
}

void SymmetricCipherContext::decrypt(const std::string& input_file, const std::string& output_file, size_t& out_len) {
    std::ifstream in_file(input_file, std::ios::binary | std::ios::ate);
    if (!in_file) throw std::runtime_error("Cannot open input file: " + input_file);

    size_t file_size = static_cast<size_t>(in_file.tellg());
    in_file.seekg(0, std::ios::beg);

    uint8_t* data = nullptr;
    if (file_size > 0) {
        data = new uint8_t[file_size];
        in_file.read(reinterpret_cast<char*>(data), file_size);
        if (!in_file) {
            delete[] data;
            throw std::runtime_error("Failed to read input file: " + input_file);
        }
    }
    in_file.close();

    size_t length = file_size;
    processData(data, length, false);

    std::ofstream out_file(output_file, std::ios::binary);
    if (!out_file) {
        delete[] data;
        throw std::runtime_error("Cannot open output file: " + output_file);
    }
    if (length > 0 && data) {
        out_file.write(reinterpret_cast<const char*>(data), length);
        if (!out_file) {
            delete[] data;
            throw std::runtime_error("Failed to write output file: " + output_file);
        }
    }
    out_file.close();

    out_len = length;
    delete[] data;
}

// Асинхронные версии (оставлены как есть в заголовке, при необходимости смени на std::future)
// Внимание: текущая реализация с detach требует, чтобы вызывающий гарантировал время жизни output и out_len.
void SymmetricCipherContext::encryptAsync(const uint8_t* input, size_t in_len, uint8_t* output, size_t& out_len) {
    std::thread([this, input, in_len, output, &out_len]() {
        this->encrypt(input, in_len, output, out_len);
    }).detach();
}

void SymmetricCipherContext::decryptAsync(const uint8_t* input, size_t in_len, uint8_t* output, size_t& out_len) {
    std::thread([this, input, in_len, output, &out_len]() {
        this->decrypt(input, in_len, output, out_len);
    }).detach();
}

void SymmetricCipherContext::encryptAsync(const std::string& input_file, const std::string& output_file, size_t& out_len) {
    std::thread([this, input_file, output_file, &out_len]() {
        this->encrypt(input_file, output_file, out_len);
    }).detach();
}

void SymmetricCipherContext::decryptAsync(const std::string& input_file, const std::string& output_file, size_t& out_len) {
    std::thread([this, input_file, output_file, &out_len]() {
        this->decrypt(input_file, output_file, out_len);
    }).detach();
}