// SymmetricCipherContext.h
#include <vector>
#include <memory>
#include <thread>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <functional>
#include "Interfaces.h"
#include "Feistel_network.h"
#include "Encryption_Modes.h"
#include "Padding_Modes.h"
#include <variant>

enum class CipherMode {
    ECB, CBC, PCBC, CFB, OFB, CTR, RANDOM_DELTA
};

enum class PaddingMode {
    ZEROS, ANSI_X923, PKCS7, ISO_10126
};

enum class CipherAlgorithm {
    DES, DEAL
};

#include <variant>


// Для дополнительных параметров
using AdditionalParam = std::variant<int, std::string, std::vector<uint8_t>>;

class SymmetricCipherContext {
private:
    std::unique_ptr<ISymmetricCipher> cipher;
    std::unique_ptr<ICipherMode> mode;
    std::unique_ptr<IPadding> padding;
    std::vector<uint8_t> iv;
    ByteOrder byte_order;
    size_t key_size;

    // Внутренняя фабрика режимов
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

    bool requiresIV(CipherMode mode) const {
        return mode != CipherMode::ECB;
    }

    std::unique_ptr<IPadding> createPadding(PaddingMode padding_mode) {
        switch (padding_mode) {
            case PaddingMode::ZEROS: return std::make_unique<ZerosPadding>();
            case PaddingMode::ANSI_X923: return std::make_unique<ANSIX923Padding>();
            case PaddingMode::PKCS7: return std::make_unique<PKCS7Padding>();
            case PaddingMode::ISO_10126: return std::make_unique<ISO10126Padding>();
            default: throw std::invalid_argument("Unsupported padding mode");
        }
    }

    void processAdditionalParams(const std::vector<AdditionalParam>& params) {
        // Обработка дополнительных параметров
        for (const auto& param : params) {
            // Можно добавить специфичную логику для разных режимов
        }
    }

    void processData(std::vector<uint8_t>& data, bool encrypt) {
        if (encrypt) {
            padding->apply(data, cipher->blockSize());
            mode->processBlocks(data, cipher.get(), iv, true);
        } else {
            mode->processBlocks(data, cipher.get(), iv, false);
            padding->remove(data, cipher->blockSize());
        }
    }

    void processFile(const std::string& input_file, const std::string& output_file, bool encrypt) {
        std::ifstream in_file(input_file, std::ios::binary);
        if (!in_file) {
            throw std::runtime_error("Cannot open input file: " + input_file);
        }

        std::vector<uint8_t> data;
        data.assign(std::istreambuf_iterator<char>(in_file), std::istreambuf_iterator<char>());
        in_file.close();

        processData(data, encrypt);

        std::ofstream out_file(output_file, std::ios::binary);
        if (!out_file) {
            throw std::runtime_error("Cannot open output file: " + output_file);
        }
        out_file.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

public:
    SymmetricCipherContext(
            CipherAlgorithm algorithm,
            CipherMode c_mode,
            PaddingMode p_mode,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& initialization_vector = {},
            const std::vector<AdditionalParam>& additional_params = {}
    ) : byte_order(ByteOrder::BIG_ENDIAN) {

        // Создаем алгоритм
        switch (algorithm) {
            case CipherAlgorithm::DES:
                cipher = std::make_unique<DES>(byte_order);
                key_size = 8;
                break;
            case CipherAlgorithm::DEAL:
                key_size = key.size();
                cipher = std::make_unique<DEAL>(key_size, byte_order);
                break;
            default:
                throw std::invalid_argument("Unsupported cipher algorithm");
        }

        if (key.size() != cipher->keySize()) {
            throw std::invalid_argument("Key size doesn't match algorithm requirements");
        }
        cipher->setupKeys(key.data(), key.size());

        // Создаем режим шифрования
        mode = createCipherMode(c_mode);

        // Создаем паддинг
        padding = createPadding(p_mode);

        // Устанавливаем IV
        if (!initialization_vector.empty()) {
            iv = initialization_vector;
            if (iv.size() != cipher->blockSize()) {
                throw std::invalid_argument("IV size doesn't match block size");
            }
        } else if (requiresIV(c_mode)) {
            iv.resize(cipher->blockSize());
            std::fill(iv.begin(), iv.end(), 0);
        }

        // Обрабатываем дополнительные параметры
        processAdditionalParams(additional_params);
    }

    // Основные методы - ТОЛЬКО ТО, ЧТО В ЗАДАНИИ
    void encrypt(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) {
        output = input; // одно копирование
        processData(output, true);
    }

    void decrypt(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) {
        output = input; // одно копирование
        processData(output, false);
    }

    void encrypt(const std::string& input_file, const std::string& output_file) {
        processFile(input_file, output_file, true);
    }

    void decrypt(const std::string& input_file, const std::string& output_file) {
        processFile(input_file, output_file, false);
    }

    // Асинхронные версии - ТОЛЬКО ТО, ЧТО В ЗАДАНИИ
    void encryptAsync(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) {
        std::thread([this, input, &output]() {
            this->encrypt(input, output);
        }).detach();
    }

    void decryptAsync(const std::vector<uint8_t>& input, std::vector<uint8_t>& output) {
        std::thread([this, input, &output]() {
            this->decrypt(input, output);
        }).detach();
    }

    void encryptAsync(const std::string& input_file, const std::string& output_file) {
        std::thread([this, input_file, output_file]() {
            this->encrypt(input_file, output_file);
        }).detach();
    }

    void decryptAsync(const std::string& input_file, const std::string& output_file) {
        std::thread([this, input_file, output_file]() {
            this->decrypt(input_file, output_file);
        }).detach();
    }
};