#include <vector>
#include <memory>
#include <thread>
#include <mutex>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <condition_variable>
#include <queue>
#include <functional>
#include "Interfaces.h"
#include "Feistel_network.cpp"

// Перечисления для режимов
enum class CipherMode {
    ECB, CBC, PCBC, CFB, OFB, CTR, RANDOM_DELTA
};

enum class PaddingMode {
    ZEROS, ANSI_X923, PKCS7, ISO_10126
};

enum class CipherAlgorithm {
    DES, DEAL
};

class SymmetricCipherContext {
private:
    std::unique_ptr<ISymmetricCipher> cipher;
    CipherMode cipher_mode;
    PaddingMode padding_mode;
    std::vector<uint8_t> iv;
    ByteOrder byte_order;
    size_t key_size;

public:
    // Конструктор
    SymmetricCipherContext(
            CipherAlgorithm algorithm,
            CipherMode c_mode,
            PaddingMode p_mode,
            const std::vector<uint8_t>& key,
            const std::vector<uint8_t>& initialization_vector = {},
            ByteOrder order = ByteOrder::BIG_ENDIAN,
            size_t k_size = 16,
            const std::vector<std::string>& additional_params = {}
    ) : cipher_mode(c_mode), padding_mode(p_mode), byte_order(order), key_size(k_size) {

        // Создаем соответствующий алгоритм
        switch (algorithm) {
            case CipherAlgorithm::DES:
                cipher = std::make_unique<DES>(byte_order);
                key_size = 8;
                break;
            case CipherAlgorithm::DEAL:
                cipher = std::make_unique<DEAL>(key_size, byte_order);
                break;
            default:
                throw std::invalid_argument("Unsupported cipher algorithm");
        }

        // Проверяем и устанавливаем ключ
        if (key.size() != cipher->keySize()) {
            throw std::invalid_argument("Key size doesn't match algorithm requirements");
        }
        cipher->setupKeys(key.data(), key.size());

        // Устанавливаем IV
        if (!initialization_vector.empty()) {
            iv = initialization_vector;
            if (iv.size() != cipher->blockSize()) {
                throw std::invalid_argument("IV size doesn't match block size");
            }
        } else if (requiresIV()) {
            iv.resize(cipher->blockSize());
            std::fill(iv.begin(), iv.end(), 0);
        }
        processAdditionalParams(additional_params);
    }

    // Асинхронное шифрование данных в памяти
    void encryptAsync(const std::vector<uint8_t>& data,
                      const std::function<void(std::vector<uint8_t>)>& callback) {
        std::thread([this, data, callback]() {
            auto result = this->encryptData(data);
            callback(result);
        }).detach();
    }

    // Асинхронное дешифрование данных в памяти
    void decryptAsync(const std::vector<uint8_t>& data,
                      const std::function<void(std::vector<uint8_t>)>& callback) {
        std::thread([this, data, callback]() {
            auto result = this->decryptData(data);
            callback(result);
        }).detach();
    }

    // Асинхронное шифрование файла
    void encryptFileAsync(const std::string& input_file,
                          const std::string& output_file,
                          const std::function<void(bool)>& callback = nullptr) {
        std::thread([this, input_file, output_file, callback]() {
            bool success = false;
            try {
                this->processFile(input_file, output_file, true);
                success = true;
            } catch (...) {
                success = false;
            }
            if (callback) callback(success);
        }).detach();
    }

    // Асинхронное дешифрование файла
    void decryptFileAsync(const std::string& input_file,
                          const std::string& output_file,
                          const std::function<void(bool)>& callback = nullptr) {
        std::thread([this, input_file, output_file, callback]() {
            bool success = false;
            try {
                this->processFile(input_file, output_file, false);
                success = true;
            } catch (...) {
                success = false;
            }
            if (callback) callback(success);
        }).detach();
    }

    // Параллельное шифрование с использованием std::thread для блоков
    std::vector<uint8_t> encryptParallel(const std::vector<uint8_t>& data) {
        auto padded_data = applyPadding(data);
        return processBlocksParallel(padded_data, true);
    }

    // Параллельное дешифрование с использованием std::thread для блоков
    std::vector<uint8_t> decryptParallel(const std::vector<uint8_t>& data) {
        auto decrypted_data = processBlocksParallel(data, false);
        return removePadding(decrypted_data);
    }

    // Синхронные методы
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) {
        return encryptData(data);
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data) {
        return decryptData(data);
    }

    void encryptFile(const std::string& input_file, const std::string& output_file) {
        processFile(input_file, output_file, true);
    }

    void decryptFile(const std::string& input_file, const std::string& output_file) {
        processFile(input_file, output_file, false);
    }

    // Геттеры
    CipherMode getCipherMode() const { return cipher_mode; }
    PaddingMode getPaddingMode() const { return padding_mode; }
    size_t getBlockSize() const { return cipher->blockSize(); }
    size_t getKeySize() const { return cipher->keySize(); }

private:
    // Основные методы обработки данных
    std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data) {
        auto padded_data = applyPadding(data);
        return processBlocks(padded_data, true);
    }

    std::vector<uint8_t> decryptData(const std::vector<uint8_t>& data) {
        auto decrypted_data = processBlocks(data, false);
        return removePadding(decrypted_data);
    }

    void processFile(const std::string& input_file, const std::string& output_file, bool encrypt) {
        std::ifstream in_file(input_file, std::ios::binary);
        std::ofstream out_file(output_file, std::ios::binary);

        if (!in_file || !out_file) {
            throw std::runtime_error("Cannot open files");
        }

        std::vector<uint8_t> input_data((std::istreambuf_iterator<char>(in_file)),std::istreambuf_iterator<char>());

        std::vector<uint8_t> output_data;
        if (encrypt) {
            output_data = encryptData(input_data);
        } else {
            output_data = decryptData(input_data);
        }

        out_file.write(reinterpret_cast<const char*>(output_data.data()), output_data.size());
    }

    // Параллельная обработка блоков с прямым созданием потоков
    std::vector<uint8_t> processBlocksParallel(const std::vector<uint8_t>& data, bool encrypt) {
        if (!canParallelize()) {
            return processBlocks(data, encrypt);
        }

        size_t block_size = cipher->blockSize();
        size_t num_blocks = data.size() / block_size;
        size_t possible_threads = std::thread::hardware_concurrency();
        std::vector<uint8_t> result(data.size());

        // Определяем количество потоков
        size_t num_threads = std::min(possible_threads, num_blocks);
        if (num_threads == 0) num_threads = 1;

        std::vector<std::thread> threads;
        std::vector<std::exception_ptr> exceptions(num_threads, nullptr);

        // Распределяем блоки по потокам
        size_t blocks_per_thread = (num_blocks + num_threads - 1) / num_threads;

        for (size_t t = 0; t < num_threads; t++) {
            threads.emplace_back([&, t, encrypt]() {
                try {
                    size_t start_block = t * blocks_per_thread;
                    size_t end_block = std::min((t + 1) * blocks_per_thread, num_blocks);

                    for (size_t i = start_block; i < end_block; i++) {
                        processSingleBlock(data.data() + i * block_size,
                                           result.data() + i * block_size,
                                           i, encrypt);
                    }
                } catch (...) {
                    exceptions[t] = std::current_exception();
                }
            });
        }

        // Ждем завершения всех потоков
        for (auto& thread : threads) {
            thread.join();
        }

        // Проверяем исключения
        for (const auto& ex : exceptions) {
            if (ex) {
                std::rethrow_exception(ex);
            }
        }

        return result;
    }

    // Последовательная обработка блоков
    std::vector<uint8_t> processBlocks(const std::vector<uint8_t>& data, bool encrypt) {
        size_t block_size = cipher->blockSize();
        size_t num_blocks = data.size() / block_size;
        std::vector<uint8_t> result(data.size());

        for (size_t i = 0; i < num_blocks; i++) {
            processSingleBlock(data.data() + i * block_size,
                               result.data() + i * block_size,
                               i, encrypt);
        }

        return result;
    }

    void processSingleBlock(const uint8_t* input, uint8_t* output, size_t block_index, bool encrypt) {
        switch (cipher_mode) {
            case CipherMode::ECB:
                processECB(input, output, encrypt);
                break;
            case CipherMode::CBC:
                processCBC(input, output, block_index, encrypt);
                break;
            case CipherMode::PCBC:
                processPCBC(input, output, block_index, encrypt);
                break;
            case CipherMode::CFB:
                processCFB(input, output, block_index, encrypt);
                break;
            case CipherMode::OFB:
                processOFB(input, output, block_index);
                break;
            case CipherMode::CTR:
                processCTR(input, output, block_index);
                break;
            case CipherMode::RANDOM_DELTA:
                processRandomDelta(input, output, block_index, encrypt);
                break;
        }
    }

    // Реализации различных режимов шифрования
    void processECB(const uint8_t* input, uint8_t* output, bool encrypt) {
        if (encrypt) {
            cipher->encrypt(input, output);
        } else {
            cipher->decrypt(input, output);
        }
    }

    void processCBC(const uint8_t* input, uint8_t* output, size_t block_index, bool encrypt) {
        thread_local std::vector<uint8_t> prev_block = iv;

        if (encrypt) {
            std::vector<uint8_t> xored(cipher->blockSize());
            for (size_t i = 0; i < cipher->blockSize(); i++) {
                xored[i] = input[i] ^ prev_block[i];
            }
            cipher->encrypt(xored.data(), output);
            prev_block.assign(output, output + cipher->blockSize());
        } else {
            std::vector<uint8_t> decrypted(cipher->blockSize());
            cipher->decrypt(input, decrypted.data());
            for (size_t i = 0; i < cipher->blockSize(); i++) {
                output[i] = decrypted[i] ^ prev_block[i];
            }
            prev_block.assign(input, input + cipher->blockSize());
        }
    }

    void processCFB(const uint8_t* input, uint8_t* output, size_t block_index, bool encrypt) {
        thread_local std::vector<uint8_t> shift_register = iv;
        std::vector<uint8_t> encrypted(cipher->blockSize());

        cipher->encrypt(shift_register.data(), encrypted.data());

        if (encrypt) {
            for (size_t i = 0; i < cipher->blockSize(); i++) {
                output[i] = input[i] ^ encrypted[i];
            }
            shift_register.assign(output, output + cipher->blockSize());
        } else {
            for (size_t i = 0; i < cipher->blockSize(); i++) {
                output[i] = input[i] ^ encrypted[i];
            }
            shift_register.assign(input, input + cipher->blockSize());
        }
    }

    void processOFB(const uint8_t* input, uint8_t* output, size_t block_index) {
        thread_local std::vector<uint8_t> key_stream = iv;
        std::vector<uint8_t> new_key_stream(cipher->blockSize());

        cipher->encrypt(key_stream.data(), new_key_stream.data());

        for (size_t i = 0; i < cipher->blockSize(); i++) {
            output[i] = input[i] ^ new_key_stream[i];
        }

        key_stream = std::move(new_key_stream);
    }

    void processCTR(const uint8_t* input, uint8_t* output, size_t block_index) {
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

        std::vector<uint8_t> key_stream(cipher->blockSize());
        cipher->encrypt(counter.data(), key_stream.data());

        for (size_t i = 0; i < cipher->blockSize(); i++) {
            output[i] = input[i] ^ key_stream[i];
        }
    }

    void processPCBC(const uint8_t* input, uint8_t* output, size_t block_index, bool encrypt) {
        thread_local std::vector<uint8_t> prev_input = iv;
        thread_local std::vector<uint8_t> prev_output = iv;

        if (encrypt) {
            std::vector<uint8_t> xored(cipher->blockSize());
            for (size_t i = 0; i < cipher->blockSize(); i++) {
                xored[i] = input[i] ^ prev_input[i] ^ prev_output[i];
            }
            cipher->encrypt(xored.data(), output);
            prev_input.assign(input, input + cipher->blockSize());
            prev_output.assign(output, output + cipher->blockSize());
        } else {
            std::vector<uint8_t> decrypted(cipher->blockSize());
            cipher->decrypt(input, decrypted.data());
            for (size_t i = 0; i < cipher->blockSize(); i++) {
                output[i] = decrypted[i] ^ prev_input[i] ^ prev_output[i];
            }
            prev_input.assign(output, output + cipher->blockSize());
            prev_output.assign(input, input + cipher->blockSize());
        }
    }

    void processRandomDelta(const uint8_t* input, uint8_t* output, size_t block_index, bool encrypt) {
        std::vector<uint8_t> delta(cipher->blockSize());
        std::fill(delta.begin(), delta.end(), block_index & 0xFF);

        if (encrypt) {
            std::vector<uint8_t> xored(cipher->blockSize());
            for (size_t i = 0; i < cipher->blockSize(); i++) {
                xored[i] = input[i] ^ delta[i];
            }
            cipher->encrypt(xored.data(), output);
        } else {
            std::vector<uint8_t> decrypted(cipher->blockSize());
            cipher->decrypt(input, decrypted.data());
            for (size_t i = 0; i < cipher->blockSize(); i++) {
                output[i] = decrypted[i] ^ delta[i];
            }
        }
    }

    // Реализации режимов набивки
    std::vector<uint8_t> applyPadding(const std::vector<uint8_t>& data) {
        size_t block_size = cipher->blockSize();
        size_t padding_size = block_size - (data.size() % block_size);
        if (padding_size == block_size) padding_size = 0;

        std::vector<uint8_t> padded_data = data;

        switch (padding_mode) {
            case PaddingMode::ZEROS:
                if (padding_size > 0) {
                    padded_data.resize(data.size() + padding_size, 0x00);
                }
                break;

            case PaddingMode::ANSI_X923:
                padded_data.resize(data.size() + padding_size, 0x00);
                if (padding_size > 0) {
                    padded_data.back() = static_cast<uint8_t>(padding_size);
                }
                break;

            case PaddingMode::PKCS7:
                if (padding_size > 0) {
                    padded_data.resize(data.size() + padding_size, static_cast<uint8_t>(padding_size));
                }
                break;

            case PaddingMode::ISO_10126:
                padded_data.resize(data.size() + padding_size);
                if (padding_size > 0) {
                    // В реальной реализации здесь должны быть случайные байты
                    std::fill(padded_data.end() - padding_size, padded_data.end() - 1, 0x00);
                    padded_data.back() = static_cast<uint8_t>(padding_size);
                }
                break;
        }

        return padded_data;
    }

    std::vector<uint8_t> removePadding(const std::vector<uint8_t>& data) {
        if (data.empty()) return data;

        size_t padding_size = 0;

        switch (padding_mode) {
            case PaddingMode::ZEROS:
                for (auto it = data.rbegin(); it != data.rend(); ++it) {
                    if (*it != 0) {
                        padding_size = std::distance(data.rbegin(), it);
                        break;
                    }
                }
                break;

            case PaddingMode::ANSI_X923:
            case PaddingMode::PKCS7:
            case PaddingMode::ISO_10126:
                padding_size = data.back();
                if (padding_size == 0 || padding_size > cipher->blockSize() || padding_size > data.size()) {
                    throw std::runtime_error("Invalid padding");
                }
                break;
        }

        if (padding_size > data.size()) {
            throw std::runtime_error("Invalid padding size");
        }

        return std::vector<uint8_t>(data.begin(), data.end() - padding_size);
    }

    // Вспомогательные методы
    bool requiresIV() const {
        return cipher_mode != CipherMode::ECB;
    }

    bool canParallelize() const {
        return cipher_mode == CipherMode::ECB || cipher_mode == CipherMode::CTR;
    }

    void processAdditionalParams(const std::vector<std::string>& params) {
        for (const auto& param : params) {
            // Обработка дополнительных параметров
        }
    }

};