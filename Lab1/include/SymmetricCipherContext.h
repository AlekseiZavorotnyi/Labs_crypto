// SymmetricCipherContext.h
#include "ICipherMode.h"
#include "IPadding.h"
#include <memory>
#include <thread>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <functional>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <any>
#include "DES/DES.h"
#include "DEAL/DEAL.h"
#include "AES/AES.h"
#include "TripleDES.h"

enum class CipherMode { ECB, CBC, PCBC, CFB, OFB, CTR, RANDOM_DELTA };
enum class PaddingMode { ZEROS, ANSI_X923, PKCS7, ISO_10126 };
enum class CipherAlgorithm { DES, DEAL, TripleDES, AES };

class SymmetricCipherContext {
private:
    std::unique_ptr<ISymmetricCipher> cipher;
    std::unique_ptr<ICipherMode> mode;
    std::unique_ptr<IPadding> padding;
    std::unique_ptr<uint8_t[]> iv;
    ByteOrder byte_order;
    size_t key_size;
    size_t block_size;
    size_t user_threads = 0;

    std::unique_ptr<ICipherMode> createCipherMode(CipherMode mode);
    bool requiresIV(CipherMode mode) const;
    std::unique_ptr<IPadding> createPadding(PaddingMode padding_mode);
    void processData(uint8_t*& data, size_t& length, bool encrypt);
    void processAdditionalParams(const std::vector<std::any>& params);

public:
    SymmetricCipherContext(
            CipherAlgorithm algorithm,
            CipherMode c_mode,
            PaddingMode p_mode,
            size_t block_size,
            const uint8_t* key,
            size_t key_len,
            const uint8_t* initialization_vector = nullptr,
            size_t iv_len = 0,
            const std::vector<std::any>& additionalParams = {}
    );

    // Основные методы
    void encrypt(const uint8_t* input, size_t in_len, uint8_t* output, size_t& out_len);
    void decrypt(const uint8_t* input, size_t in_len, uint8_t* output, size_t& out_len);

    void encrypt(const std::string& input_file, const std::string& output_file, size_t& out_len);
    void decrypt(const std::string& input_file, const std::string& output_file, size_t& out_len);
};