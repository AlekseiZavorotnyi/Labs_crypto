#include "SymmetricCipherContext.h"
#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>

void test1(SymmetricCipherContext& ctx){
    size_t out_len = 0;
    ctx.encrypt("./img.png", "./img1.png", out_len);
    std::cout << "Encrypted length: " << out_len << "\n";

    size_t dec_len = 0;
    ctx.decrypt("./img1.png", "./img2.png", dec_len);
    std::cout << "Decrypted length: " << dec_len << "\n";
}

void test2(SymmetricCipherContext& ctx){
    const char* text = "Hello world!!!";
    size_t in_len = strlen(text);
    uint8_t plain[64];
    memcpy(plain, text, in_len);
    uint8_t encrypted[128];
    uint8_t decrypted[128];
    size_t out_len_text = 0;
    std::cout << "Encrypted length: " << in_len << "\n";
    ctx.encrypt(plain, in_len, encrypted, out_len_text);
    std::cout << "Encrypted length: " << out_len_text << "\n";
    size_t dec_len_text = 0;
    ctx.decrypt(encrypted, out_len_text, decrypted, dec_len_text);
    std::cout << "Decrypted length: " << dec_len_text << "\n";

    std::string recovered(reinterpret_cast<char*>(decrypted), dec_len_text);
    std::cout << "Recovered: " << recovered << "\n";
}

SymmetricCipherContext create_cipher(){
    uint8_t key_DEAL[16] = {10, 23, 54, 3, 124, 43, 76, 255, 10, 23, 54, 3, 124, 43, 76, 255};
    const uint8_t iv_DEAL[16] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};

    uint8_t key_DEAL_3DES_24[24] = {10, 23, 54, 3, 124, 43, 76, 255, 10, 23, 54, 3, 124, 43, 76, 255, 10, 23, 54, 3, 124, 43, 76, 255};
    const uint8_t iv_DEAL_3DES_24[24] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};

    uint8_t key_DES[8] = {10, 23, 54, 3, 124, 43, 76, 255};
    const uint8_t iv_DES[8] = {1, 2, 3, 4, 5, 6, 7, 8};


    SymmetricCipherContext ctx_DES(
            CipherAlgorithm::DES,
            CipherMode::CBC,
            PaddingMode::PKCS7,
            8, key_DES, 8, iv_DES, 8, std::vector<std::any> {std::any(7)}
    );

    SymmetricCipherContext ctx_DEAL(
            CipherAlgorithm::DEAL,
            CipherMode::CBC,
            PaddingMode::PKCS7,
            16, key_DEAL, 16, iv_DEAL, 16
    );

    SymmetricCipherContext ctx_DEAL_24(
            CipherAlgorithm::DEAL,
            CipherMode::CBC,
            PaddingMode::PKCS7,
            24, key_DEAL_3DES_24, 24, iv_DEAL_3DES_24, 24
    );

    SymmetricCipherContext ctx_3DES(
            CipherAlgorithm::TripleDES,
            CipherMode::CBC,
            PaddingMode::PKCS7,
            8, key_DEAL_3DES_24, 24, iv_DES, 8
    );
    return ctx_3DES;
}

int main(){
    auto TrDES = create_cipher();
    test1(TrDES);
    return 0;
}