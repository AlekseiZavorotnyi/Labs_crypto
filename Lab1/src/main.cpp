#include "SymmetricCipherContext.h"
#include <iostream>
#include <string>
#include <cstring>

int main() {
    uint8_t key[8] = {10, 23, 54, 3, 124, 43, 76, 255};
    const uint8_t iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    const char* text = "Hello world!!!";
    size_t in_len = strlen(text);
    uint8_t plain[64];
    memcpy(plain, text, in_len);

    //uint8_t encrypted[128];
    //uint8_t decrypted[128];
    size_t out_len = 0; // переменная для длины

    SymmetricCipherContext ctx(
            CipherAlgorithm::DES,
            CipherMode::CFB,
            PaddingMode::PKCS7,
            key, 8, iv, 8
    );
    /*std::cout << "Encrypted length: " << in_len << "\n";
    ctx.encrypt(plain, in_len, encrypted, out_len);
    std::cout << "Encrypted length: " << out_len << "\n";
    size_t dec_len = 0;
    ctx.decrypt(encrypted, out_len, decrypted, dec_len);
    std::cout << "Decrypted length: " << dec_len << "\n";*/
    // Шифрование
    ctx.encrypt("./img.png", "./img1.png", out_len);
    std::cout << "Encrypted length: " << out_len << "\n";

    // Дешифрование
    size_t dec_len = 0;
    ctx.decrypt("./img1.png", "./img2.png", dec_len);
    std::cout << "Decrypted length: " << dec_len << "\n";

    //std::string recovered(reinterpret_cast<char*>(decrypted), dec_len);
    //std::cout << "Recovered: " << recovered << "\n";

    return 0;
}