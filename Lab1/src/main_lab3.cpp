#include <iostream>

#include "../include/AES/GF_Service.h"
#include "../include/AES/AES.h"

int main() {
    uint8_t key128[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t message[] = "Hello world! Ita";
    uint8_t ciphertext[16] = { 0 };
    uint8_t plain[16] = { 0 };

    AES aes(16, 16, key128);
    aes.encrypt(message, ciphertext);
    aes.decrypt(ciphertext, plain);
    std::cout << "Ciphertext: ";
    for (int i = 0; i < 16; ++i)
        printf("%02x ", ciphertext[i]);
    std::cout << std::endl << "Plaintext: ";
    for (int i = 0; i < 16; ++i)
        printf("%c", plain[i]);
    std::cout << std::endl;
}