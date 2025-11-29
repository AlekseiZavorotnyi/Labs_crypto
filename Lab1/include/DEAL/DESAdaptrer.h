#ifndef LABS_CRYPTO_DESADAPTRER_H
#define LABS_CRYPTO_DESADAPTRER_H
#include "./DES/DES.h"

class DESAdapter {
private:
    DES des_impl;

public:
    void encrypt(const uint8_t* data, const uint8_t* key, uint8_t* output);
    void decrypt(const uint8_t* data, const uint8_t* key, uint8_t* output);
};
#endif //LABS_CRYPTO_DESADAPTRER_H
