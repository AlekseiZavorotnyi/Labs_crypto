#include <iostream>

#include "../include/AES/GF_Service.h"
#include "../include/AES/AES.h"
#include "SymmetricCipherContext.h"
#include <vector>

void test128(SymmetricCipherContext& ctx_AES_cur, auto ind){
    size_t out_len = 0;
    ctx_AES_cur.encrypt("./img.png", "./AES128/encrypted/img_" + ind + ".png", out_len);

    size_t dec_len = 0;
    ctx_AES_cur.decrypt("./AES128/encrypted/img_" + ind + ".png", "./AES128/decrypted/img_" + ind + ".png", dec_len);
}

void test192(SymmetricCipherContext& ctx_AES_cur, auto ind){
    size_t out_len = 0;
    ctx_AES_cur.encrypt("./img.png", "./AES192/encrypted/img_" + ind + ".png", out_len);

    size_t dec_len = 0;
    ctx_AES_cur.decrypt("./AES192/encrypted/img_" + ind + ".png", "./AES192/decrypted/img_" + ind + ".png", dec_len);
}

void test256(SymmetricCipherContext& ctx_AES_cur, auto ind){
    size_t out_len = 0;
    ctx_AES_cur.encrypt("./img.png", "./AES256/encrypted/img_" + ind + ".png", out_len);

    size_t dec_len = 0;
    ctx_AES_cur.decrypt("./AES256/encrypted/img_" + ind + ".png", "./AES256/decrypted/img_" + ind + ".png", dec_len);
}

int main() {
    uint8_t key128[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t key192[24] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t key256[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    const uint8_t iv_AES_128[16] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t iv_AES_192[24] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t iv_AES_256[32] = {1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,1, 2, 3, 4, 5, 6, 7, 8,1, 2, 3, 4, 5, 6, 7, 8};

    std::vector<CipherMode> c_modes = {CipherMode::CBC, CipherMode::CFB,CipherMode::CTR,CipherMode::ECB,CipherMode::OFB,CipherMode::PCBC,CipherMode::RANDOM_DELTA};
    std::vector<PaddingMode> p_modes = {PaddingMode::ANSI_X923, PaddingMode::PKCS7, PaddingMode::ZEROS, PaddingMode::ISO_10126};
    std::vector<size_t> sizes = {16, 24, 32};

    int ind = 0;
    for (auto c_mode : c_modes){
        for (auto p_mode : p_modes){
            for (auto size : sizes){
                if (size == 16) {
                    SymmetricCipherContext ctx_AES_cur(
                            CipherAlgorithm::AES,
                            c_mode,
                            p_mode,
                            size, key128, size, iv_AES_128, size
                    );
                    test128(ctx_AES_cur, std::to_string(ind++));
                }
                else if(size == 24){
                    SymmetricCipherContext ctx_AES_cur(
                            CipherAlgorithm::AES,
                            c_mode,
                            p_mode,
                            size, key192, size, iv_AES_192, size
                    );
                    test192(ctx_AES_cur, std::to_string(ind++));
                }
                else{
                    SymmetricCipherContext ctx_AES_cur(
                            CipherAlgorithm::AES,
                            c_mode,
                            p_mode,
                            size, key256, size, iv_AES_256, size
                    );
                    test256(ctx_AES_cur, std::to_string(ind++));
                }

            }
        }
    }
}