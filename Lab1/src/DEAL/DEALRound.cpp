#include "DEAL/DEALRound.h"

DEALRound::DEALRound(ByteOrder order) : byte_order(order) {}

void DEALRound::modifyKey(const uint8_t* originalKey, uint8_t modifier, uint8_t* modifiedKey) {
    for (size_t i = 0; i < 8; i++) {
        modifiedKey[i] = originalKey[i] ^ modifier;
    }
}

void DEALRound::encryptRound(const uint8_t* inputBlock, const uint8_t* roundKey, uint8_t* output) {
    uint8_t temp1[8], temp2[8];
    uint8_t modifiedKey1[8], modifiedKey2[8];

    // Создаем модифицированные ключи
    modifyKey(roundKey, 0x0F, modifiedKey1);
    modifyKey(roundKey, 0xF0, modifiedKey2);

    // 3DES-like структура: E-D-E
    des_adapter_.encrypt(inputBlock, roundKey, temp1);
    des_adapter_.decrypt(temp1, modifiedKey1, temp2);
    des_adapter_.encrypt(temp2, modifiedKey2, output);
}