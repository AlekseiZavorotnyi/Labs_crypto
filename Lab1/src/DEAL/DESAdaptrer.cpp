#include "DEAL/DESAdaptrer.h"


void DESAdapter::encrypt(const uint8_t* data, const uint8_t* key, uint8_t* output) {
    des_impl.setupKeys(key, 8);
    des_impl.encrypt(data, output);
}

void DESAdapter::decrypt(const uint8_t* data, const uint8_t* key, uint8_t* output) {
    des_impl.setupKeys(key, 8);
    des_impl.decrypt(data, output);
}