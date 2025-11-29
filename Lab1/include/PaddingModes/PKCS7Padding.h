#include "./IPadding.h"

class PKCS7Padding : public IPadding {
public:
    void apply(uint8_t*& data, size_t& length, size_t block_size) override;
    void remove(uint8_t* data, size_t& length, size_t block_size) override;
};

