#include "./IPadding.h"

class ISO10126Padding : public IPadding {
public:
    void apply(uint8_t*& data, size_t& length, size_t block_size) override;
    void remove(uint8_t* data, size_t& length, size_t block_size) override;
};