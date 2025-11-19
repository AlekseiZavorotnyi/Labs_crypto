#include <algorithm>
#include <memory>
#include "Interfaces.h"
#include <vector>
#include "Feistel_network.cpp"


class Zeros: public ICipheringMode{
private:
    std::unique_ptr<ISymmetricCipher> alg;
    size_t block_size;
public:
    ECB(std::unique_ptr<ISymmetricCipher> alg_ptr, size_t block_size)
            : alg(std::move(alg_ptr)), block_size(block_size) {}

};