#pragma once
#include <cstddef>
#include <cstdint>
#include "Interfaces/ISymmetricCipher.h"

class ICipherMode {
public:
    virtual ~ICipherMode() = default;

    virtual void processBlocks(uint8_t* data, size_t& length,
                               ISymmetricCipher* cipher,
                               const uint8_t* /*iv*/,
                               bool encrypt) = 0;

    virtual bool canParallelize() const = 0;
    virtual bool requiresIV() const = 0;
};
