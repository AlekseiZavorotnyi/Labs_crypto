#pragma once
#include <cstdint>
#include <stdexcept>
#include <memory>
#include <algorithm>
#include <cstdlib>

class IPadding {
public:
    virtual ~IPadding() = default;

    virtual void apply(uint8_t*& data, size_t& length, size_t block_size) = 0;

    virtual void remove(uint8_t* data, size_t& length, size_t block_size) = 0;
};