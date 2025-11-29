#pragma once
#include <cstdint>
#include <stdexcept>
#include <memory>
#include <algorithm>
#include <cstdlib>

class IPadding {
public:
    virtual ~IPadding() = default;

    // apply: принимает указатель на данные и их длину,
    // возвращает новый буфер с паддингом и обновляет длину
    virtual void apply(uint8_t*& data, size_t& length, size_t block_size) = 0;

    // remove: принимает указатель на данные и длину,
    // уменьшает длину (буфер остаётся тем же)
    virtual void remove(uint8_t* data, size_t& length, size_t block_size) = 0;
};