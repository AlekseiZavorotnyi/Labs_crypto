#ifndef LABS_CRYPTO_GF256SERVICE_H
#define LABS_CRYPTO_GF256SERVICE_H

#include <cstdint>
#include <vector>

class GF_Service {
public:
    static uint8_t add(uint8_t a, uint8_t b);

    static uint8_t mult_mod(uint8_t a, uint8_t b, uint16_t mod);

    static int degree(uint32_t n);

    static uint16_t mod(uint16_t a, uint16_t mod);

    static uint16_t gcd(uint16_t, uint16_t);

    static uint16_t square_mod(uint16_t a, uint16_t mod);

    static bool is_prime(uint16_t n);

    static uint16_t mul(uint16_t a, uint16_t b);

    static uint8_t inverse_mod(uint16_t a, uint16_t mod);

    static std::vector<uint16_t> get_primes();

    struct DivResult {
        uint32_t quot;
        uint32_t rem;
    };

    static DivResult divide(uint32_t a, uint32_t b);

    static std::vector<uint32_t> decompose_to_primes(uint32_t n);
};


#endif //LABS_CRYPTO_GF256SERVICE_H
