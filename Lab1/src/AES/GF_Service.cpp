#include "../../include/AES/GF_Service.h"

#include <stdexcept>
#include <iostream>

uint8_t GF_Service::add(uint8_t a, uint8_t b) {
    return a ^ b;
}

uint8_t GF_Service::mult_mod(uint8_t a, uint8_t b, uint16_t mod) {
    uint16_t res = 0, temp_a = a, temp_b = b;

    for (int i = 0; i < 8; ++i) {
        if (temp_b & 1) {
            res ^= temp_a;
        }
        bool carry = temp_a & 0x80;
        temp_a <<= 1;
        if (carry) {
            temp_a ^= mod;
        }
        temp_b >>= 1;
    }
    return static_cast<uint8_t>(res);
}

int GF_Service::degree(uint32_t n) {
    for (int i = 31; i >= 0; --i) {
        if (n & (1u << i)) {
            return i;
        }
    }
    return -1;
}

uint16_t GF_Service::mod(uint16_t a, uint16_t mod) {
    int deg_mod = GF_Service::degree(mod);

    while (true) {
        int deg_a = GF_Service::degree(a);
        if (deg_a < deg_mod) {
            break;
        }

        a ^= mod << (deg_a - deg_mod);
    }
    return a;
}

uint16_t GF_Service::gcd(uint16_t a, uint16_t b) {
    while (b != 0) {
        uint16_t r = mod(a, b);
        a = b;
        b = r;
    }
    return a;
}

uint16_t GF_Service::square_mod(uint16_t a, uint16_t mod) {
    uint16_t res = 0;
    for (int i = 0; i < 16; ++i) {
        if (a & (1 << i))
            res |= (1 << (2 * i));
    }
    return GF_Service::mod(res, mod);
}

bool GF_Service::is_prime(uint16_t f) {
    int f_deg = degree(f);
    if (f_deg <= 0) {
        return false;
    }

    uint16_t x = 0b10;
    uint16_t power = x;
    for (int k = 1; k <= f_deg / 2; ++k) {
        power = square_mod(power, f);
        uint16_t g = GF_Service::gcd(power ^ x, f);
        if (g != 1) {
            return false;
        }
    }
    return true;
}

uint16_t GF_Service::mul(uint16_t a, uint16_t b) {
    uint16_t res = 0;
    while (b) {
        if (b & 1)
            res ^= a;
        a <<= 1;
        b >>= 1;
    }
    return res;
}

uint8_t GF_Service::inverse_mod(uint16_t a, uint16_t mod) {
    if (a == 0) return 0;

    uint16_t r0 = mod;
    uint16_t r1 = a;
    uint16_t s0 = 0;
    uint16_t s1 = 1;

    while (r1 != 0) {
        int deg0 = degree(r0);
        int deg1 = degree(r1);

        if (deg0 < deg1)
            std::swap(r0, r1), std::swap(s0, s1);

        uint16_t q = 1 << (deg0 - deg1);

        r0 ^= r1 << (deg0 - deg1);
        s0 ^= mul(q, s1);
    }
    if (r0 != 1) throw std::runtime_error("modulus is reducible");
    return static_cast<uint8_t>(s0);
}

std::vector<uint16_t> GF_Service::get_primes() {
    std::vector<uint16_t> primes;
    for (uint16_t f = 0b100000000; f <= 0b111111111; ++f) {
        if (is_prime(f)) {
            primes.push_back(f);
        }
    }
    if (primes.size() != 30) {
        std::cout << "WARNING: primes count != 30" << std::endl;
    }
    return primes;
}

GF_Service::DivResult GF_Service::divide(uint32_t a, uint32_t b) {
    uint32_t q = 0;
    int deg_b = degree(b);

    while (degree(a) >= deg_b) {
        int shift = degree(a) - deg_b;
        q |= (1u << shift);
        a ^= b << shift;
    }
    return {q, a};
}

std::vector<uint32_t> GF_Service::decompose_to_primes(uint32_t f) {
    std::vector<uint32_t> factors;

    if (f == 0 || f == 1) return factors;

    for (uint32_t d = 2; d <= f; ++d) {
        if (!is_prime(d)) continue;

        while (true) {
            auto [q, r] = divide(f, d);
            if (r != 0) break;
            //std::cout << "divide by " << std::hex << d << ", q = " << q << std::endl;

            factors.push_back(d);
            f = q;
        }
    }
    if (f != 1) {
        factors.push_back(f);
    }
    return factors;
}