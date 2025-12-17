#include <utility>
#include <vector>
#include <iostream>

#include "../../include/RSA/WienerAttack.h"

void WienerAttack::decompose_to_chained_fraction(mpz_class a, mpz_class b) {
    chained_frac.clear();
    while (b != 1) {
        mpz_class complete = a / b;
        chained_frac.push_back(complete);
        mpz_class left = a % b;
        a = b;
        b = left;
    }
    chained_frac_size = chained_frac.size();
}

WienerAttack::frac WienerAttack::get_frac_part(size_t i) const {
    if (i >= chained_frac.size()) {
        throw std::out_of_range("Can not create part of chained frac. Index out of range.");
    }
    WienerAttack::frac frac{};

    mpz_class num = chained_frac[i];
    mpz_class den = 1;

    for (int j = static_cast<int>(i) - 1; j >= 0; --j) {
        std::swap(num, den);
        num = chained_frac[j] * den + num;
    }

    frac.a = num;
    frac.b = den;
    return frac;
}

WienerAttack::WienerAttack(mpz_class N, mpz_class e) : N(std::move(N)), e(std::move(e)) {
    chained_frac_size = 0;
    chained_frac = {};
}

mpz_class WienerAttack::crack_key() {
    decompose_to_chained_fraction(e, N);
    for (size_t i = 1; i < chained_frac_size; ++i) {
        frac KiDi = get_frac_part(i);
        mpz_class ki = KiDi.a, di = KiDi.b;
        if (((e * di - 1) % ki) != 0) {
            continue;
        }

        mpz_class phi = (e * di - 1) / ki;
        mpz_class p_and_q = N - (e * di - 1) / ki + 1;
        mpz_class discriminant = p_and_q * p_and_q - 4 * N;
        if (discriminant < 0) {
            continue;
        }
        mpz_class sqrt_discriminant;
        mpz_sqrt(sqrt_discriminant.get_mpz_t(), discriminant.get_mpz_t());
        if (sqrt_discriminant * sqrt_discriminant != discriminant) {
            continue;
        }

        mpz_class p, q;
        if ((p_and_q + sqrt_discriminant) % 2 != 0) {
            continue;
        }
        p = (p_and_q + sqrt_discriminant) / 2;
        if ((p_and_q - sqrt_discriminant) % 2 != 0) {
            continue;
        }
        q = (p_and_q - sqrt_discriminant) / 2;

        if (p * q == N) {
            return di;
        }
    }
    return -1;
}
