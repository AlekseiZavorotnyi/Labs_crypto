#ifndef LABS_CRYPTO_SERVICE_H
#define LABS_CRYPTO_SERVICE_H
#include <cstdint>
#include <stdexcept>
#include <gmp.h>
#include <gmpxx.h>

class Service {
public:
    static mpz_class Legengre_val(const mpz_class& a, const mpz_class& p);

    static mpz_class Jacobi_val(mpz_class a, const mpz_class& n);

    static mpz_class gcd(mpz_class a, mpz_class b);

    static mpz_class egcd(const mpz_class& a, mpz_class b, mpz_class &x, mpz_class &y);

    static mpz_class powmod(const mpz_class& a, mpz_class b, const mpz_class& mod);

    static mpz_class pow(const mpz_class& a, mpz_class b);

    static mpz_class root4(mpz_class n);

    static bool is_odd(const mpz_class& a);

    static mpz_class random_in_range(const mpz_class& min, const mpz_class& max);

    static mpz_class random_with_len(size_t bit_len);
};
#endif //LABS_CRYPTO_SERVICE_H