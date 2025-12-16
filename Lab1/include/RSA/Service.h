#ifndef LABS_CRYPTO_SERVICE_H
#define LABS_CRYPTO_SERVICE_H
#include <cstdint>
#include <stdexcept>
#include <gmp.h>


using big = mpz_t;
using ubig = unsigned long long;

class Server {
public:
    big gcd(big a, big b);
    big extended_gcd(big a, big b, big &x, big &y);
    big mod_pow(big a, big e, big m);
    big legendre_symbol(big a, big p);
    big jacobi_symbol(big a, big n);
private:
    big mul_mod(big a, big b, big m);
    big norm_mod(big a, big m);
};
#endif //LABS_CRYPTO_SERVICE_H
