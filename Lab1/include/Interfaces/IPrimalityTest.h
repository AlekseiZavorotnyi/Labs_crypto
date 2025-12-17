#ifndef LABS_CRYPTO_IPRIMALITYTEST_H
#define LABS_CRYPTO_IPRIMALITYTEST_H
#include <gmpxx.h>

class IPrimalityTest {
public:
    virtual bool isPrime(const mpz_class& n, double p_min) = 0;
    virtual ~IPrimalityTest() = default;
};

#endif //LABS_CRYPTO_IPRIMALITYTEST_H
