#ifndef LABS_CRYPTO_PRIMETEST_H
#define LABS_CRYPTO_PRIMETEST_H
#include <gmpxx.h>

#include "../Interfaces/IPrimalityTest.h"

class PrimeTest : IPrimalityTest {
private:
    [[nodiscard]] int calculate_iter_cnt(double p_min) const;

protected:
    virtual bool test_iteration(const mpz_class &n) = 0;

    [[nodiscard]] virtual double one_iter_fail_probability() const = 0;

public:
    bool isPrime(const mpz_class &n, double p_min) final;
    virtual ~PrimeTest() = default;
};


#endif //LABS_CRYPTO_PRIMETEST_H