#ifndef LABS_CRYPTO_MILRABTEST_H
#define LABS_CRYPTO_MILRABTEST_H
#include "PrimeTest.h"

class MilRabTest: public PrimeTest {
    double one_iter_fail_probability() const override;
    bool test_iteration(const mpz_class &n) override;
};

#endif //LABS_CRYPTO_MILRABTEST_H