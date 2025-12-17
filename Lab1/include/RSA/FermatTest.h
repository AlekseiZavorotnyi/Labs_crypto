#ifndef LABS_CRYPTO_FERMATTEST_H
#define LABS_CRYPTO_FERMATTEST_H
#include "PrimeTest.h"

class FermatTest : public PrimeTest {
protected:
    double one_iter_fail_probability() const override;
    bool test_iteration(const mpz_class &n) override;
};


#endif //LABS_CRYPTO_FERMATTEST_H
