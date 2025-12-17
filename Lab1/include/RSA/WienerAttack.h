#ifndef LABS_CRYPTO_WIENERATTACK_H
#define LABS_CRYPTO_WIENERATTACK_H
#include <gmpxx.h>
#include <vector>

class WienerAttack {
private:
    mpz_class N;
    mpz_class e;
    std::vector<mpz_class> chained_frac;

public:
    size_t chained_frac_size;
    struct frac {
        mpz_class a;
        mpz_class b;
    };

    void decompose_to_chained_fraction(mpz_class a, mpz_class b);

    frac get_frac_part(size_t i) const;

    WienerAttack(mpz_class N, mpz_class e);

    mpz_class crack_key();
};


#endif //LABS_CRYPTO_WIENERATTACK_H
