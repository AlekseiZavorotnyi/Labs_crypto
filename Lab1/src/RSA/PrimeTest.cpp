#include "../../include/RSA/PrimeTest.h"
#include <cmath>

int PrimeTest::calculate_iter_cnt(double p_min) const {
    double p_error = 1 - p_min;
    double base = this->one_iter_fail_probability();
    return std::ceil(std::log(p_error) / std::log(base));
}

bool PrimeTest::isPrime(const mpz_class &n, double p_min) {
    int iter_cnt = this->calculate_iter_cnt(p_min);

    for (int i = 0; i < iter_cnt; ++i) {
        if (!this->test_iteration(n)) {
            return false;
        }
    }
    return true;
}
