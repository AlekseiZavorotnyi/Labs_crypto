#include "../../include/RSA/Service.h"

#include <ctime>
#include <random>
#include <chrono>
#include  <thread>

bool Service::is_odd(const mpz_class &a) {
    return mpz_odd_p(a.get_mpz_t());
}

mpz_class Service::powmod(const mpz_class& a, mpz_class b, const mpz_class& mod) {
    mpz_class base = a % mod;
    mpz_class result(1);

    while (b > 0) {
        if (is_odd(b)) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        b /= 2;
    }

    return result;
}

mpz_class Service::pow(const mpz_class& a, mpz_class b) {
    mpz_class base(a);
    mpz_class result(1);

    while (b > 0) {
        if (is_odd(b)) {
            result *= base;
        }
        base *= base;
        b /= 2;
    }
    return result;
}

mpz_class Service::Legengre_val(const mpz_class& a, const mpz_class& p) {
    mpz_class t = powmod(a, (p - 1) / 2, p);
    if (t == 0) {
        return 0;
    }
    if (t == 1) {
        return 1;
    }
    if (t == p - 1) {
        return -1;
    }
    return -2;
}

mpz_class Service::Jacobi_val(mpz_class a, const mpz_class& n) {
    if (n <= 0 || (n % 2) == 0) return 0;
    if (n == 1) return 1;

    a = a % n;
    if (a == 0) return 0;
    if (a == 1) return 1;

    mpz_class result(1);

    if (a < 0) {
        a = a * -1;
        if (n % 4 == 3) {
            result *= -1;
        }
    }

    mpz_class t(0);
    while (!is_odd(a)) {
        a /= 2;
        ++t;
    }
    if (t > 0) {
        if ((n % 8 == 3 || n % 8 == 5) && (t % 2 == 1)) {
            result *= -1;
        }
    }

    if (a % 4 == 3 && n % 4 == 3) {
        result *= -1;
    }

    if (a == 1) return result;
    return result * Jacobi_val(n % a, a);
}

mpz_class Service::gcd(mpz_class a, mpz_class b) {
    while (a > 0) {
        if (a <= b) {
            b = b % a;
        }
        std::swap(a ,b);
    }
    return b;
}

mpz_class Service::egcd(const mpz_class& a, mpz_class b, mpz_class &x, mpz_class &y) {
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    mpz_class x1, y1;
    mpz_class g = egcd(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return g;
}

mpz_class Service::root4(mpz_class n) {
    mpz_class sqrt_n;
    mpz_sqrt(sqrt_n.get_mpz_t(), n.get_mpz_t());
    mpz_class fourth_root;
    mpz_sqrt(fourth_root.get_mpz_t(), sqrt_n.get_mpz_t());
    return fourth_root;
}

mpz_class Service::random_in_range(const mpz_class &min, const mpz_class &max) {
    thread_local gmp_randclass rng(gmp_randinit_default);
    thread_local bool initialized = false;

    if (!initialized) {
        std::random_device rd;
        auto time_seed = static_cast<unsigned long>(
                std::chrono::high_resolution_clock::now()
                        .time_since_epoch().count()
        );
        auto thread_id = std::hash<std::thread::id>{}(std::this_thread::get_id());
        rng.seed(rd() ^ time_seed ^ thread_id);
        initialized = true;
    }

    if (min > max) {
        throw std::invalid_argument("min must be <= max");
    }

    mpz_class range = max - min;

    if (range <= 0) {
        throw std::overflow_error("Range too large, possible overflow");
    }

    mpz_class random_offset = rng.get_z_range(range);
    return min + random_offset;
}

mpz_class Service::random_with_len(size_t bit_len) {
    thread_local gmp_randclass rng(gmp_randinit_default);
    thread_local bool initialized = false;

    if (!initialized) {
        std::random_device rd;
        auto time_seed = static_cast<unsigned long>(
                std::chrono::high_resolution_clock::now()
                        .time_since_epoch().count()
        );
        auto thread_id = std::hash<std::thread::id>{}(std::this_thread::get_id());
        rng.seed(rd() ^ time_seed ^ thread_id);
        initialized = true;
    }

    if (bit_len == 0) {
        return 0;
    }

    mpz_class num = rng.get_z_bits(bit_len);
    mpz_setbit(num.get_mpz_t(), bit_len - 1);
    if (!mpz_odd_p(num.get_mpz_t())) {
        mpz_add_ui(num.get_mpz_t(), num.get_mpz_t(), 1);
    }
    return num;
}
