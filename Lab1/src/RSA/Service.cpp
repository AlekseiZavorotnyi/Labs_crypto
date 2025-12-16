#include "RSA/Service.h"

big Server::norm_mod(big a, big m) {
    big r = a % m;
    if (r < 0) {
        r += m;
    }
    return r;
}

big Server::mul_mod(big a, big b, big m) {
    a = norm_mod(a, m);
    b = norm_mod(b, m);
    __int128 res = ( (__int128)a * (__int128)b ) % (__int128)m;
    return (big)res;
}

big Server::gcd(big a, big b) {
    a = a < 0 ? -a : a;
    b = b < 0 ? -b : b;
    while (b != 0) {
        big t = a % b;
        a = b;
        b = t;
    }
    return a;
}

big Server::extended_gcd(big a, big b, big &x, big &y) {
    x = 1; y = 0;
    big x1 = 0, y1 = 1;
    while (b != 0) {
        big q = a / b;
        big t = a % b;
        a = b; b = t;

        big tmp = x - q * x1;
        x = x1; x1 = tmp;

        tmp = y - q * y1;
        y = y1; y1 = tmp;
    }
    return a;
}

big Server::mod_pow(big a, big e, big m) {
    if (m <= 0) throw std::invalid_argument("modulus must be positive");
    a = norm_mod(a, m);
    big result = 1 % m;
    while (e > 0) {
        if (e & 1Ubig) result = mul_mod(result, a, m);
        a = mul_mod(a, a, m);
        e >>= 1Ubig;
    }
    return result;
}

big Server::legendre_symbol(big a, big p) {
    if (p <= 2 || (p % 2 == 0)) {
        throw std::invalid_argument("p must be odd prime");
    }
    a = norm_mod(a, p);
    if (a == 0) return 0;
    big r = mod_pow(a, (p - 1) / 2, p);
    if (r == 1) return 1;
    if (r == p - 1) return -1;
    return -1;
}

big Server::jacobi_symbol(big a, big n) {
    if (n <= 0 || (n % 2 == 0)) throw std::invalid_argument("n must be positive odd");
    a = norm_mod(a, n);
    if (a == 0) return 0;
    big result = 1;

    while (a != 0) {
        int tz = 0;
        while ((a & 1big) == 0) {
            a >>= 1;
            tz++;
        }
        if (tz % 2 == 1) {
            big nm8 = n % 8;
            if (nm8 == 3 || nm8 == 5) result = -result;
        }
        if ((a % 4 == 3) && (n % 4 == 3)) result = -result;

        big tmp = a;
        a = n % tmp;
        n = tmp;

        if (a == 0) {
            if (n == 1) return result;
            return 0;
        }
    }
    return (n == 1) ? result : 0;
}