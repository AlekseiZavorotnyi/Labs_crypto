#include "RSA/Service.h"

ll Server::norm_mod(ll a, ll m) {
    ll r = a % m;
    if (r < 0) {
        r += m;
    }
    return r;
}

ll Server::mul_mod(ll a, ll b, ll m) {
    a = norm_mod(a, m);
    b = norm_mod(b, m);
    __int128 res = ( (__int128)a * (__int128)b ) % (__int128)m;
    return (ll)res;
}

ll Server::gcd(ll a, ll b) {
    a = a < 0 ? -a : a;
    b = b < 0 ? -b : b;
    while (b != 0) {
        ll t = a % b;
        a = b;
        b = t;
    }
    return a;
}

ll Server::extended_gcd(ll a, ll b, ll &x, ll &y) {
    x = 1; y = 0;
    ll x1 = 0, y1 = 1;
    while (b != 0) {
        ll q = a / b;
        ll t = a % b;
        a = b; b = t;

        ll tmp = x - q * x1;
        x = x1; x1 = tmp;

        tmp = y - q * y1;
        y = y1; y1 = tmp;
    }
    return a;
}

ll Server::mod_pow(ll a, ull e, ll m) {
    if (m <= 0) throw std::invalid_argument("modulus must be positive");
    a = norm_mod(a, m);
    ll result = 1 % m;
    while (e > 0) {
        if (e & 1ULL) result = mul_mod(result, a, m);
        a = mul_mod(a, a, m);
        e >>= 1ULL;
    }
    return result;
}

ll Server::legendre_symbol(ll a, ll p) {
    if (p <= 2 || (p % 2 == 0)) {
        throw std::invalid_argument("p must be odd prime");
    }
    a = norm_mod(a, p);
    if (a == 0) return 0;
    ll r = mod_pow(a, (p - 1) / 2, p);
    if (r == 1) return 1;
    if (r == p - 1) return -1;
    return -1;
}

ll Server::jacobi_symbol(ll a, ll n) {
    if (n <= 0 || (n % 2 == 0)) throw std::invalid_argument("n must be positive odd");
    a = norm_mod(a, n);
    if (a == 0) return 0;
    ll result = 1;

    while (a != 0) {
        int tz = 0;
        while ((a & 1LL) == 0) {
            a >>= 1;
            tz++;
        }
        if (tz % 2 == 1) {
            ll nm8 = n % 8;
            if (nm8 == 3 || nm8 == 5) result = -result;
        }
        if ((a % 4 == 3) && (n % 4 == 3)) result = -result;

        ll tmp = a;
        a = n % tmp;
        n = tmp;

        if (a == 0) {
            if (n == 1) return result;
            return 0;
        }
    }
    return (n == 1) ? result : 0;
}