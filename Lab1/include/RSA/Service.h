#ifndef LABS_CRYPTO_SERVICE_H
#define LABS_CRYPTO_SERVICE_H
#include <cstdint>
#include <stdexcept>

using ll = long long;
using ull = unsigned long long;

class Server {
public:
    ll gcd(ll a, ll b);
    ll extended_gcd(ll a, ll b, ll &x, ll &y);
    ll mod_pow(ll a, ull e, ll m);
    ll legendre_symbol(ll a, ll p);
    ll jacobi_symbol(ll a, ll n);
private:
    ll mul_mod(ll a, ll b, ll m);
    ll norm_mod(ll a, ll m);
};
#endif //LABS_CRYPTO_SERVICE_H
