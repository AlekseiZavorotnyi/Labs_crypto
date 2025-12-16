#include <iostream>
#include "RSA/Service.h"

int main(){
    mpz_t a, b;
    mpz_init(a);
    mpz_init(b);

    mpz_set_str(a, "10", 10);
    mpz_set_str(b, "2", 10);
    auto c = Server();
    mpz_clear(a);
    mpz_clear(b);
    std::cout << c.gcd(a, b) << std::endl;
}