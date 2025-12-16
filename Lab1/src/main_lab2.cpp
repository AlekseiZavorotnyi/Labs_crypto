#include <iostream>
#include "RSA/Service.h"

int main(){
    ll a = 5, b = 10;
    auto c = Server();
    std::cout << c.gcd(a, b) << std::endl;
}