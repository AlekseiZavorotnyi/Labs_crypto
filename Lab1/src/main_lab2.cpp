#include <iostream>
#include <ostream>

#include "../include/RSA/RSA_Service.h"
#include "../include/RSA/WienerAttack.h"

#include <gmpxx.h>
#include <vector>

#include "RSA/Service.h"

using PT = RSA_Service::KeyGenerator::PrimalityTest;

int main() {
    // RSA_Service rsa(PT::Fermat, 0.99, 1024);
    // std::cout << "RSA created" << std::endl;
    // rsa.generate_rsa_keys();
    //
    // mpz_class m("564123456789123456789123456789");
    // mpz_class c = rsa.encrypt(m);
    // std::cout << "Encrypted message: " << c << std::endl;
    // mpz_class d = rsa.decrypt(c);
    // std::cout << "Decrypted message: " << d << std::endl;
    //
    RSA_Service weak_rsa(PT::Fermat, 0.99, 1024);
    weak_rsa.generate_weak_rsa_keys();
    mpz_class m("564123456789123456789123456789");
    mpz_class c = weak_rsa.encrypt(m);
    std::cout << "Encrypted message: " << c << std::endl;
    mpz_class d = weak_rsa.decrypt(c);
    std::cout << "Decrypted message: " << d << std::endl;

    std::cout << "\n\nWiener attack!" << std::endl;
    WienerAttack wa(weak_rsa.public_key.n, weak_rsa.public_key.e);
    mpz_class private_d = wa.crack_key();
    if (private_d == -1) {
        std::cout << "d is -1";
        return 0;
    }
    mpz_class cracked_text = Service::powmod(c, private_d, weak_rsa.public_key.n);
    std::cout << "Cracked text: " << cracked_text << std::endl;
}