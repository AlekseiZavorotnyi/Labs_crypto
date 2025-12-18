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
    RSA_Service rsa(PT::Fermat, 0.99, 1024);
    std::string img("./kotik.png");
    std::string encrypted_path("./c.txt");
    std::string decrypted_path("./rsa.png");

    rsa.generate_rsa_keys();
    rsa.rsa_encrypt_file(img, encrypted_path);
    rsa.rsa_decrypt_file(encrypted_path, decrypted_path);
    return 0;
}