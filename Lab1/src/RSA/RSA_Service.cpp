#include "../../include/RSA/RSA_Service.h"
#include "../../include/Interfaces/IPrimalityTest.h"
#include "../../include/RSA/PrimeTest.h"
#include "../../include/RSA/FermatTest.h"
#include "../../include/RSA/SolStrTest.h"
#include "../../include/RSA/MilRabTest.h"
#include "../../include/RSA/Service.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <fstream>
#include <iomanip>

std::string name_test(RSA_Service::KeyGenerator::PrimalityTest test) {
    switch (test) {
        case RSA_Service::KeyGenerator::PrimalityTest::Fermat: {
            return "Fermat";
        }
        case RSA_Service::KeyGenerator::PrimalityTest::MillerRabin: {
            return "MillerRabin";
        }
        case RSA_Service::KeyGenerator::PrimalityTest::SoloveyStrassen: {
            return "SoloveyStrassen";
        }
        default:
            return "";
    }
}

RSA_Service::KeyGenerator::KeyGenerator(RSA_Service &parent, PrimalityTest p_test, double p_min, size_t bit_len) : service_(parent) {
    this->p_test = p_test;
    this->p_min = p_min;
    this->bit_len = bit_len;
}

void RSA_Service::KeyGenerator::generate_keys() const {
    std::cout << "\nGenerating keys" << std::endl;
    PrimeTest *test = nullptr;
    switch (this->p_test) {
        case PrimalityTest::Fermat: {
            test = new FermatTest();
            break;
        }
        case PrimalityTest::SoloveyStrassen: {
            test = new SolStrTest();
            break;
        }
        case PrimalityTest::MillerRabin: {
            test = new MilRabTest();
            break;
        }
        default:
            break;
    }

    if (test == nullptr) {
        return;
    }
    std::cout << "Test " + name_test(this->p_test) + " created." << std::endl;

    while (true) {
        mpz_class p, q;
        while (true) {
            do {
                p = Service::random_with_len(bit_len);
            } while (!test->isPrime(p, p_min));

            do {
                q = Service::random_with_len(bit_len);
            } while (!test->isPrime(q, p_min));

            mpz_class diff = (p - q);
            if (diff < 0) diff = -diff;
            if (diff >= Service::pow(2, bit_len / 2 - 10)) {
                std::cout << "P & Q generated. Fermat attack denied.\nP: " << p << "\nQ: " << q << std::endl;
                break;
            }
            std::cout << "P & Q can be affected by Fermat attack.Repeating" << std::endl;
        }

        mpz_class N = p * q;
        mpz_class phi = (p - 1) * (q - 1);
        mpz_class e = 65537;

        mpz_class d, y;
        mpz_class gcd = Service::egcd(e, phi, d, y);
        if (gcd != 1) {
            std::cout << "GCD of e and phi is not 1. Repeating" << std::endl;
            continue;
        }
        std::cout << "GCD: " << gcd << std::endl;

        if (d < 0) {
            d = (d % phi + phi) % phi;
        } else {
            d %= phi;
        }

        if (d > (Service::root4(N) / 3)) {
            service_.private_key = PrivateKey(N, d);
            service_.public_key = PublicKey(N, e);
            std::cout << "d is ok. Keys generated" << std::endl;
            break;
        }
        std::cout << "d can be affected by Wiener attack. Repeating" << std::endl;
    }

    delete test;
}

void RSA_Service::KeyGenerator::generate_weak_keys() const {
    std::cout << "\nGenerating weak keys" << std::endl;
    PrimeTest *test = nullptr;
    switch (this->p_test) {
        case PrimalityTest::Fermat: {
            test = new FermatTest();
            break;
        }
        case PrimalityTest::SoloveyStrassen: {
            test = new SolStrTest();
            break;
        }
        case PrimalityTest::MillerRabin: {
            test = new MilRabTest();
            break;
        }
        default:
            break;
    }

    if (test == nullptr) {
        return;
    }
    std::cout << "Test " + name_test(this->p_test) + " created." << std::endl;

    mpz_class p, q;
    while (true) {
        do {
            p = Service::random_with_len(bit_len);
        } while (!test->isPrime(p, p_min));

        do {
            q = Service::random_with_len(bit_len);
        } while (!test->isPrime(q, p_min));

        mpz_class N = p * q;
        mpz_class phi = (p - 1) * (q - 1);
        mpz_class border = Service::root4(N) / 3;

        mpz_class e, d, y;
        do {
            d = Service::random_in_range(1, border);
        } while (Service::gcd(d, phi) != 1);

        mpz_class gcd = Service::egcd(d, phi, e, y);

        if (gcd != 1) {
            std::cout << "GCD of d and phi is not 1. Trying again..." << std::endl;
        }
        else {
            if (e < 0) {
                e = (e % phi + phi) % phi;
            } else {
                e %= phi;
            }
            std::cout << "GCD: " << gcd << "\nd: " << d << "\nfound e: " << e << std::endl;
            service_.private_key = PrivateKey(N, d);
            service_.public_key = PublicKey(N, e);
            std::cout << "Weak keys generated.\n" << std::endl;
            break;
        }
    }
}

void RSA_Service::generate_rsa_keys() const {
    keys_generator.generate_keys();
}

void RSA_Service::generate_weak_rsa_keys() const {
    keys_generator.generate_weak_keys();
}

RSA_Service::RSA_Service(KeyGenerator::PrimalityTest test, double min_prime_probability,
                         size_t bit_length) : keys_generator(*this, test, min_prime_probability, bit_length) {
}

mpz_class RSA_Service::encrypt(const mpz_class &m) const {
    mpz_class c = Service::powmod(m, public_key.e, public_key.n);
    return c;
}

mpz_class RSA_Service::decrypt(const mpz_class &c) const {
    mpz_class d = Service::powmod(c, private_key.d, private_key.n);
    return d;
}

#pragma pack(push, 1)
struct RsaFileHeader {
    char magic[4];
    uint32_t k;
    uint64_t original_size;
};
#pragma pack(pop)

static mpz_class bytes_to_mpz(const uint8_t* data, size_t len) {
    mpz_class x;
    mpz_import(x.get_mpz_t(), len, 1, 1, 0, 0, data);
    return x;
}

static void mpz_to_fixed_bytes(const mpz_class& x, uint8_t* out, size_t k) {
    std::memset(out, 0, k);
    size_t count = 0;
    mpz_export(out, &count, 1, 1, 0, 0, x.get_mpz_t());
    if (count > k) throw std::runtime_error("mpz_to_fixed_bytes: doesn't fit");
    if (count < k) {
        std::memmove(out + (k - count), out, count);
        std::memset(out, 0, k - count);
    }
}

static size_t modulus_bytes(const mpz_class& n) {
    return (mpz_sizeinbase(n.get_mpz_t(), 2) + 7) / 8;
}

void RSA_Service::rsa_encrypt_file( const std::string &in_path, const std::string &out_path) const {
    std::ifstream in(in_path, std::ios::binary);
    if (!in) throw std::runtime_error("can't open input");

    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw std::runtime_error("can't open output");

    const mpz_class n = this->public_key.n;
    const size_t k = modulus_bytes(n);
    const size_t p = (k > 1) ? (k - 1) : 0;
    if (p == 0) throw std::runtime_error("invalid modulus size");

    in.seekg(0, std::ios::end);
    uint64_t original_size = static_cast<uint64_t>(in.tellg());
    in.seekg(0, std::ios::beg);

    RsaFileHeader hdr{};
    std::memcpy(hdr.magic, "RSA1", 4);
    hdr.k = static_cast<uint32_t>(k);
    hdr.original_size = original_size;
    out.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));

    std::vector<uint8_t> plain(p);
    std::vector<uint8_t> cipher(k);

    size_t total_size = original_size;
    std::cout << "RSA encrypts file. Size =  " << total_size << " bytes";

    while (in) {
        in.read(reinterpret_cast<char*>(plain.data()), static_cast<std::streamsize>(p));
        std::streamsize got = in.gcount();
        if (got <= 0) break;

        if (static_cast<size_t>(got) < p) {
            std::memset(plain.data() + got, 0, p - static_cast<size_t>(got));
        }

        mpz_class m = bytes_to_mpz(plain.data(), p);
        if (m >= n) throw std::runtime_error("plaintext block >= n (unexpected)");

        mpz_class c = this->encrypt(m);
        mpz_to_fixed_bytes(c, cipher.data(), k);

        out.write(reinterpret_cast<const char*>(cipher.data()), static_cast<std::streamsize>(k));

    }
    std::cout << std::endl;
}

void RSA_Service::rsa_decrypt_file(const std::string &in_path, const std::string &out_path) const {
    std::ifstream in(in_path, std::ios::binary);
    if (!in) throw std::runtime_error("can't open input");

    RsaFileHeader hdr{};
    in.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (in.gcount() != sizeof(hdr) || std::memcmp(hdr.magic, "RSA1", 4) != 0) {
        throw std::runtime_error("bad RSA file header");
    }

    const size_t k = hdr.k;
    const size_t p = (k > 1) ? (k - 1) : 0;
    if (p == 0) throw std::runtime_error("invalid k");

    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw std::runtime_error("can't open output");

    std::vector<uint8_t> cipher(k);
    std::vector<uint8_t> plain(p);

    uint64_t remaining = hdr.original_size;

    size_t total_size = remaining;
    std::cout << "RSA decrypts file. Size =  " << total_size << " bytes";

    while (remaining > 0) {
        in.read(reinterpret_cast<char*>(cipher.data()), static_cast<std::streamsize>(k));
        if (in.gcount() != static_cast<std::streamsize>(k)) {
            throw std::runtime_error("truncated ciphertext");
        }

        mpz_class c = bytes_to_mpz(cipher.data(), k);
        mpz_class m = this->decrypt(c);

        std::vector<uint8_t> tmp(k);
        mpz_to_fixed_bytes(m, tmp.data(), k);
        std::memcpy(plain.data(), tmp.data() + (k - p), p);

        const size_t to_write = (remaining >= p) ? p : static_cast<size_t>(remaining);
        out.write(reinterpret_cast<const char*>(plain.data()), static_cast<std::streamsize>(to_write));
        remaining -= to_write;

    }
    std::cout << std::endl;
}