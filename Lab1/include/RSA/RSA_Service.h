#ifndef LABS_CRYPTO_RSA_SERVICE_H
#define LABS_CRYPTO_RSA_SERVICE_H

#include <gmpxx.h>

class RSA_Service {
public:
    struct PublicKey {
        mpz_class n;
        mpz_class e;
    };

    struct PrivateKey {
        mpz_class n;
        mpz_class d;
    };

    PublicKey public_key;

    class KeyGenerator {
    public:
        enum class PrimalityTest {
            Fermat,
            SoloveyStrassen,
            MillerRabin,
        };

        KeyGenerator(RSA_Service &parent, PrimalityTest p_test, double p_min, size_t bit_len);

        void generate_keys() const;

        void generate_weak_keys() const;

    private:
        RSA_Service &service_;
        PrimalityTest p_test;
        size_t bit_len;
        double p_min;
    };

    RSA_Service(KeyGenerator::PrimalityTest test, double min_prime_probability, size_t bit_length);

    void generate_rsa_keys() const;

    void generate_weak_rsa_keys() const;

    mpz_class encrypt(const mpz_class &message) const;

    mpz_class decrypt(const mpz_class &cipher) const;

    void rsa_encrypt_file(const std::string& in_path, const std::string& out_path) const;

    void rsa_decrypt_file(const std::string& in_path, const std::string& out_path) const;

private:
    PrivateKey private_key;
    KeyGenerator keys_generator;
};

#endif //LABS_CRYPTO_RSA_SERVICE_H