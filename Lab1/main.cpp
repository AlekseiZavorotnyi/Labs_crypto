#include <iostream>
#include <iomanip>
#include <vector>
#include <memory>
#include "Feistel_network.cpp"

using namespace std;

bool areEqual(const mass_b& a, const mass_b& b) {
    if (a.size() != b.size()) return false;

    for (size_t i = 0; i < a.size(); i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

void printHex(const string& label, const mass_b& data) {
    cout << label << ": ";
    for (auto byte_val : data) {
        cout << hex << setw(2) << setfill('0')
             << static_cast<int>(static_cast<uint8_t>(byte_val)) << " ";
    }
    cout << dec << endl;
}

bool Comparing(mass_b original, mass_b decrypted){
    if (areEqual(original, decrypted)) {
        cout << "All is good" << endl;
    } else {
        cout << "All is NOT good" << endl;

        // Покажем различия
        cout << "DIFF:" << endl;
        for (size_t i = 0; i < original.size(); i++) {
            if (original[i] != decrypted[i]) {
                cout << "  Byte " << i << ": "
                     << hex << setw(2) << static_cast<int>(static_cast<uint8_t>(original[i]))
                     << " vs "
                     << hex << setw(2) << static_cast<int>(static_cast<uint8_t>(decrypted[i]))
                     << dec << endl;
            }
        }
        return false;
    }
    return true;
}

int main() {

    try {

        //auto des = std::make_unique<DES>();
        auto deal = std::make_unique<DEAL>();

        // 2. Тестовые данные
        mass_b original_des = {byte{0x01}, byte{0x23}, byte{0x45}, byte{0x67},
                           byte{0x89}, byte{0xAB}, byte{0xCD}, byte{0xEF}};
        mass_b key_des = {byte{0x13}, byte{0x34}, byte{0x57}, byte{0x79},
                      byte{0x9B}, byte{0xBC}, byte{0xDF}, byte{0xF1}};

        mass_b original_deal = {
                byte{0x00}, byte{0x11}, byte{0x22}, byte{0x33},
                byte{0x44}, byte{0x55}, byte{0x66}, byte{0x77},
                byte{0x88}, byte{0x99}, byte{0xAA}, byte{0xBB},
                byte{0xCC}, byte{0xDD}, byte{0xEE}, byte{0xFF}
        };

        mass_b key_deal = {
                byte{0x01}, byte{0x23}, byte{0x45}, byte{0x67},
                byte{0x89}, byte{0xAB}, byte{0xCD}, byte{0xEF},
                byte{0xFE}, byte{0xDC}, byte{0xBA}, byte{0x98},
                byte{0x76}, byte{0x54}, byte{0x32}, byte{0x10}
        };

        cout << "\n1. Start data:" << endl;
        //printHex("original_des text", original_des);
        printHex("original_deal text", original_deal);
        //printHex("Key des", key_des);
        printHex("Key deal", key_deal);

        //des->setupKeys(key_des);
        deal->setupKeys(key_deal);

        // 4. Шифруем
        cout << "\n2. Encrypting..." << endl;
        //mass_b encrypted_des = des->encrypt(original_des);
        //printHex("Encrypted DES text", encrypted_des);
        mass_b encrypted_deal = deal->encrypt(original_deal);
        printHex("Encrypted DEAL text", encrypted_deal);

        // 5. Проверяем, что шифрование изменило данные
        /*if (areEqual(original_des, encrypted_des)) {
            cout << "Error: Encryption DES didn`t do anything!" << endl;
            return 1;
        } else {
            cout << "Encrypted DES successfully" << endl << endl;
        }*/

        if (areEqual(original_deal, encrypted_deal)) {
            cout << "Error: Encryption DEAL didn`t do anything!" << endl;
            return 1;
        } else {
            cout << "Encrypted DEAL successfully" << endl;
        }

        // 6. Дешифруем
        cout << "\n3. Decrypting..." << endl;
        //mass_b decrypted_des = des->decrypt(encrypted_des);
        mass_b decrypted_deal = deal->decrypt(encrypted_deal);
        //printHex("Decrypted DES text", decrypted_des);
        printHex("Decrypted DEAL text", decrypted_deal);

        // 7. Сравниваем оригинал и результат дешифрования
        cout << "\n4. Compare res:" << endl;
        //Comparing(original_des, decrypted_des);
        Comparing(original_deal, decrypted_deal);

    } catch (const exception& e) {
        cout << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}