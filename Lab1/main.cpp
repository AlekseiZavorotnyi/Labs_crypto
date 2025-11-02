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

int main() {

    try {

        auto des = std::make_unique<DES>();

        // 2. Тестовые данные
        mass_b original = {byte{0x01}, byte{0x23}, byte{0x45}, byte{0x67},
                           byte{0x89}, byte{0xAB}, byte{0xCD}, byte{0xEF}};
        mass_b key = {byte{0x13}, byte{0x34}, byte{0x57}, byte{0x79},
                      byte{0x9B}, byte{0xBC}, byte{0xDF}, byte{0xF1}};

        cout << "\n1. Start data:" << endl;
        printHex("Original text", original);
        printHex("Key", key);

        des->setupKeys(key);

        // 4. Шифруем
        cout << "\n2. Encrypting..." << endl;
        mass_b encrypted = des->encrypt(original);
        printHex("Encrypted text", encrypted);

        // 5. Проверяем, что шифрование изменило данные
        if (areEqual(original, encrypted)) {
            cout << "Error: Encryption didn`t do anything!" << endl;
            return 1;
        } else {
            cout << "Encrypted successfully" << endl;
        }

        // 6. Дешифруем
        cout << "\n3. Decrypting..." << endl;
        mass_b decrypted = des->decrypt(encrypted);
        printHex("Decrypted text", decrypted);

        // 7. Сравниваем оригинал и результат дешифрования
        cout << "\n4. Compare res:" << endl;
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
            return 1;
        }

    } catch (const exception& e) {
        cout << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}