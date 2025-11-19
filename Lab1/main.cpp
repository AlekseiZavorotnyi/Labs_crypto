#include <iostream>
#include <iomanip>
#include <vector>
#include <memory>
//#include "Feistel_network.cpp"
#include "Encryption_Modes.cpp"

using namespace std;

bool areEqual(const uint8_t* a, const uint8_t* b, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}


void printHex(const string& label, const vector<uint8_t>& data) {
    cout << label << ": ";
    for (size_t i = 0; i < data.size(); i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(data[i]) << " ";
    }
    cout << dec << endl;
}

bool test(SymmetricCipherContext& context, const vector<uint8_t>& original, const vector<uint8_t>& key) {
    try {
        cout << "\n1. Start data:" << endl;
        printHex("original text", original);
        printHex("Key", key);

        cout << "\n2. Encrypting..." << endl;
        auto encrypted = context.encrypt(original);
        printHex("Encrypted text", encrypted);

        // Проверяем, что шифрование что-то изменило
        bool same = true;
        for (size_t i = 0; i < original.size(); i++) {
            if (encrypted[i] != original[i]) {
                same = false;
                break;
            }
        }

        if (same) {
            cout << "Error: Encryption didn't do anything!" << endl;
            return false;
        } else {
            cout << "Encrypted successfully" << endl << endl;
        }

        cout << "\n3. Decrypting..." << endl;
        auto decrypted = context.decrypt(encrypted);
        printHex("Decrypted text", decrypted);

        cout << "\n4. Compare res:" << endl;
        if (original == decrypted) {
            cout << "All is good" << endl;
        } else {
            cout << "All is NOT good" << endl;
            return false;
        }

    } catch (const exception& e) {
        cout << "Error: " << e.what() << endl;
        return false;
    }
    return true;
}

int main() {
    // Тестовые данные
    vector<uint8_t> text = {'S', 'o', 'm', 'e', ' ', 't', 'e', 'x', 't', ' ', 't', 'o', ' ', 'c', 'h', 'e',
                            'c', 'k', ' ', 'i', 'f', ' ', 'D', 'E', 'S', ' ', 'w', 'o', 'r', 'k', 's', '.',
                            '\n', 'I', 'f', ' ', 'y', 'o', 'u', ' ', 's', 'e', 'e', ' ', 't', 'h', 'i', 's',
                            ',', ' ', 'I', ' ', 'h', 'a', 'l', 'f', ' ', 'w', 'o', 'n', '!', '\0'};

    vector<uint8_t> key_des = {10, 23, 54, 3, 124, 43, 76, 255};
    vector<uint8_t> key_deal = {10, 23, 54, 3, 124, 43, 76, 255,
                                200, 150, 100, 50, 25, 75, 125, 175};

    // Тест DES
    cout << "=== Testing DES ===" << endl;
    SymmetricCipherContext desContext(
            CipherAlgorithm::DES,
            CipherMode::ECB,
            PaddingMode::PKCS7,
            key_des
    );
    test(desContext, text, key_des);

    // Тест DEAL
    cout << "\n=== Testing DEAL ===" << endl;
    SymmetricCipherContext dealContext(
            CipherAlgorithm::DEAL,
            CipherMode::ECB,
            PaddingMode::PKCS7,
            key_deal,
            {},
            ByteOrder::BIG_ENDIAN,
            16
    );
    test(dealContext, text, key_deal);

    return 0;
}