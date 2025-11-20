#include <iostream>
#include <iomanip>
#include <vector>
#include <memory>
#include <thread>
#include "SymmetricCipherContext.h"

using namespace std;

void printHex(const string& label, const vector<uint8_t>& data) {
    cout << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < min(data.size(), size_t(32)); i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(data[i]) << " ";
    }
    if (data.size() > 32) cout << "...";
    cout << dec << endl;
}

void debugTestWithPadding(const string& name, SymmetricCipherContext& context, const vector<uint8_t>& original) {
    cout << "\n=== Debug " << name << " ===" << endl;

    printHex("Original data", original);
    cout << "Original size: " << original.size() << " bytes" << endl;

    // Тестируем процесс шаг за шагом
    vector<uint8_t> padded = original;

    // Шаг 1: Применяем padding
    vector<uint8_t> encrypted, decrypted;

    // Шаг 2: Шифруем
    context.encrypt(original, encrypted);
    printHex("Encrypted data", encrypted);
    cout << "Encrypted size: " << encrypted.size() << " bytes" << endl;

    // Шаг 3: Дешифруем
    context.decrypt(encrypted, decrypted);
    printHex("Decrypted data", decrypted);
    cout << "Decrypted size: " << decrypted.size() << " bytes" << endl;

    // Сравниваем
    bool match = true;
    size_t min_size = min(original.size(), decrypted.size());

    for (size_t i = 0; i < min_size; i++) {
        if (original[i] != decrypted[i]) {
            cout << "❌ Data mismatch at position " << i
                 << ": Original=" << hex << (int)original[i]
                 << ", Decrypted=" << (int)decrypted[i] << dec << endl;
            match = false;
            break;
        }
    }

    if (match && original.size() == decrypted.size()) {
        cout << "✅ Test PASSED!" << endl;
    } else {
        cout << "❌ Test FAILED! Size diff: " << original.size()
             << " vs " << decrypted.size() << endl;
    }
}

int main() {
    // Оригинальные данные из вашего первого main
    vector<uint8_t> original_text = {'S', 'o', 'm', 'e', ' ', 't', 'e', 'x', 't', ' ', 't', 'o', ' ', 'c', 'h', 'e',
                                     'c', 'k', ' ', 'i', 'f', ' ', 'D', 'E', 'S', ' ', 'w', 'o', 'r', 'k', 's', '.',
                                     '\n', 'I', 'f', ' ', 'y', 'o', 'u', ' ', 's', 'e', 'e', ' ', 't', 'h', 'i', 's',
                                     ',', ' ', 'I', ' ', 'h', 'a', 'l', 'f', ' ', 'w', 'o', 'n', '!', '\0'};

    vector<uint8_t> key_des = {10, 23, 54, 3, 124, 43, 76, 255};
    vector<uint8_t> key_deal = {10, 23, 54, 3, 124, 43, 76, 255,
                                200, 150, 100, 50, 25, 75, 125, 175};

    cout << "=== TESTING ORIGINAL DATA WITH DIFFERENT PADDING MODES ===" << endl;

    // Тестируем разные padding modes
    vector<PaddingMode> paddingModes = {
            PaddingMode::PKCS7,
            PaddingMode::ANSI_X923,
            PaddingMode::ISO_10126
            // ZEROS не тестируем - он сломан для данных с нулями
    };

    for (auto paddingMode : paddingModes) {
        string paddingName;
        switch (paddingMode) {
            case PaddingMode::PKCS7: paddingName = "PKCS7"; break;
            case PaddingMode::ANSI_X923: paddingName = "ANSI_X923"; break;
            case PaddingMode::ISO_10126: paddingName = "ISO_10126"; break;
            default: paddingName = "UNKNOWN";
        }

        cout << "\n--- Testing DES with " << paddingName << " padding ---" << endl;
        SymmetricCipherContext desContext(
                CipherAlgorithm::DES,
                CipherMode::ECB,
                paddingMode,
                key_des
        );
        debugTestWithPadding("DES " + paddingName, desContext, original_text);

        cout << "\n--- Testing DEAL with " << paddingName << " padding ---" << endl;
        SymmetricCipherContext dealContext(
                CipherAlgorithm::DEAL,
                CipherMode::ECB,
                paddingMode,
                key_deal
        );
        debugTestWithPadding("DEAL " + paddingName, dealContext, original_text);
    }

    return 0;
}