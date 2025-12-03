#include <cstddef>
#include <cstdint>
#include "./Interfaces/ISymmetricCipher.h"
#include "./ICipherMode.h"

class CTRMode : public ICipherMode {
public:
    void processBlocks(uint8_t* data, size_t& length,
                       ISymmetricCipher* cipher,
                       const uint8_t* iv,
                       bool encrypt,
                       size_t user_threads = 0) override;
    bool canParallelize() const override;
    bool requiresIV() const override;

private:
    static void addToCounter(uint8_t* counter, size_t counter_len, size_t add);
};
