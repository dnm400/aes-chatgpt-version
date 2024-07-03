#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <cstdint>

// S-box for AES
static const uint8_t sbox[256] = {
    // ... (omitted for brevity, include full S-box here)
};

// Round constant for AES key schedule
static const uint8_t Rcon[10] = {
    // ... (omitted for brevity, include round constants here)
};

// Substitute bytes using the S-box
void subBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = sbox[state[i][j]];
        }
    }
}

// Shift rows operation
void shiftRows(uint8_t state[4][4]) {
    uint8_t temp;

    // Shift row 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Shift row 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Shift row 3
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

// Mix columns operation
void mixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];
    for (int c = 0; c < 4; ++c) {
        temp[0] = state[0][c];
        temp[1] = state[1][c];
        temp[2] = state[2][c];
        temp[3] = state[3][c];

        state[0][c] = gfMul(temp[0], 2) ^ gfMul(temp[1], 3) ^ gfMul(temp[2], 1) ^ gfMul(temp[3], 1);
        state[1][c] = gfMul(temp[0], 1) ^ gfMul(temp[1], 2) ^ gfMul(temp[2], 3) ^ gfMul(temp[3], 1);
        state[2][c] = gfMul(temp[0], 1) ^ gfMul(temp[1], 1) ^ gfMul(temp[2], 2) ^ gfMul(temp[3], 3);
        state[3][c] = gfMul(temp[0], 3) ^ gfMul(temp[1], 1) ^ gfMul(temp[2], 1) ^ gfMul(temp[3], 2);
    }
}

// Galois Field (GF) multiplication
uint8_t gfMul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t hi_bit_set;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
            a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

// Add round key operation
void addRoundKey(uint8_t state[4][4], const uint8_t* roundKey) {
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            state[r][c] ^= roundKey[r + 4 * c];
        }
    }
}

// Key expansion
void keyExpansion(const uint8_t key[16], uint8_t expandedKeys[176]) {
    std::memcpy(expandedKeys, key, 16);
    uint8_t temp[4];
    int bytesGenerated = 16;
    int rconIndex = 0;

    while (bytesGenerated < 176) {
        std::memcpy(temp, expandedKeys + bytesGenerated - 4, 4);

        if (bytesGenerated % 16 == 0) {
            uint8_t t = temp[0];
            temp[0] = sbox[temp[1]] ^ Rcon[rconIndex++];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        }

        for (int i = 0; i < 4; ++i) {
            expandedKeys[bytesGenerated] = expandedKeys[bytesGenerated - 16] ^ temp[i];
            ++bytesGenerated;
        }
    }
}

// AES encryption of a single block
void aesEncryptBlock(uint8_t input[16], const uint8_t key[16]) {
    uint8_t state[4][4];
    uint8_t expandedKeys[176];
    std::memcpy(state, input, 16);
    keyExpansion(key, expandedKeys);

    addRoundKey(state, key);

    for (int round = 1; round < 10; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expandedKeys + round * 16);
    }

    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expandedKeys + 160);

    std::memcpy(input, state, 16);
}

// XOR operation for two blocks of data
void xorBlocks(uint8_t* out, const uint8_t* in1, const uint8_t* in2, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        out[i] = in1[i] ^ in2[i];
    }
}

// Increment the counter (nonce) for CTR mode
void incrementCounter(uint8_t* counter, size_t length) {
    for (size_t i = length; i > 0; --i) {
        if (++counter[i - 1] != 0) {
            break;
        }
    }
}

// Helper function to print data in hex format
void printHex(const std::string& label, const uint8_t* data, size_t length) {
    std::cout << label;
    for (size_t i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    // Key and counter (nonce)
    uint8_t key[16] = {0};
    uint8_t counter[16] = {0};

    // Initialize key and counter with random values (for example purposes, using fixed values)
    for (int i = 0; i < 16; ++i) {
        key[i] = i;
        counter[i] = i + 16;
    }

    printHex("Key: ", key, sizeof(key));
    printHex("Counter: ", counter, sizeof(counter));

    // Plaintext
    std::string plaintext = "This is a test message for AES CTR mode.";
    size_t plaintextLength = plaintext.size();

    // Ciphertext
    std::vector<uint8_t> ciphertext(plaintextLength);

    // Encrypt in CTR mode
    uint8_t encryptedCounter[16];
    size_t numBlocks = (plaintextLength + 15) / 16;

    for (size_t i = 0; i < numBlocks; ++i) {
        aesEncryptBlock(counter, key);

        size_t blockStart = i * 16;
        size_t blockSize = std::min(16, plaintextLength - blockStart);

        xorBlocks(ciphertext.data() + blockStart, reinterpret_cast<const uint8_t*>(plaintext.data()) + blockStart, counter, blockSize);

        incrementCounter(counter, 16);
    }

    // Print ciphertext
    printHex("Ciphertext: ", ciphertext.data(), ciphertext.size());

    // Decrypt
    std::vector<uint8_t> decryptedText(plaintextLength);

    // Reset counter (for example purposes, using fixed values again)
    for (int i = 0; i < 16; ++i) {
        counter[i] = i + 16;
    }

    for (size_t i = 0; i < numBlocks; ++i) {
        aesEncryptBlock(counter, key);

        size_t blockStart = i * 16;
        size_t blockSize = std::min(16, plaintextLength - blockStart);

        xorBlocks(decryptedText.data() + blockStart, ciphertext.data() + blockStart, counter, blockSize);

        incrementCounter(counter, 16);
    }

    // Print decrypted text
    std::string decryptedStr(reinterpret_cast<char*>(decryptedText.data()), decryptedText.size());
    std::cout << "Decrypted text: " << decryptedStr << std::endl;

    return 0;
}
