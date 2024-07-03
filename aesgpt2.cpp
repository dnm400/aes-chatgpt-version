#include <stdint.h>
#include <string.h>

// Constants for AES
#define Nb 4
#define Nk 4
#define Nr 10

typedef uint8_t state_t[4][4];

// S-box and Rcon arrays here, same as in the previous implementation
static const uint8_t sbox[256] = {
    // S-box values here...
};

static const uint8_t Rcon[255] = {
    // Rcon values here...
};

uint8_t getSBoxValue(uint8_t num) {
    return sbox[num];
}

void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key) {
    unsigned i, j, k;
    uint8_t tempa[4];

    for (i = 0; i < Nk; ++i) {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    for (; (i < (Nb * (Nr + 1))); ++i) {
        for (j = 0; j < 4; ++j) {
            tempa[j] = RoundKey[(i - 1) * 4 + j];
        }
        if (i % Nk == 0) {
            k = tempa[0];
            tempa[0] = tempa[1];
            tempa[1] = tempa[2];
            tempa[2] = tempa[3];
            tempa[3] = k;

            tempa[0] = getSBoxValue(tempa[0]);
            tempa[1] = getSBoxValue(tempa[1]);
            tempa[2] = getSBoxValue(tempa[2]);
            tempa[3] = getSBoxValue(tempa[3]);

            tempa[0] = tempa[0] ^ Rcon[i / Nk];
        } else if (Nk > 6 && i % Nk == 4) {
            tempa[0] = getSBoxValue(tempa[0]);
            tempa[1] = getSBoxValue(tempa[1]);
            tempa[2] = getSBoxValue(tempa[2]);
            tempa[3] = getSBoxValue(tempa[3]);
        }
        RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
        RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
        RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
        RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
    }
}

void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey) {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

void SubBytes(state_t* state) {
    uint8_t i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*state)[j][i] = getSBoxValue((*state)[j][i]);
        }
    }
}

void ShiftRows(state_t* state) {
    uint8_t temp;

    temp = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;
    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

uint8_t xtime(uint8_t x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

void MixColumns(state_t* state) {
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i) {
        t = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        Tm = (*state)[i][0] ^ (*state)[i][1];
        Tm = xtime(Tm);
        (*state)[i][0] ^= Tm ^ Tmp;
        Tm = (*state)[i][1] ^ (*state)[i][2];
        Tm = xtime(Tm);
        (*state)[i][1] ^= Tm ^ Tmp;
        Tm = (*state)[i][2] ^ (*state)[i][3];
        Tm = xtime(Tm);
        (*state)[i][2] ^= Tm ^ Tmp;
        Tm = (*state)[i][3] ^ t;
        Tm = xtime(Tm);
        (*state)[i][3] ^= Tm ^ Tmp;
    }
}

void Cipher(state_t* state, const uint8_t* RoundKey) {
    uint8_t round = 0;

    AddRoundKey(0, state, RoundKey);

    for (round = 1; round < Nr; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(Nr, state, RoundKey);
}

void AES128_ECB_encrypt(uint8_t* input, const uint8_t* key, uint8_t* output) {
    memcpy(output, input, 16);
    state_t* state = (state_t*)output;

    uint8_t RoundKey[176];
    KeyExpansion(RoundKey, key);
    Cipher(state, RoundKey);
}

void increment_counter(uint8_t* counter) {
    for (int i = 15; i >= 0; i--) {
        if (++counter[i]) {
            break;
        }
    }
}

void AES128_CTR_encrypt(uint8_t* input, const uint8_t* key, uint8_t* counter, uint8_t* output, size_t length) {
    uint8_t buffer[16];
    uint8_t keystream[16];
    uint8_t RoundKey[176];
    KeyExpansion(RoundKey, key);

    for (size_t i = 0; i < length; i += 16) {
        AES128_ECB_encrypt(counter, key, keystream);
        increment_counter(counter);

        size_t block_size = (length - i) < 16 ? (length - i) : 16;
        for (size_t j = 0; j < block_size; ++j) {
            output[i + j] = input[i + j] ^ keystream[j];
        }
    }
}
