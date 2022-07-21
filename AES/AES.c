#include "AES.h"

byte times02(byte x)
{
    if (x & 0x80)
        return (x << 1) ^ 0x1B;
    else
        return (x << 1);
}

byte times03(byte x)
{
    return x ^ times02(x);
}

void addRoundKey(State* state, State* key)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state->val[i][j] ^= key->val[i][j];
        }
    }
}

void subBytes(State* state)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state->val[i][j] = sBox[state->val[i][j]];
        }
    }
}

void shiftRows(State* state)
{
    byte cpy[4][4];
    int i, j, k = 1;

    memcpy(cpy, state->val, 16 * sizeof(byte));

    for (i = 1; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state->val[i][j] = cpy[i][(j + k) % 4];
        }
        k++;
    }
}

void mixColumns(State* state)
{
    byte cpy[4][4];
    int i, j;

    memcpy(cpy, state->val, 16 * sizeof(byte));

    for (i = 0; i < 4; i++)
    {
        state->val[0][i] = times02(cpy[0][i]) ^ times03(cpy[1][i]) ^ cpy[2][i] ^ cpy[3][i];
        state->val[1][i] = cpy[0][i] ^ times02(cpy[1][i]) ^ times03(cpy[2][i]) ^ cpy[3][i];
        state->val[2][i] = cpy[0][i] ^ cpy[1][i] ^ times02(cpy[2][i]) ^ times03(cpy[3][i]);
        state->val[3][i] = times03(cpy[0][i]) ^ cpy[1][i] ^ cpy[2][i] ^ times02(cpy[3][i]);
    }
}

void invSubBytes(State* state)
{
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state->val[i][j] = invSBox[state->val[i][j]];
        }
    }
}

void invShiftRows(State* state)
{
    byte cpy[4][4];
    int i, j, k = 0;

    memcpy(cpy, state->val, 16 * sizeof(byte));
   
    // Have to do this because modulus don't work with negative numbers
    state->val[1][0] = cpy[1][3];
    state->val[1][1] = cpy[1][0];
    state->val[1][2] = cpy[1][1];
    state->val[1][3] = cpy[1][2];

    state->val[2][0] = cpy[2][2];
    state->val[2][1] = cpy[2][3];
    state->val[2][2] = cpy[2][0];
    state->val[2][3] = cpy[2][1];

    state->val[3][0] = cpy[3][1];
    state->val[3][1] = cpy[3][2];
    state->val[3][2] = cpy[3][3];
    state->val[3][3] = cpy[3][0];
}

void invMixColumns(State* state)
{
    byte cpy[4][4];
    int i, j;

    memcpy(cpy, state->val, 16 * sizeof(byte));

    for (i = 0; i < 4; i++)
    {
        state->val[0][i] = times0E[cpy[0][i]] ^ times0B[cpy[1][i]] ^ times0D[cpy[2][i]] ^ times09[cpy[3][i]];
        state->val[1][i] = times09[cpy[0][i]] ^ times0E[cpy[1][i]] ^ times0B[cpy[2][i]] ^ times0D[cpy[3][i]];
        state->val[2][i] = times0D[cpy[0][i]] ^ times09[cpy[1][i]] ^ times0E[cpy[2][i]] ^ times0B[cpy[3][i]];
        state->val[3][i] = times0B[cpy[0][i]] ^ times0D[cpy[1][i]] ^ times09[cpy[2][i]] ^ times0E[cpy[3][i]];
    }
}

void setCipherKey(AES_128* aes, byte cipherKey[16])
{
    int i, j, k = 0;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            aes->roundKeys[0].val[j][i] = cipherKey[k];
            k++;
        }
    }

    byte x[4], O2[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
    for (i = 1; i <= 10; i++)
    {
        x[0] = sBox[aes->roundKeys[i - 1].val[1][3]];
        x[1] = sBox[aes->roundKeys[i - 1].val[2][3]];
        x[2] = sBox[aes->roundKeys[i - 1].val[3][3]];
        x[3] = sBox[aes->roundKeys[i - 1].val[0][3]];

        x[0] ^= O2[i - 1];

        aes->roundKeys[i].val[0][0] = aes->roundKeys[i - 1].val[0][0] ^ x[0];
        aes->roundKeys[i].val[1][0] = aes->roundKeys[i - 1].val[1][0] ^ x[1];
        aes->roundKeys[i].val[2][0] = aes->roundKeys[i - 1].val[2][0] ^ x[2];
        aes->roundKeys[i].val[3][0] = aes->roundKeys[i - 1].val[3][0] ^ x[3];

        aes->roundKeys[i].val[0][1] = aes->roundKeys[i - 1].val[0][1] ^ aes->roundKeys[i].val[0][0];
        aes->roundKeys[i].val[1][1] = aes->roundKeys[i - 1].val[1][1] ^ aes->roundKeys[i].val[1][0];
        aes->roundKeys[i].val[2][1] = aes->roundKeys[i - 1].val[2][1] ^ aes->roundKeys[i].val[2][0];
        aes->roundKeys[i].val[3][1] = aes->roundKeys[i - 1].val[3][1] ^ aes->roundKeys[i].val[3][0];

        aes->roundKeys[i].val[0][2] = aes->roundKeys[i - 1].val[0][2] ^ aes->roundKeys[i].val[0][1];
        aes->roundKeys[i].val[1][2] = aes->roundKeys[i - 1].val[1][2] ^ aes->roundKeys[i].val[1][1];
        aes->roundKeys[i].val[2][2] = aes->roundKeys[i - 1].val[2][2] ^ aes->roundKeys[i].val[2][1];
        aes->roundKeys[i].val[3][2] = aes->roundKeys[i - 1].val[3][2] ^ aes->roundKeys[i].val[3][1];

        aes->roundKeys[i].val[0][3] = aes->roundKeys[i - 1].val[0][3] ^ aes->roundKeys[i].val[0][2];
        aes->roundKeys[i].val[1][3] = aes->roundKeys[i - 1].val[1][3] ^ aes->roundKeys[i].val[1][2];
        aes->roundKeys[i].val[2][3] = aes->roundKeys[i - 1].val[2][3] ^ aes->roundKeys[i].val[2][2];
        aes->roundKeys[i].val[3][3] = aes->roundKeys[i - 1].val[3][3] ^ aes->roundKeys[i].val[3][2];
    }
}

void encrypt128(AES_128* aes, byte message[16])
{
    State state;
    int i, j, k = 0;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state.val[j][i] = message[k];
            k++;
        }
    }

    addRoundKey(&state, &aes->roundKeys[0]);
    int r;
    for (r = 1; r <= 9; r++)
    {
        subBytes(&state);
        shiftRows(&state);
        mixColumns(&state);
        addRoundKey(&state, &aes->roundKeys[r]);
    }

    subBytes(&state);
    shiftRows(&state);
    addRoundKey(&state, &aes->roundKeys[10]);

    k = 0;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            message[k] = state.val[i][j];
            k++;
        }
    }
}

void decrypt128(AES_128* aes, byte message[16])
{
    State state;
    int i, j, k = 0;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state.val[i][j] = message[k];
            k++;
        }
    }
    addRoundKey(&state, &aes->roundKeys[10]);
    int r;
    for (r = 9; r >= 1; r--)
    {
        invShiftRows(&state);
        invSubBytes(&state);
        addRoundKey(&state, &aes->roundKeys[r]);
        invMixColumns(&state);
    }

    invShiftRows(&state);
    invSubBytes(&state);
    addRoundKey(&state, &aes->roundKeys[0]);

    k = 0;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            message[k] = state.val[j][i];
            k++;
        }
    }
}

void printState(State* state)
{
    int i, j;
    printf("\n");
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
            printf("%02x ", state->val[i][j]);
        printf("\n");
    }
}
