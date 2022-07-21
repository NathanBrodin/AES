#include "AES.h"

/*
* Implementation of AES 128 
* https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
*/

int main()
{
    AES_128 aes;
    byte message[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    byte cipherKey[16] = { 0x00, 0x0E, 0x51, 0xEA, 0x00, 0x0E, 0x51, 0xEA, 0x00, 0x0E, 0x51, 0xEA, 0x00, 0x0E, 0x51, 0xEA };
    int i;

    printf("          Message: ");
    for (i = 0; i < 16; i++)
        printf("%02x ", message[i]);
    printf("\n");

    setCipherKey(&aes, cipherKey);
    encrypt128(&aes, message);

    printf("Encrypted message: ");
    for (i = 0; i < 16; i++)
        printf("%02x ", message[i]);
    printf("\n");

    decrypt128(&aes, message);

    printf("Decrypted message: ");
    for (i = 0; i < 16; i++)
        printf("%02x ", message[i]);
    printf("\n");

    return EXIT_SUCCESS;  
}