#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#define BUF_SIZE 1024

int main() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *key = "1234567891123123";
    unsigned char *iv = "0000000000000000";
    const unsigned char *message = "this is a secret message";
    unsigned char obuf[BUF_SIZE], decrypted[BUF_SIZE];
    int tot=0, i, dec_tot=0, len=0;

    printf("the key is ");
    for(i=0; i<16; i++) {
        printf("%2x", key[i]);
    }
    printf("\n");

    printf("the IV is ");
    for(i=0; i<16; i++) {
        printf("%2x", iv[i]);
    }
    printf("\n");

    printf("the message is ");
    for(i=0; i<strlen(message); i++) {
        printf("%2x", message[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);

    EVP_CipherUpdate(ctx, obuf, &len, message, strlen(message));
    tot += len;

    EVP_CipherFinal(ctx, obuf+tot, &len);
    tot += len;
    printf("the encrypted message is ");
    for(i=0; i<tot; i++) {
        printf("%2x", obuf[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);

    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv);

    EVP_CipherUpdate(ctx, decrypted, &len, obuf, tot);
    dec_tot += len;
    len = 0;
    EVP_CipherFinal(ctx, decrypted+dec_tot, &len);
    dec_tot += len;
    printf("the decrypted message is ");
    for(i=0; i<dec_tot; i++) {
        printf("%2x", decrypted[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}