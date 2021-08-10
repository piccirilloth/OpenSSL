#include <stdio.h>
#include <openssl/hmac.h>

#define HASH_SIZE 1024

int main() {
    HMAC_CTX *ctx;
    char hash[HASH_SIZE];
    int len, i;
    char *message = "This is the message we want to compute the hash";
    unsigned char *key = "1234567991234567"; //length = 16

    ctx = HMAC_CTX_new();
    HMAC_Init(ctx, key, 16, EVP_sha3_256());

    HMAC_Update(ctx, message, HASH_SIZE);
    HMAC_Final(ctx, hash, &len);

    printf("the HMAC expected length is 32 bytes, the result is of %d bytes\n", len);
    printf("the keyed digest computed is ");
    for(i=0; i<len; i++)
        printf("%2x", hash[i]);
    printf("\n");

    return 0;
}
