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
    if(EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv) != 1) {
        printf("error in EVP_EncryptInit\n");
        return -1;
    }

    if(EVP_CipherUpdate(ctx, obuf, &len, message, strlen(message)) != 1) {
        printf("error in EVP_CipherUpdate\n");
        return -1;
    }
    printf("%d\n", len);
    tot += len;

    if(EVP_CipherFinal(ctx, obuf+tot, &len) != 1) {
        printf("error in EVP_CipherFinal\n");
        return -1;
    }
    printf("%d\n", len);
    tot += len;
    printf("the encrypted message is ");
    for(i=0; i<tot; i++) {
        printf("%2x", obuf[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);

    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    if(EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv) != 1) {
        printf("error in EVP_DecryptInit\n");
        return -1;
    }

    if(EVP_CipherUpdate(ctx, decrypted, &len, obuf, tot) != 1) {
        printf("error in EVP_CipherUpdate\n");
        return -1;
    }
    dec_tot += len;

    if(EVP_CipherFinal(ctx, decrypted+dec_tot, &len) != 1) {
        printf("error in EVP_CipherFinal\n");
        return -1;
    }
    dec_tot += len;
    printf("the decrypted message is ");
    for(i=0; i<dec_tot; i++) {
        printf("%2x", decrypted[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);

    /***************************************************************************/
    printf("\nEncryption with split\n");
    int split_index = 12;
    char *long_message = "This is a long message"; // 22 characters

    printf("the long message is ");
    for(i=0; i< strlen(long_message); i++) {
        printf("%2x", long_message[i]);
    }
    printf("\n");

    ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);

    tot = 0;
    EVP_CipherUpdate(ctx, obuf, &len, long_message, split_index);
    printf("%d\n", len);
    tot += len;
    EVP_CipherUpdate(ctx, obuf+tot, &len, long_message+split_index, strlen(long_message)-split_index);
    printf("%d\n", len);
    tot += len;
    EVP_CipherFinal(ctx, obuf+tot, &len);
    printf("%d\n", len);
    tot += len;

    printf("the long message encrypted is ");
    for(i=0; i<tot; i++) {
        printf("%2x", obuf[i]);
    }
    printf("\n");

    /******************************************************************************/

    // Compute digest
    printf("\nThe message we want to compute the digest on is %s\n", message);
    EVP_MD_CTX *md_ctx;
    md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit(md_ctx, EVP_sha256());

    unsigned char hash[BUF_SIZE];
    int hash_len;

    EVP_DigestUpdate(md_ctx, message, strlen(message));
    EVP_DigestFinal(md_ctx, hash, &hash_len);

    printf("the hash has length equal to %d bytes\n", hash_len);
    for(i=0; i<hash_len; i++) {
        printf("%2x", hash[i]);
    }
    printf("\n");
    return 0;
}
