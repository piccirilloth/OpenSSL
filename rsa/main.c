#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>
#define KEY_LENGTH 2048
#define ERR_SIZE 130

int main() {
    RSA *key_pair = NULL;
    BIGNUM *bne = NULL; // public exponent e
    int bits = 2048;
    unsigned long e = RSA_F4;

    bne = BN_new();
    BN_set_word(bne, e);

    key_pair = RSA_new();
    RSA_generate_key_ex(key_pair, bits, bne, NULL);

    /*
    int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                                  unsigned char *kstr, int klen,
                                  pem_password_cb *cb, void *u);
     int PEM_write_bio_PrivateKey_traditional(BIO *bp, EVP_PKEY *x,
                                              const EVP_CIPHER *enc,
                                              unsigned char *kstr, int klen,
                                              pem_password_cb *cb, void *u);
     int PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                              unsigned char *kstr, int klen,
                              pem_password_cb *cb, void *u);
     int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc,
                                unsigned char *kstr, int klen,
                                pem_password_cb *cb, void *u);
    */
    BIO *bp_private = NULL;
    bp_private = BIO_new_file("private_key.pem", "w+");
    PEM_write_bio_RSAPrivateKey(bp_private, key_pair, NULL, NULL, 0, NULL, NULL);

    // TODO EXERCISE: write a password protected AES-encrypted private key
    // TODO EXERCISE: read a public or private key from file

    // RSA OPERATIONS
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char *pri_key;           // Private key
    char *pub_key;           // Public key
    char msg[KEY_LENGTH/8];
    char err[ERR_SIZE];      // Buffer for any error messages (130 by openssl specs)

    // To get the PEM RSA data structure in memory
    // NOTE: in alternative use a non-bio version of functions to stdout to print the keys
    BIO *pri_bio = BIO_new(BIO_s_mem());
    BIO *pub_bio = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri_bio, key_pair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub_bio, key_pair);

    pri_len = BIO_pending(pri_bio);
    pub_len = BIO_pending(pub_bio);
    //count the character actually written into the BIO object
    printf("pri_len = %d\npub_len = %d\n", pri_len, pub_len);

    // allocate a standard string
    pri_key = (char*)malloc(pri_len + 1); //room for the '\0'
    pub_key = (char*)malloc(pub_len + 1); //room for the '\0'

    BIO_read(pri_bio, pri_key, pri_len);
    BIO_read(pub_bio, pub_key, pub_len);
    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    printf("public key =\n%s\nprivate key =\n%s\n", pub_key, pri_key);

    printf("Insert the message to encrypt: ");
    fgets(msg, KEY_LENGTH-1, stdin);
    msg[strlen(msg)-1] = '\0';

    char *encrypted_data = NULL;    // Encrypted message
    int encrypted_data_len;
    encrypted_data = malloc(RSA_size(key_pair));

    /*
    int RSA_public_encrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
    RSA_public_encrypt() returns the size of the encrypted data (i.e.,
    RSA_size(rsa)). RSA_private_decrypt() returns the size of the recovered
    plaintext. A return value of 0 is not an error and means only that the plaintext was empty.
    On error, -1 is returned; the error codes can be obtained by ERR_get_error(3).
    */

    if((encrypted_data_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg,
                                                (unsigned char*)encrypted_data,
                                                key_pair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
        exit(1);
    }
    FILE *out = fopen("out.bin", "w");
    //size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
    //sizeof(*encrypted_data) = sizeof(char) = 1 byte
    fwrite(encrypted_data, sizeof(*encrypted_data),  RSA_size(key_pair), out);
    fclose(out);
    printf("Encrypted message written to file.\n");
    free(encrypted_data);
    encrypted_data = NULL;

    /*****************************************************************************/

    printf("Reading encrypted message and attempting decryption...\n");
    encrypted_data = (char*)malloc(RSA_size(key_pair));
    out = fopen("out.bin", "r");
    fread(encrypted_data, sizeof(*encrypted_data), RSA_size(key_pair), out);
    fclose(out);

    // Decrypt it
    char *decrypted_data;    // Decrypted message
    decrypted_data = (char*)malloc(encrypted_data_len);

    /*
        int RSA_private_decrypt(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding);
        Error management is the same and the _encrypt function
    */

    if(RSA_private_decrypt(encrypted_data_len, (unsigned char*)encrypted_data,
                           (unsigned char*)decrypted_data,
                           key_pair, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
        exit(1);
    }
    printf("Decrypted message: %s\n", decrypted_data);

    BIO_free_all(bp_private);
    RSA_free(key_pair);
    BN_free(bne);
    return 0;
}
