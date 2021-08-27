#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/applink.c>
#include <openssl/err.h>

int main() {
    BIGNUM *b1 = BN_new();
    BIGNUM *b2 = BN_new();
    BIGNUM *b3 = BN_new();

    printf("b1 after the creation is equal to "); // = 0
    BN_print_fp(stdout, b1);
    printf("\n");
    BN_set_word(b1, 250);
    printf("b1 after the initialization is equal to "); // = 250 (FA)
    BN_print_fp(stdout, b1);
    printf("\n");

    BN_set_word(b2, 80);
    BN_CTX *ctx = BN_CTX_new();
    BN_mod(b3, b1, b2, ctx); //compute the reminder between b1 and b2 and save the result in b3
    printf("the reminder between b1 and b2 is "); // = 250 (FA)
    BN_print_fp(stdout, b3);
    printf("\n");

    char num_string[] = "123456789012345678901234567890123456789012345678901234567890";
    BIGNUM *dec = BN_new();
    BN_dec2bn(&dec, num_string);
    printf("hex bignum: %s\n", BN_bn2hex(dec));
    printf("dec bignum: %s\n", BN_bn2dec(dec));

    // for all functions 1 is returned if success, otherwise 0
    BN_add(b3, b1, b2); //in b3 the result
    BN_div(b3, dec, b1, b2, ctx); //in b3 the result and in dec the reminder
    if (!BN_mod_exp(b3,b1,b2,dec,ctx)) { //b3 = b1^b2 mod dec
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    int cmp_result;
    cmp_result = BN_cmp(b1,b2);
    if(cmp_result == 0)
        printf("=\n");
    else if (cmp_result < 0)
        printf("<\n");
    else
        printf(">\n");

    BN_free(b1);
    BN_free(b2);
    BN_free(b3);
    BN_free(dec);
    BN_CTX_free(ctx);

    return 0;
}
