#include <stdio.h>
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a)
{
    char *number_str = BN_bn2hex(a);
    printf("%s 0x%s\n", msg, number_str);
    OPENSSL_free(number_str);
}

BIGNUM *make_rsa_private_key(BIGNUM *p, BIGNUM *q, BIGNUM *e)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *q_1 = BN_new();
    BIGNUM *p_1 = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *res = BN_new();

    BIGNUM *n = BN_new();
    BIGNUM *phi = BN_new();
    BN_dec2bn(&one, "1");

    // Calculate n = p*q
    BN_mul(n, p, q, ctx);

    // Calculate Phi
    BN_sub(p_1, p, one);
    BN_sub(q_1, q, one);
    BN_mul(phi, p_1, q_1, ctx);
    BN_mod_inverse(res, e, phi, ctx);
    // Find

    BN_CTX_free(ctx);
    return res;
}

int main()
{
    // Exercise 1.
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();

    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    BIGNUM *private_key = make_rsa_private_key(p, q, e);

    printBN("RSA Private Key", private_key);

    BN_CTX_free(ctx);
}