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

void exercise_1()
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

void exercise_2()
{
    // Exercise 2.
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *msg = BN_new();
    BIGNUM *encrypted = BN_new();

    // M = A top secret!

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&msg, "4120746f702073656372657421");

    // Encryption (msg ^ e) % n
    BN_mod_exp(encrypted, msg, e, n, ctx);
    printBN("Encrypted msg", encrypted);

    BN_CTX_free(ctx);
}

void exercise_3()
{
    // Exercise 3.
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *C = BN_new();
    BIGNUM *decrypted = BN_new();

    // M = A top secret!

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&C, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    // Decryption m = (c ^ d) % n
    BN_mod_exp(decrypted, C, d, n, ctx);
    printBN("Decrypted msg", decrypted);
    // result after convert is Password is dees

    BN_CTX_free(ctx);
}

int main()
{
    exercise_1();
    exercise_2();
    exercise_3();
}