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

    // Private key
    BN_mod_inverse(res, e, phi, ctx);

    BN_CTX_free(ctx);
    return res;
}

// Use the public key to encrypt
BIGNUM *encrypt(BIGNUM *msg, BIGNUM *e, BIGNUM *n)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *encrypted = BN_new();
    BN_mod_exp(encrypted, msg, e, n, ctx);
    // printBN("Encrypted msg", encrypted);
    BN_CTX_free(ctx);
    return encrypted;
}

// Use the private key for decrypt
BIGNUM *decrypt(BIGNUM *cipher, BIGNUM *d, BIGNUM *n)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *decrypted = BN_new();
    BN_mod_exp(decrypted, cipher, d, n, ctx);
    // printBN("Decrypted msg", decrypted);
    BN_CTX_free(ctx);
    return decrypted;
}

// Use the private key for sign
BIGNUM *sign(BIGNUM *msg, BIGNUM *d, BIGNUM *n)
{
    // Sign don't have the same purpose  as
    // decryption, but the formula is the same
    // so we reuse the function
    return decrypt(msg, d, n);
}

// Use the public key to verify msg
int verify(BIGNUM *msg, BIGNUM *signature, BIGNUM *e, BIGNUM *n)
{
    BIGNUM *original_msg = encrypt(signature, e, n);
    printBN("omsg", original_msg);
    return BN_cmp(msg, original_msg) == 0 ? 1 : 0;
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

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&msg, "4120746f702073656372657421");

    BIGNUM *encrypted = encrypt(msg, e, n);

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

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&C, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    // Result after decrypt and convert from hex is Password is dees
    BIGNUM *decrypted = decrypt(C, d, n);

    BN_CTX_free(ctx);
}

void exercise_4()
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *msg = BN_new();

    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
    BN_hex2bn(&msg, "4D203D2049206F776520796F752024323030302E");

    BIGNUM *signature = sign(msg, d, n);
    printBN("signature", signature);

    BN_CTX_free(ctx);
}

void exercise_5()
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *M = BN_new();
    BN_hex2bn(&M, "4C61756E63682061206D697373696C652E"); // FIXME
    BIGNUM *S = BN_new();
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BIGNUM *e = BN_new();
    BN_hex2bn(&e, "010001");
    BIGNUM *n = BN_new();
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    int a = verify(M, S, e, n);
    printf("Verify result: %d\n", a);
    BN_CTX_free(ctx);
}

void exercise_6()
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *M = BN_new();
    BN_hex2bn(&M, "3012ff57fef748aca9e9ab8b4cd08de7eaced042e36c9e4c8ea29648f3b19f9d");
    BIGNUM *S = BN_new();
    BN_hex2bn(&S, "949ec4e67e35527e4859e89535ca04dd5ed6dd1bab8f8793d5a3ddc6f75f89c13dba5e5bbe987c2a628a4a0392abbf9ae98e4150df6beb59af9098a3a7c338725108152e582465ae537a68b38b0e57b7b19f94b7fb91d352ec9965753a7e588011ce7257ad42d09efae8636686580fd7a6baa67522231af12b843fe37d1bd52ac00b62b8fd37305511aeb65cf5c04a3b8218fcf2c0a24c271257ae56194c43bcddf87fa68be1125f8c673358302ec8fa1936103ebdebf97966801b5c0556e820f01251f1423649842f0a9d83a8920c79edfee1e9c9b4a2930947ea57b7fe4c6c3b3bd2b9ee3a9f0cfcd60d1c4fc51ebaa1369063be337aea2ec256b828f8f246");
    BIGNUM *e = BN_new();
    BN_hex2bn(&e, "10001");
    BIGNUM *n = BN_new();
    BN_hex2bn(&n, "bb021528ccf6a094d30f12ec8d5592c3f882f199a67a4288a75d26aab52bb9c54cb1af8e6bf975c8a3d70f4794145535578c9ea8a23919f5823c42a94e6ef53bc32edb8dc0b05cf35938e7edcf69f05a0b1bbec094242587fa3771b313e71cace19befdbe43b45524596a9c153ce34c852eeb5aeed8fde6070e2a554abb66d0e97a540346b2bd3bc66eb66347cfa6b8b8f572999f830175dba726ffb81c5add286583d17c7e709bbf12bf786dcc1da715dd446e3ccad25c188bc60677566b3f118f7a25ce653ff3a88b647a5ff1318ea9809773f9d53f9cf01e5f5a6701714af63a4ff99b3939ddc53a706fe48851da169ae2575bb13cc5203f5ed51a18bdb15");

    int a = verify(M, S, e, n);
    printf("Verify result: %d\n", a);

    printBN("The hash of certificate body", M);
    BN_CTX_free(ctx);
}

int main()
{
    exercise_1();
    exercise_2();
    exercise_3();
    exercise_4();
    exercise_5();
    exercise_6();
}