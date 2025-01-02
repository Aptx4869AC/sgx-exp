#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>
#include <sgx_trts.h>
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "tSgxSSL_api.h"
#include <vector>
#include <cstdio>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <pbc_sgx/pbc.h>
#include <string.h>

int printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int) strnlen(buf, BUFSIZ - 1) + 1;
}

// element_t -> string
void serl(unsigned char **str, size_t *count, element_t e) {
    printf("element_t serialization\n");
    unsigned char *pointer = *str;
    element_to_bytes(pointer, e);
}

// string -> element_t
void deserl(element_t e, unsigned char *str, size_t count) {
    printf("element_t de-serialization\n");
    element_from_bytes(e, str);
}

void step_1(unsigned char **element_str, size_t *element_str_count) {
    pairing_t pairing;
    element_t sk, pk, signature, h, g;
    char message[] = "Hello, world!";

    // Initialize pairing
    char param_str[] = "type a \n"
                       "q 40132934874065581357639239301938089130039744463472639389591743372055069245229811691989086088125328594220615378634210894681862132537783020759006156856256486760853214375759294871087842511098137328669742901944483362556170153388301818039153709502326627974456159915072198235053718093631308481607762634120235579251 \n"
                       "h 5986502056676971303894401875152023968506744561211054886102595589603460071084910131070137261543726329935522867827513637124526300709663875599084261056444276 \n"
                       "r 6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941560715789883889358865432577 \n"
                       "exp2 511 \n"
                       "exp1 87 \n"
                       "sign1 1 \n"
                       "sign0 1";

    pbc_param_t par;
    pbc_param_init_set_str(par, param_str);
    pairing_init_pbc_param(pairing, par);

    // Initialize elements
    element_init_Zr(sk, pairing);
    element_init_G1(signature, pairing);
    element_init_G1(h, pairing);
    element_init_G1(g, pairing);
    element_init_G1(pk, pairing);

    // Generate data
    uint32_t random_value;
    sgx_read_rand((uint8_t*)&random_value, sizeof(random_value));
    gmp_randstate_t gmp_rand;
    gmp_randinit_default(gmp_rand);
    gmp_randseed_ui(gmp_rand, (unsigned long int) random_value);
    mpz_t data;
    mpz_init(data);
    mpz_rrandomb(data, gmp_rand, 64);
    element_set_mpz(sk, data);
    // element_random(sk); // x, 存在bug，sgx中不会改变，即是同一个值
    element_random(g);


    // Generate signature
    element_from_hash(h, message, strlen(message));
    element_pow_zn(signature, h, sk); // h^x
    element_pow_zn(pk, g, sk); // g^x

    // Verify signature
    element_t e1, e2;
    element_init_GT(e1, pairing);
    element_init_GT(e2, pairing);

    pairing_apply(e1, signature, g, pairing); // e(signature,g)
    pairing_apply(e2, h, pk, pairing);       // e(h,g^x)

    if (element_cmp(e1, e2) == 0) {
        printf("Signature verified successfully.\n");
    } else {
        printf("Failed to verify signature.\n");
    }

    serl(element_str, element_str_count, sk);

//    // Clear elements
//    element_clear(e1);
//    element_clear(e2);
//    element_clear(sk);
//    element_clear(pk);
//    element_clear(signature);
//    element_clear(h);
//    element_clear(g);
//    pairing_clear(pairing);
}





