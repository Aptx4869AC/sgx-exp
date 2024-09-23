#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <mcl/include/mcl/bn_c384_256.h>

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

int g_err = 0;
#define ASSERT(x) { if (!(x)) { printf("err %s:%d\n", __FILE__, __LINE__); g_err++; } }

void Hash(mclBnG1 *P, const unsigned char *m, size_t len)
{
    mclBnFp t;
    int ret = mclBnFp_setHashOf(&t, m, len);
    if (ret != 0)
    {
        printf("err ret=%d\n", ret);
    }
    mclBnFp_mapToG1(P, &t);  // 使用正确的函数将哈希映射到 G1
}

void KeyGen(mclBnFr *s, mclBnG2 *pub, mclBnG2 *Q)
{
//    mclBnFr_setByCSPRNG(s);  // 生成随机私钥，得要找替换的
    mclBnG2_mul(pub, Q, s);  // pub = sQ
}

void Sign(mclBnG1 *sign, const mclBnFr *s, const unsigned char* m, size_t len)
{
    mclBnG1 Hm;
    Hash(&Hm, m, len);
    mclBnG1_mul(sign, &Hm, s); // sign = s H(m)
}

int Verify(const mclBnG1 *sign, const mclBnG2 *Q, const mclBnG2 *pub, const unsigned char* m, size_t len)
{
    mclBnGT e1, e2;
    mclBnG1 Hm;
    Hash(&Hm, m, len);
    mclBn_pairing(&e1, sign, Q);  // e1 = e(sign, Q)
    mclBn_pairing(&e2, &Hm, pub); // e2 = e(Hm, sQ)
    return mclBnGT_isEqual(&e1, &e2);
}


void ocall_test()
{
    printf("This is a test message.\n");
}

void pair_test()
{

    printf("[Enclave] pair_test begin\n");
    char buf[1600];
    const char *aStr = "123";
    const char *bStr = "456";
    int ret = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (ret != 0) {
        printf("err ret=%d\n", ret);
    }
    mclBnFr a, b, ab;
    mclBnG1 P, aP;
    mclBnG2 Q, bQ;
    mclBnGT e, e1, e2;
    mclBnFr_setStr(&a, aStr, strlen(aStr), 10);
    mclBnFr_setStr(&b, bStr, strlen(bStr), 10);
    mclBnFr_mul(&ab, &a, &b);
    mclBnFr_getStr(buf, sizeof(buf), &ab, 10);
    printf("%s x %s = %s\n", aStr, bStr, buf);
    mclBnFr_sub(&a, &a, &b);
    mclBnFr_getStr(buf, sizeof(buf), &a, 10);
    printf("%s - %s = %s\n", aStr, bStr, buf);

    ASSERT(!mclBnG1_hashAndMapTo(&P, "this", 4));
    ASSERT(!mclBnG2_hashAndMapTo(&Q, "that", 4));
    ASSERT(mclBnG1_getStr(buf, sizeof(buf), &P, 16));
    printf("P = %s\n", buf);
    ASSERT(mclBnG2_getStr(buf, sizeof(buf), &Q, 16));
    printf("Q = %s\n", buf);

    mclBnG1_mul(&aP, &P, &a);
    mclBnG2_mul(&bQ, &Q, &b);

    mclBn_pairing(&e, &P, &Q);
    ASSERT(mclBnGT_getStr(buf, sizeof(buf), &e, 16));
    printf("e = %s\n", buf);
    mclBnGT_pow(&e1, &e, &a);
    mclBn_pairing(&e2, &aP, &Q);
    ASSERT(mclBnGT_isEqual(&e1, &e2));

    mclBnGT_pow(&e1, &e, &b);
    mclBn_pairing(&e2, &P, &bQ);
    ASSERT(mclBnGT_isEqual(&e1, &e2));
    if (g_err) {
        printf("err %d\n", g_err);
    } else {
        printf("no err\n");
    }
    printf("[Enclave] pair_test end\n");
}

void bls_test()
{
    printf("[Enclave] bls_test begin\n");

    char buf[1600];
    const unsigned char *m = (unsigned char*)"aptx4869";
    size_t m_len = strlen((const char*)m);
    printf("msg: %s\n", m);

    int ret = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (ret != 0) {
        printf("err ret=%d\n", ret);
    }

    mclBnG2 Q;
    mclBnFr s;
    mclBnG2 pub;
    mclBnG1 sign;

    const char *Str = "48691412";
    mclBnG2_hashAndMapTo(&Q, "Q_seed", 6);  // 对 Q 进行哈希映射初始化
    mclBnFr_setStr(&s, Str, strlen(Str), 10);

    // 生成密钥对
    KeyGen(&s, &pub, &Q);

    // 打印私钥
    mclBnFr_getStr(buf, sizeof(buf), &s, 16);
    printf("secret key = %s\n", buf);

    // 打印公钥
    mclBnG2_getStr(buf, sizeof(buf), &pub, 16);
    printf("public key = %s\n", buf);

    // 签名
    Sign(&sign, &s, m, m_len);

    // 打印签名
    mclBnG1_getStr(buf, sizeof(buf), &sign, 16);
    printf("signature = %s\n", buf);

    // 验证
    int ok = Verify(&sign, &Q, &pub, m, m_len);
    printf("verify: %s\n", ok ? "ok" : "no");
    printf("[Enclave] bls_test end\n");
}

