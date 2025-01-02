#include <iostream>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <../Enclave/mcl/include/mcl/bn_c384_256.h>
int g_err = 0;
#define ASSERT(x) { if (!(x)) { printf("err %s:%d\n", __FILE__, __LINE__); g_err++; } }

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t
{
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
        {
                SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL
        }, {
                SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL
        }, {
                SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL
        }, {
                SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.", "Please refer to the sample \"PowerTransition\" for details."
        }, {
                SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL
        }, {
                SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL
        }, {
                SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL
        }, {
                SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL
        }, {
                SGX_ERROR_NO_DEVICE, "Invalid SGX device.", "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
        }, {
                SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL
        }, {
                SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL
        }, {
                SGX_ERROR_DEVICE_BUSY, "SGX device was busy.", NULL
        }, {
                SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL
        }, {
                SGX_ERROR_INVALID_ATTRIBUTE, "Enclave was not authorized.", NULL
        }, {
                SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL
        }, {
                SGX_ERROR_MEMORY_MAP_FAILURE, "Failed to reserve memory for the enclave.", NULL
        },};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {
        if (ret == sgx_errlist[idx].err)
        {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

/* ECall functions */


/* Application entry */
int main(int argc, char *argv[])
{
    (void) (argc);
    (void) (argv);

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }


    printf("[App] pair_test begin\n");
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
    printf("[App] pair_test end\n");


    ocall_test(global_eid);
    pair_test(global_eid);
    bls_test(global_eid);


    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    printf("Info: exp successfully returned.\n");
    return 0;
}
