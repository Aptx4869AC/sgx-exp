#include <iostream>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <pthread.h>
#include <cstdio>

#include <sgx_urts.h>
#include "App.h"
#include "Enclave_u.h"

#define MAX_PATH FILENAME_MAX
using namespace std;

sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] =
        {
                {
                        SGX_ERROR_UNEXPECTED,
                        "Unexpected error occurred.",
                        NULL
                },
                {
                        SGX_ERROR_INVALID_PARAMETER,
                        "Invalid parameter.",
                        NULL
                },
                {
                        SGX_ERROR_OUT_OF_MEMORY,
                        "Out of memory.",
                        NULL
                },
                {
                        SGX_ERROR_ENCLAVE_LOST,
                        "Power transition occurred.",
                        "Please refer to the sample \"PowerTransition\" for details."
                },
                {
                        SGX_ERROR_INVALID_ENCLAVE,
                        "Invalid enclave image.",
                        NULL
                },
                {
                        SGX_ERROR_INVALID_ENCLAVE_ID,
                        "Invalid enclave identification.",
                        NULL
                },
                {
                        SGX_ERROR_INVALID_SIGNATURE,
                        "Invalid enclave signature.",
                        NULL
                },
                {
                        SGX_ERROR_OUT_OF_EPC,
                        "Out of EPC memory.",
                        NULL
                },
                {
                        SGX_ERROR_NO_DEVICE,
                        "Invalid SGX device.",
                        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
                },
                {
                        SGX_ERROR_MEMORY_MAP_CONFLICT,
                        "Memory map conflicted.",
                        NULL
                },
                {
                        SGX_ERROR_INVALID_METADATA,
                        "Invalid enclave metadata.",
                        NULL
                },
                {
                        SGX_ERROR_DEVICE_BUSY,
                        "SGX device was busy.",
                        NULL
                },
                {
                        SGX_ERROR_INVALID_VERSION,
                        "Enclave version was invalid.",
                        NULL
                },
                {
                        SGX_ERROR_INVALID_ATTRIBUTE,
                        "Enclave was not authorized.",
                        NULL
                },
                {
                        SGX_ERROR_ENCLAVE_FILE_ACCESS,
                        "Can't open enclave file.",
                        NULL
                },
                {
                        SGX_ERROR_MEMORY_MAP_FAILURE,
                        "Failed to reserve memory for the enclave.",
                        NULL
                },
        };

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if (ret == sgx_errlist[idx].err) {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n",
               ret);
}

int initialize_enclave(void) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}


/* OCall functions */
void ocall_print_string(const char *str) {
    printf("%s", str);
}

/* Application entry */
int main(int argc, char **argv) {
    (void) (argc);
    (void) (argv);

    /* Initialize the enclave */
    if (initialize_enclave() < 0) {
        printf("Enter a character before exit ...\n");
        getchar();
    }
    

    step_1(global_eid);

    // destroy Encalve
    sgx_destroy_enclave(global_eid);
    printf("Info: successfully returned.\n");
    return 0;
}

