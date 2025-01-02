#include <iostream>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <pthread.h>
#include <cstdio>
#include <chrono>
#include <thread>
#include <omp.h>
#include <iomanip>
#include <pbc/pbc.h>

#include <sgx_urts.h>
#include "server.h"
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
                        "Invalid Intel® Software Guard Extensions device.",
                        "Please make sure Intel® Software Guard Extensions module is enabled in the BIOS, and install Intel® Software Guard Extensions driver afterwards."
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
                        "Intel® Software Guard Extensions device was busy.",
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
        printf("Error: Unexpected error occurred [0x%x].\n", ret);
}

/* Initialize the enclave:
 *   Step 1: retrive the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void) {
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    /* Step 1: retrive the launch token saved by last transaction */

    /* try to get the token saved in $HOME */
    char cwd[1024];
    const char *home_dir = getcwd(cwd, sizeof(cwd));
    if (home_dir != NULL &&
        (strlen(home_dir) + strlen("/") + sizeof(TOKEN_FILENAME) + 1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME) + 1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(token_path));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    printf("token_path: %s\n", token_path);
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }

    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);

    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);

        return -1;
    }

    /* Step 3: save the launch token if it is updated */

    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);

    return 0;
}


/* OCall functions */
void ocall_print_string(const char *str) {
    printf("%s", str);
}


// element_t -> string
void serl(unsigned char **str, size_t *count, element_t e) {
    printf("element_t serialization\n");
    *count = (size_t) element_length_in_bytes(e);
    *str = (unsigned char *) malloc(*count);
    element_to_bytes(*str, e);
}

// string -> element_t
void deserl(element_t e, unsigned char *str, size_t count) {
    printf("element_t de-serialization\n");
    element_from_bytes(e, str);
}

/* Application entry */
int main(int argc, char **argv) {
    (void) (argc);
    (void) (argv);

    /* Changing dir to where the executable is.*/
    char absolutePath[MAX_PATH];
    char *ptr = NULL;

    ptr = realpath(dirname(argv[0]), absolutePath);

    if (ptr == NULL || chdir(absolutePath) != 0)
        return 1;

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
        return 1;


    // Initialize pairing
    pairing_t pairing;
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

    element_t zr, g1, g2, gt;
    element_init_Zr(zr, pairing);
    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);
    element_init_GT(gt, pairing);
    element_random(zr);
    element_random(g1);
    element_random(g2);
    element_random(gt);
    element_printf("zr = %B\n", zr);
    element_printf("g1 = %B\n", g1);
    element_printf("g2 = %B\n", g2);
    element_printf("gt = %B\n", gt);
    // test
    unsigned char *gt_element_str;
    size_t gt_element_str_count;
    serl(&gt_element_str, &gt_element_str_count, gt);
    deserl(gt, gt_element_str, gt_element_str_count);
    element_printf("gt = %B\n", gt);

    size_t ZR_SIZE = element_length_in_bytes(zr);
    size_t G1_SIZE = element_length_in_bytes(g1);
    size_t G2_SIZE = element_length_in_bytes(g2);
    size_t GT_SIZE = element_length_in_bytes(gt);
    printf("G1:%ld\n", G1_SIZE);
    printf("G2:%ld\n", G2_SIZE);
    printf("GT:%ld\n", GT_SIZE);
    printf("Zr:%ld\n", ZR_SIZE);


    element_t data;
//    element_init_GT(data, pairing);
    element_init_Zr(data, pairing);
    size_t element_str_count = element_length_in_bytes(data);
    unsigned char *element_str = (unsigned char *) malloc(element_str_count);

    step_1(global_eid, &element_str, &element_str_count);
    deserl(data, element_str, element_str_count);
    printf("element_str_count = %d\n", element_str_count);
    element_printf("data = %B\n", data);

    // destroy Encalve
    sgx_destroy_enclave(global_eid);
    printf("Info: successfully returned.\n");
    return 0;

}

