/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : https://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : https://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "argon2.h"
#include "core.h"

#define OUT_LEN 32
#define ENCODED_LEN 108

int argon2_ctx(argon2_context *context) {
    /* 1. Validate all inputs */
    int result = validate_inputs(context);
    uint32_t memory_blocks, segment_length;
    argon2_instance_t instance;

    if (ARGON2_OK != result) {
        return result;
    }

    /* 2. Align memory size */
    /* Minimum memory_blocks = 8L blocks, where L is the number of lanes */
    memory_blocks = context->m_cost;

    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    }

    segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    /* Ensure that all segments have equal length */
    memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);

    instance.version = context->version;
    instance.memory = NULL;
    instance.passes = context->t_cost;
    instance.memory_blocks = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context->lanes;
    instance.threads = context->threads;

    if (instance.threads > instance.lanes) {
        instance.threads = instance.lanes;
    }

    /* 3. Initialization: Hashing inputs, allocating memory, filling first
     * blocks
     */
    result = initialize(&instance, context);

    if (ARGON2_OK != result) {
        return result;
    }

    /* 4. Filling memory */
    result = fill_memory_blocks(&instance);

    if (ARGON2_OK != result) {
        return result;
    }
    /* 5. Finalization */
    finalize(context, &instance);

    return ARGON2_OK;
}



int argon2_hash_without_encoding(const uint32_t t_cost, const uint32_t m_cost,
                const uint32_t parallelism, const void *pwd,
                const size_t pwdlen, const void *salt, const size_t saltlen,
                void *hash, const size_t hashlen, const uint32_t version){

    argon2_context context;
    int result;
    uint8_t *out;

    if (pwdlen > ARGON2_MAX_PWD_LENGTH) {
        return ARGON2_PWD_TOO_LONG;
    }

    if (saltlen > ARGON2_MAX_SALT_LENGTH) {
        return ARGON2_SALT_TOO_LONG;
    }

    if (hashlen > ARGON2_MAX_OUTLEN) {
        return ARGON2_OUTPUT_TOO_LONG;
    }

    if (hashlen < ARGON2_MIN_OUTLEN) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }

    out = malloc(hashlen);
    if (!out) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    context.out = (uint8_t *)out;
    context.outlen = (uint32_t)hashlen;
    context.pwd = CONST_CAST(uint8_t *)pwd;
    context.pwdlen = (uint32_t)pwdlen;
    context.salt = CONST_CAST(uint8_t *)salt;
    context.saltlen = (uint32_t)saltlen;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = parallelism;
    context.threads = parallelism;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;
    context.version = version;

    result = argon2_ctx(&context);

    if (result != ARGON2_OK) {
        clear_internal_memory(out, hashlen);
        free(out);
        return result;
    }

    /* if raw hash requested, write it */
    if (hash) {
        memcpy(hash, out, hashlen);
    }

    /* if encoding requested, write it */
    clear_internal_memory(out, hashlen);
    free(out);

    return ARGON2_OK;
}

const char *argon2_error_message(int error_code) {
    switch (error_code) {
    case ARGON2_OK:
        return "OK";
    case ARGON2_OUTPUT_PTR_NULL:
        return "Output pointer is NULL";
    case ARGON2_OUTPUT_TOO_SHORT:
        return "Output is too short";
    case ARGON2_OUTPUT_TOO_LONG:
        return "Output is too long";
    case ARGON2_PWD_TOO_SHORT:
        return "Password is too short";
    case ARGON2_PWD_TOO_LONG:
        return "Password is too long";
    case ARGON2_SALT_TOO_SHORT:
        return "Salt is too short";
    case ARGON2_SALT_TOO_LONG:
        return "Salt is too long";
    case ARGON2_AD_TOO_SHORT:
        return "Associated data is too short";
    case ARGON2_AD_TOO_LONG:
        return "Associated data is too long";
    case ARGON2_SECRET_TOO_SHORT:
        return "Secret is too short";
    case ARGON2_SECRET_TOO_LONG:
        return "Secret is too long";
    case ARGON2_TIME_TOO_SMALL:
        return "Time cost is too small";
    case ARGON2_TIME_TOO_LARGE:
        return "Time cost is too large";
    case ARGON2_MEMORY_TOO_LITTLE:
        return "Memory cost is too small";
    case ARGON2_MEMORY_TOO_MUCH:
        return "Memory cost is too large";
    case ARGON2_LANES_TOO_FEW:
        return "Too few lanes";
    case ARGON2_LANES_TOO_MANY:
        return "Too many lanes";
    case ARGON2_PWD_PTR_MISMATCH:
        return "Password pointer is NULL, but password length is not 0";
    case ARGON2_SALT_PTR_MISMATCH:
        return "Salt pointer is NULL, but salt length is not 0";
    case ARGON2_SECRET_PTR_MISMATCH:
        return "Secret pointer is NULL, but secret length is not 0";
    case ARGON2_AD_PTR_MISMATCH:
        return "Associated data pointer is NULL, but ad length is not 0";
    case ARGON2_MEMORY_ALLOCATION_ERROR:
        return "Memory allocation error";
    case ARGON2_FREE_MEMORY_CBK_NULL:
        return "The free memory callback is NULL";
    case ARGON2_ALLOCATE_MEMORY_CBK_NULL:
        return "The allocate memory callback is NULL";
    case ARGON2_INCORRECT_PARAMETER:
        return "Argon2_Context context is NULL";
    case ARGON2_INCORRECT_TYPE:
        return "There is no such version of Argon2";
    case ARGON2_OUT_PTR_MISMATCH:
        return "Output pointer mismatch";
    case ARGON2_THREADS_TOO_FEW:
        return "Not enough threads";
    case ARGON2_THREADS_TOO_MANY:
        return "Too many threads";
    case ARGON2_MISSING_ARGS:
        return "Missing arguments";
    case ARGON2_ENCODING_FAIL:
        return "Encoding failed";
    case ARGON2_DECODING_FAIL:
        return "Decoding failed";
    case ARGON2_THREAD_FAIL:
        return "Threading failure";
    case ARGON2_DECODING_LENGTH_FAIL:
        return "Some of encoded parameters are too long or too short";
    case ARGON2_VERIFY_MISMATCH:
        return "The password does not match the supplied hash";
    default:
        return "Unknown error code";
    }
}


int argon2_test(){

    unsigned char out[OUT_LEN];
    int version = ARGON2_VERSION_10;
    int ret = argon2_hash_without_encoding(2, 1 << 16, 1, "password", strlen("password"), "somesalt", strlen("somesalt"), out, 32, version);
    unsigned char correct_out_1[OUT_LEN] = {0xf6, 0xc4, 0xdb, 0x4a, 0x54, 0xe2, 0xa3, 0x70, 0x62, 0x7a,
                                          0xff, 0x3d, 0xb6, 0x17, 0x6b, 0x94, 0xa2, 0xa2, 0x09, 0xa6,
                                          0x2c, 0x8e, 0x36, 0x15, 0x27, 0x11, 0x80, 0x2f, 0x7b, 0x30, 0xc6, 0x94};

    if(ret != ARGON2_OK)
        return -1;

    for(int i = 0; i < 32; i++)
        if(correct_out_1[i] != out[i])
            return -1;

    /*
    unsigned char correct_out_2[OUT_LEN] = {0x3e, 0x68, 0x9a, 0xaa, 0x3d, 0x28, 0xa7, 0x7c, 0xf2, 0xbc,
                                            0x72, 0xa5, 0x1a, 0xc5, 0x31, 0x66, 0x76, 0x17, 0x51, 0x18,
                                            0x2f, 0x1e, 0xe2, 0x92, 0xe3, 0xf6, 0x77, 0xa7, 0xda, 0x4c, 0x24, 0x67};

    ret = argon2_hash_without_encoding(2, 1 << 18, 1, "password", strlen("password"), "somesalt", strlen("somesalt"), out, 32, version);
    if(ret != ARGON2_OK)
        return -1;

    for(int i = 0; i < 32; i++)
        if(correct_out_2[i] != out[i])
            return -1;
    */

    unsigned char correct_out_2[OUT_LEN] = {0xfd, 0x4d, 0xd8, 0x3d, 0x76, 0x2c, 0x49, 0xbd, 0xea, 0xf5,
                                            0x7c, 0x47, 0xbd, 0xcd, 0x0c, 0x2f, 0x1b, 0xab, 0xf8, 0x63,
                                            0xfd, 0xeb, 0x49, 0x0d, 0xf6, 0x3e, 0xde, 0x99, 0x75, 0xfc, 0xcf, 0x06};

    ret = argon2_hash_without_encoding(2, 1 << 8, 1, "password", strlen("password"), "somesalt", strlen("somesalt"), out, 32, version);
    if(ret != ARGON2_OK)
        return -1;

    for(int i = 0; i < 32; i++)
        if(correct_out_2[i] != out[i])
            return -1;

    unsigned char correct_out_3[OUT_LEN] = {0x81, 0x63, 0x05, 0x52, 0xb8, 0xf3, 0xb1, 0xf4, 0x8c, 0xdb,
                                            0x19, 0x92, 0xc4, 0xc6, 0x78, 0x64, 0x3d, 0x49, 0x0b, 0x2b,
                                            0x5e, 0xb4, 0xff, 0x6c, 0x4b, 0x34, 0x38, 0xb5, 0x62, 0x17, 0x24, 0xb2};
    ret = argon2_hash_without_encoding(1, 1 << 16, 1, "password", strlen("password"), "somesalt", strlen("somesalt"), out, 32, version);
    if(ret != ARGON2_OK)
        return -1;

    for(int i = 0; i < 32; i++)
        if(correct_out_3[i] != out[i])
            return -1;

    unsigned char correct_out_4[OUT_LEN] = {0xe9, 0xc9, 0x02, 0x07, 0x4b, 0x67, 0x54, 0x53, 0x1a, 0x3a,
                                            0x0b, 0xe5, 0x19, 0xe5, 0xba, 0xf4, 0x04, 0xb3, 0x0c, 0xe6,
                                            0x9b, 0x3f, 0x01, 0xac, 0x3b, 0xf2, 0x12, 0x29, 0x96, 0x01, 0x09, 0xa3};
    ret = argon2_hash_without_encoding(2, 1 << 16, 1, "differentpassword", strlen("differentpassword"), "somesalt", strlen("somesalt"), out, 32, version);
    if(ret != ARGON2_OK)
        return -1;

    for(int i = 0; i < 32; i++)
        if(correct_out_4[i] != out[i])
            return -1;

    unsigned char correct_out_5[OUT_LEN] = {0x79, 0xa1, 0x03, 0xb9, 0x0f, 0xe8, 0xae, 0xf8, 0x57, 0x0c,
                                            0xb3, 0x1f, 0xc8, 0xb2, 0x22, 0x59, 0x77, 0x89, 0x16, 0xf8,
                                            0x33, 0x6b, 0x7b, 0xda, 0xc3, 0x89, 0x25, 0x69, 0xd4, 0xf1, 0xc4, 0x97};
    ret = argon2_hash_without_encoding(2, 1 << 16, 1, "password", strlen("password"), "diffsalt", strlen("diffsalt"), out, 32, version);
    if(ret != ARGON2_OK)
        return -1;

    for(int i = 0; i < 32; i++)
        if(correct_out_5[i] != out[i])
            return -1;

    return 0;



}





























