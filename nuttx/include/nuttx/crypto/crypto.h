/****************************************************************************
 * include/nuttx/crypto/crypto.h
 *
 *   Copyright (C) 2014 Gregory Nutt. All rights reserved.
 *   Author:  Sebastien Lorquet <sebastien@lorquet.fr>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

#ifndef __INCLUDE_NUTTX_CRYPTO_CRYPTO_H
#define __INCLUDE_NUTTX_CRYPTO_CRYPTO_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <debug.h>

/****************************************************************************
 * Pre-Processor Definitions
 ****************************************************************************/

#define CRYPTO_MODULE_FLAG_NEEDPIN    0x00000001
#define CRYPTO_MODULE_FLAG_ISHW       0x00000002

#define CRYPTO_CONTEXT_FLAG_READONLY 0x00000001
#define CRYPTO_CONTEXT_FLAG_ADMIN    0x00000002

#define CRYPTO_ALG_PARAM_IV         0x00000001

#define CRYPTO_KEY_FIND_NAME         1
#define CRYPTO_KEY_FIND_INDEX        2

#define CRYPTO_KEY_FLAG_TOKEN        0x00000001
#define CRYPTO_KEY_FLAG_ENCIPHER     0x00000002
#define CRYPTO_KEY_FLAG_DECIPHER     0x00000004
#define CRYPTO_KEY_FLAG_SIGN         0x00000008
#define CRYPTO_KEY_FLAG_VERIFY       0x00000010
#define CRYPTO_KEY_FLAG_DERIVE       0x00000020
#define CRYPTO_KEY_FLAG_WRAP         0x00000040
#define CRYPTO_KEY_FLAG_UNWRAP       0x00000080
#define CRYPTO_KEY_FLAG_EXTRACT      0x00000100

#define CRYPTO_KEY_COMPONENT_MAIN    0
#define CRYPTO_KEY_COMPONENT_MOD     1
#define CRYPTO_KEY_COMPONENT_EXP     2

#define CRYPTO_CIPHER_FLAG_ENCIPHER  0x00000001
#define CRYPTO_CIPHER_FLAG_DECIPHER  0x00000002
#define CRYPTO_DS_FLAG_SIGN          0x00000001
#define CRYPTO_DS_FLAG_VERIFY        0x00000002

/****************************************************************************
 * Types
 ****************************************************************************/

 #ifndef __ASSEMBLY__

struct crypto_token_info_s {
    char     name[16];
    uint32_t flags;
    uint32_t nkeys_used;
    uint32_t nkeys_free;
    uint32_t nmechs;
};

struct crypto_context_info_s {
    uint32_t module_id;
    uint32_t flags;
    uint32_t nkeys_used;
    uint32_t nkeys_free;
};

struct crypto_alg_info_s {
    uint32_t alg_id;
    uint32_t required_params;
};

struct crypto_key_info_s {
    char     name[16];
    uint32_t flags;
    uint32_t key_length;
};

/************************************************************************************
 * Public Data
 ************************************************************************************/

#undef EXTERN
#if defined(__cplusplus)
#define EXTERN extern "C"
extern "C"
{
#else
#define EXTERN extern
#endif

/************************************************************************************
 * Public Function Prototypes
 ************************************************************************************/

int crypto_module_count(void);
int crypto_module_info(int token_id, struct crypto_token_info_s *info);

int crypto_context_open(int token_id, uint32_t flags, char *pin);
int crypto_context_close(int context_id);
int crypto_context_info(int context_id, struct crypto_context_info_s *sess);

int crypto_alg_info(int token, int mech, struct crypto_alg_info_s *info);
const char *crypto_alg_name(int mech_id);
int crypto_alg_setparam(int context_id, uint32_t param, int len, uint8_t *value);

int crypto_key_find(int context_id, uint32_t flags, int index, const char *label);
int crypto_key_info(int context_id, int key_id, struct crypto_key_info_s *info);
int crypto_key_create(int context_id, uint32_t flags, const char *label);
int crypto_key_delete(int context_id, int key_id);
int crypto_key_setvalue(int context_id, int key_id, int component, int length, uint8_t *value);
int crypto_key_transfer(int context_id, int key_id, const char *label);

int crypto_cipher_init(int context_id, int key_id, uint32_t flags);
int crypto_cipher_update(int context_id, int len, uint8_t* in, uint8_t *out);
int crypto_cipher_final(int context_id, int inlen, uint8_t *in, int* outlen, uint8_t *out);

int crypto_ds_init(int context_id, int mech_id, int key_id, uint32_t flags);
int crypto_ds_update(int context_id, int len, uint8_t* data);
int crypto_ds_final(int context_id, int *siglen, uint8_t *sig);

int crypto_hash_init(int context_id, int mech_id);
int crypto_hash_update(int context_id, int len, uint8_t* data);
int crypto_hash_final(int context_id, int* hashlen, uint8_t* hash);

int crypto_derive(int context_id, int mech_id, int orig_key_id, int deriv_data_len, uint8_t* deriv_data, uint32_t new_key_flags);

int crypto_wrap(int context_id, int mech_id, int key_id, int wrap_key_id, int *wrapped_len, uint8_t* wrapped);
int crypto_unwrap(int context_id, int mech_id, int wrapped_len, uint8_t* wrapped_data, int wrap_key_id, uint32_t new_key_flags);

int crypto_random_generate(int context_id, int len, uint8_t *data);

#undef EXTERN
#if defined(__cplusplus)
}
#endif

#endif /* __ASSEMBLY__ */
#endif /* __INCLUDE_NUTTX_CRYPTO_CRYPTO_H */
