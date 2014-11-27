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

/* user interface to the crypto api */

#ifndef __INCLUDE_NUTTX_CRYPTO_CRYPTO_H
#define __INCLUDE_NUTTX_CRYPTO_CRYPTO_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

/****************************************************************************
 * Pre-Processor Definitions
 ****************************************************************************/

#define CRYPTO_MODULE_FLAG_ISHW      0x00000001
#define CRYPTO_MODULE_FLAG_NEEDPIN   0x00000002
#define CRYPTO_MODULE_FLAG_NEEDMAUTH 0x00000004

#define CRYPTO_CONTEXT_FLAG_READONLY 0x00000001
#define CRYPTO_CONTEXT_FLAG_ADMIN    0x00000002

#define CRYPTO_CONTEXT_AUTH_STEP_PIN 0

#define CRYPTO_ALG_PARAM_IV          0x00000001
#define CRYPTO_ALG_PARAM_CRC_POLY    0x00000002
#define CRYPTO_ALG_PARAM_CRC_INITVAL 0x00000004

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

struct crypto_module_info_s
{
    char     name[16];
    uint32_t flags;
    uint32_t nkeysused;
    uint32_t nkeysfree;
    uint32_t nmechs;
};

struct crypto_context_info_s
{
    uint32_t moduleid;
    uint32_t flags;
    uint32_t nkeysused;
    uint32_t nkeysfree;
};

struct crypto_alg_info_s
{
    uint32_t algid;
    uint32_t requiredparams;
};

struct crypto_key_info_s
{
    char     name[16];
    uint32_t flags;
    uint32_t keylength;
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

int crypto_init(void);
int crypto_init_fd(int fd);
int crypto_close(void);

int crypto_module_initfind(void **enum);
int crypto_module_find(int contextid, void **enum, struct crypto_module_info_s *info);

int crypto_context_open(int moduleid, uint32_t flags);
int crypto_context_auth(int contextid, int step, int indatalen, FAR uint8_t *indata, FAR int *outdatalen, FAR uint8_t *outdata);
int crypto_context_close(int contextid);
int crypto_context_info(int contextid, FAR struct crypto_context_info_s *ctxt);

int crypto_alg_info(int token, int mech, FAR struct crypto_alg_info_s *info);
FAR const char *crypto_alg_name(int algid);
int crypto_alg_setparam(int contextid, uint32_t param, int len, FAR uint8_t *value);

int crypto_key_find(int contextid, uint32_t flags, int index, FAR const char *label);
int crypto_key_info(int contextid, int keyid, FAR struct crypto_key_info_s *info);
int crypto_key_create(int contextid, uint32_t flags, FAR const char *label);
int crypto_key_delete(int contextid, int keyid);
int crypto_key_setvalue(int contextid, int keyid, int component, int length, FAR uint8_t *value);
int crypto_key_transfer(int contextid, int keyid, FAR const char *label);

int crypto_cipher_init(int contextid, int algid, int keyid, uint32_t flags);
int crypto_cipher_update(int contextid, int len, FAR uint8_t *in, FAR uint8_t *out);
int crypto_cipher_final(int contextid, int inlen, FAR uint8_t *in, FAR int *outlen, FAR uint8_t *out);

int crypto_ds_init(int contextid, int algid, int keyid, uint32_t flags);
int crypto_ds_update(int contextid, int len, FAR uint8_t *data);
int crypto_ds_final(int contextid, FAR int *siglen, FAR uint8_t *sig);

int crypto_hash_init(int contextid, int algid);
int crypto_hash_update(int contextid, int len, FAR uint8_t *data);
int crypto_hash_final(int contextid, FAR int *hashlen, FAR uint8_t *hash);

int crypto_derive(int contextid, int algid, int origkeyid, int derivdatalen, FAR uint8_t *derivdata, uint32_t newkeyflags);

int crypto_wrap(int contextid, int algid, int keyid, int wrapkeyid, FAR int *wrappedlen, FAR uint8_t *wrapped);
int crypto_unwrap(int contextid, int algid, int wrappedlen, FAR uint8_t *wrappeddata, int wrapkeyid, uint32_t newkeyflags);

int crypto_random_generate(int contextid, int len, FAR uint8_t *data);

#undef EXTERN
#if defined(__cplusplus)
}
#endif

#endif /* __ASSEMBLY__ */
#endif /* __INCLUDE_NUTTX_CRYPTO_CRYPTO_H */
