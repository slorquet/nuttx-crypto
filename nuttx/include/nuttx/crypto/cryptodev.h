/****************************************************************************
 * include/nuttx/crypto/cryptodev.h
 *
 *   Copyright (C) 2014 Gregory Nutt. All rights reserved.
 *   Author:  Max Nekludov <macscomp@gmail.com>
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

#ifndef __INCLUDE_NUTTX_CRYPTO_CRYPTODEV_H
#define __INCLUDE_NUTTX_CRYPTO_CRYPTODEV_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <stdint.h>

/****************************************************************************
 * Pre-Processor Definitions
 ****************************************************************************/

enum {
	CIOCRYPTO_MODULE_COUNT = 201,
	CIOCRYPTO_MODULE_INFO,
	CIOCRYPTO_CONTEXT_OPEN,
	CIOCRYPTO_CONTEXT_CLOSE,
	CIOCRYPTO_CONTEXT_INFO,
	CIOCRYPTO_ALG_INFO,
	CIOCRYPTO_ALG_SETPARAM,
	CIOCRYPTO_KEY_FIND,
	CIOCRYPTO_KEY_INFO,
	CIOCRYPTO_KEY_CREATE,
	CIOCRYPTO_KEY_DELETE,
	CIOCRYPTO_KEY_SETVALUE,
	CIOCRYPTO_KEY_TRANSFER,
	CIOCRYPTO_CIPHER_INIT,
	CIOCRYPTO_CIPHER_UPDATE,
	CIOCRYPTO_CIPHER_FINAL,
	CIOCRYPTO_DS_INIT,
	CIOCRYPTO_DS_UPDATE,
	CIOCRYPTO_DS_FINAL,
	CIOCRYPTO_HASH_INIT,
	CIOCRYPTO_HASH_UPDATE,
	CIOCRYPTO_HASH_FINAL,
	CIOCRYPTO_DERIVE,
	CIOCRYPTO_WRAP,
	CIOCRYPTO_UNWRAP,
	CIOCRYPTO_GEN_RANDOM,
};

struct cryptodev_module_info_s {
    //Request section
    int      module_index;
    //Response section
    char     label[16];
    uint32_t flags;
    int      nkeys_used;
    int      nkeys_free;
    int      nalgs;
};

struct cryptodev_context_open_s {
    // Request section
    int      module_index;
    char     pin[8];
    int      pinlen;
    uint32_t flags;
    //Response section
    int      context_id;
};

struct cryptodev_context_info_s {
    // Request section
    int      context_id;
    //Response section
    int      module_id;
    uint32_t flags;
    int      nkeys_used;
    int      nkeys_free;
};

struct cryptodev_alg_info_s {
    // Request section
    int      module_id;
    int      alg_index;
    //Response section
    uint32_t alg_id;
    uint32_t required_params;
};

struct cryptodev_alg_param_s {
    //Request section
    uint32_t param_id;
    int      param_value_size;
    uint8_t* param_value;
};

struct cryptodev_key_find_s {
    //Request section
    int      context_id;
    uint32_t flags;
    char     label[16];
    int      index;
    //Response section
    int      key_id;
};

struct cryptodev_key_info_s {
    //Request section
    int      context_id;
    int      key_id;
    //Response section
    char     label[16];
    uint32_t flags;
    int      key_length;
};

struct cryptodev_key_create_s {
    //Request section
    int      context_id;
    uint32_t flags;      //same as key info flags
    char     label[16];
    //Response section
    int      key_id;
};

struct cryptodev_key_delete_s {
    //Request section
    int context_id;
    int key_id;
};

struct cryptodev_key_setvalue_s {
    //Request section
    int      context_id;
    int      key_id;
    int      component_id;
    int      component_length;
    uint8_t* component;
};

struct cryptodev_key_transfer_s {
    //Request section
    int  context_id;
    int  key_id;
    char destination_key_label[16];
};

struct cryptodev_cipher_init_s {
    //Request section
    int      context_id;
    int      key_id;
    uint32_t flags;
};

struct cryptodev_cipher_update_s {
    //Request section
    int      context_id;
    int      data_length; //same for input and output
    uint8_t* indata;
    //Response section
    uint8_t* outdata;
};

struct cryptodev_cipher_final_s {
    //Request section
    int      context_id;
    int      indata_length;
    uint8_t* indata;
    //Mixed section
    int*     outdata_length;
    //Response section
    uint8_t* outdata;
};

struct cryptodev_ds_init_s {
    //Request section
    int      context_id;
    int      algorithm_id;
    int      key_id;
    uint32_t flags;
};

struct cryptodev_data_update_s {
    //Request section
    int      context_id;
    int      data_length;
    uint8_t* data;
};

struct cryptodev_data_final_s {
    //Request section
    int      context_id;
    //Mixed section
    int*     sig_length;
    uint8_t* signature;
};

struct cryptodev_hash_init_s {
    //Request section
    int    context_id;
    int    algorithm_id;
};

struct cryptodev_derive_s {
    //Request section
    int      context_id;
    int      algorithm_id;
    int      original_key_id;
    int      derivation_data_len;
    uint8_t* derivation_data;
    uint32_t new_key_flags;
    //Response section
    int      new_key_id;
};

struct cryptodev_wrap_s {
    //Request section
    int      context_id;
    int      algorithm_id;
    int      key_id;
    int      wrap_key_id;
    //Response section
    int*     wrapped_length;
    uint8_t* wrapped;
};

struct cryptodev_unwrap_s {
    //Request section
    int      context_id;
    int      algorithm_id;
    int*     wrapped_length;
    uint8_t* wrapped;
    int      wrap_key_id;
    uint32_t new_key_flags;
    //Response section
    int      new_key_id;
};

struct cryptodev_random_s {
    //Mixed section
    int*     data_length;
    //Response section
    uint8_t* randomdata;
};


#endif /* __INCLUDE_NUTTX_CRYPTO_CRYPTODEV_H */
