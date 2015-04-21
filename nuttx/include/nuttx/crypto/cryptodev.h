/****************************************************************************
 * include/nuttx/crypto/cryptodev.h
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

#ifndef __INCLUDE_NUTTX_CRYPTO_CRYPTODEV_H
#define __INCLUDE_NUTTX_CRYPTO_CRYPTODEV_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <stdint.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#include <nuttx/fs/ioctl.h>

#define _CRIOC(nr)       _IOC(_CRYPTOIOCBASE,nr)

#define CRYPTOIOC_MODULE_INITFIND _CRIOC(0x0001) /* void** */
#define CRYPTOIOC_MODULE_FIND     _CRIOC(0x0002) /* struct cryptodev_module_info_s */
#define CRYPTOIOC_CONTEXT_OPEN    _CRIOC(0x0003) /* struct cryptodev_context_open_s */
#define CRYPTOIOC_CONTEXT_AUTH    _CRIOC(0x0004) /* struct cryptodev_context_auth_s */
#define CRYPTOIOC_CONTEXT_CLOSE   _CRIOC(0x0005) /* int */
#define CRYPTOIOC_CONTEXT_INFO    _CRIOC(0x0006) /* struct cryptodev_context_info_s */
#define CRYPTOIOC_ALG_INFO        _CRIOC(0x0007) /* struct cryptodev_alg_info_s */
#define CRYPTOIOC_ALG_SETPARAM    _CRIOC(0x0008) /* struct cryptodev_alg_param_s */
#define CRYPTOIOC_KEY_INITFIND    _CRIOC(0x0009) /* void** */
#define CRYPTOIOC_KEY_FIND        _CRIOC(0x000A) /* struct cryptodev_key_find_s */
#define CRYPTOIOC_KEY_INFO        _CRIOC(0x000B) /* struct cryptodev_key_info_s */
#define CRYPTOIOC_KEY_CREATE      _CRIOC(0x000C) /* struct cryptodev_key_create_s */
#define CRYPTOIOC_KEY_DELETE      _CRIOC(0x000D) /* struct cryptodev_key_delete_s */
#define CRYPTOIOC_KEY_SETVALUE    _CRIOC(0x000E) /* struct cryptodev_key_setvalue_s */
#define CRYPTOIOC_KEY_TRANSFER    _CRIOC(0x000F) /* struct cryptodev_key_transfer_s */
#define CRYPTOIOC_CIPHER_INIT     _CRIOC(0x0010) /* struct cryptodev_cipher_init_s */
#define CRYPTOIOC_CIPHER_UPDATE   _CRIOC(0x0011) /* struct cryptodev_cipher_update_s */
#define CRYPTOIOC_CIPHER_FINAL    _CRIOC(0x0012) /* struct cryptodev_cipher_final_s */
#define CRYPTOIOC_DS_INIT         _CRIOC(0x0013) /* struct cryptodev_ds_init_s */
#define CRYPTOIOC_DS_UPDATE       _CRIOC(0x0014) /* struct cryptodev_data_update_s */
#define CRYPTOIOC_DS_FINAL        _CRIOC(0x0015) /* struct cryptodev_data_final_s */
#define CRYPTOIOC_HASH_INIT       _CRIOC(0x0016) /* struct cryptodev_hash_init_s */
#define CRYPTOIOC_HASH_UPDATE     _CRIOC(0x0017) /* struct cryptodev_data_update_s */
#define CRYPTOIOC_HASH_FINAL      _CRIOC(0x0018) /* struct cryptodev_data_final_s */
#define CRYPTOIOC_DERIVE          _CRIOC(0x0019) /* struct cryptodev_derive_s */
#define CRYPTOIOC_WRAP            _CRIOC(0x001A) /* struct cryptodev_wrap_s */
#define CRYPTOIOC_UNWRAP          _CRIOC(0x001B) /* struct cryptodev_unwrap_s */
#define CRYPTOIOC_GEN_RANDOM      _CRIOC(0x001C) /* struct cryptodev_derive_s */

struct cryptodev_module_info_s
{
  void     **enumerator; /* IO: Enumerator */
  int      moduleid;     /*  O: Module identifier */
  char     name[16];     /*  O: Module name */
  uint32_t flags;        /*  O: Module attributes */
  int      nkeysused;    /*  O: Number of keys defined */
  int      nkeysfree;    /*  O: Number of keys available */
  int      nalgs;        /*  O: Number of available algorithms */
};

struct cryptodev_context_open_s
{
  int      moduleid;  /* I : Identifier of module to access */
  uint32_t flags;     /* I : Access options */
  int      contextid; /*  O: Returned context identifier */
};

struct cryptodev_context_auth_s
{
  int      contextid;   /* I : Identifier of context to authenticate */
  int      step;        /* I : Authentication step being executed */
  int      indatalen;   /* I : Length of authentication data */
  uint8_t  *indata;     /* I : Authentication data */
  int      *outdatalen; /* IO: Length Dynamic authentication response */
  uint8_t  *outdata;    /*  O: Dynamic authentication response */
};



#endif /* __INCLUDE_NUTTX_CRYPTO_CRYPTODEV_H */
