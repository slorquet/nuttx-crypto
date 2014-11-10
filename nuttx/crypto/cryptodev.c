/****************************************************************************
 * crypto/cryptodev.c
 *
 *   Copyright (C) 2014 Gregory Nutt. All rights reserved.
 *   Author:  Max Nekludov <macscomp@gmail.com>
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

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/types.h>
#include <poll.h>
#include <errno.h>
#include <debug.h>
#include <string.h>

#include <nuttx/fs/fs.h>

#include <nuttx/crypto/crypto.h>
#include <nuttx/crypto/cryptodev.h>
#include <nuttx/crypto/cryptomod.h>

#include "cryptocore.h"

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

/* Character driver methods */

static ssize_t cryptodev_read(FAR struct file *filep, FAR char *buffer,
                              size_t len);
static ssize_t cryptodev_write(FAR struct file *filep, FAR const char *buffer,
                               size_t len);
static int cryptodev_ioctl(FAR struct file *filep, int cmd,
                           unsigned long arg);

/****************************************************************************
 * Private Data
 ****************************************************************************/

static const struct file_operations g_cryptodevops =
{
  0,                  /* open */
  0,                  /* close */
  cryptodev_read,     /* read */
  cryptodev_write,    /* write */
  0,                  /* seek */
  cryptodev_ioctl,    /* ioctl */
#ifndef CONFIG_DISABLE_POLL
  0,                  /* poll */
#endif
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static ssize_t cryptodev_read(FAR struct file *filep, FAR char *buffer,
                              size_t len)
{
  return -EACCES;
}

static ssize_t cryptodev_write(FAR struct file *filep, FAR const char *buffer,
                               size_t len)
{
  return -EACCES;
}

static int cryptodev_ioctl(FAR struct file *filep, int cmd, unsigned long arg)
{
  switch(cmd)
    {
      case CIOCRYPTO_MODULE_COUNT:
        {
          FAR int *dest = (FAR int*)arg;
          cryptlldbg("Requesting module count\n");
          *dest = cryptocore_module_count();
          return 0;
        }
	
      case CIOCRYPTO_MODULE_INFO:
        {
          FAR struct cryptodev_module_info_s *info = (FAR struct cryptodev_module_info_s*)arg;
          FAR struct cryptocore_module_s     *mod;

          cryptlldbg("Requesting module info (%d)\n", info->module_index);
          mod = cryptocore_module_find(NULL, info->module_index);
          if (mod == NULL)
            {
              return -ENODEV;
            }

          memcpy(info->name, mod->name, 16);
          info->flags      = mod->flags;
          mod->ops->key_count(&info->nkeys_used, &info->nkeys_free);
          info->nalgs      = 1;
          return 0;
        }

      case CIOCRYPTO_CONTEXT_OPEN:
        {
          FAR struct cryptodev_context_open_s *info = (FAR struct cryptodev_context_open_s*)arg;
          FAR struct cryptocore_module_s      *mod;
          FAR struct cryptocore_context_s     *ctx;
          int ret;

          cryptlldbg("Opening a context with module (%d)\n", info->module_index);
          mod = cryptocore_module_find(NULL, info->module_index);
          if (mod == NULL)
            {
              return -ENODEV;
            }

          ret = mod->ops->authenticate(info->pin, info->pinlen, info->flags);
          if (ret!=0)
            {
              cryptlldbg("Authentication failed");
              return ret;
            }

          ctx = cryptocore_context_alloc(mod, info->flags);
          if (ctx == NULL)
            {
            cryptlldbg("Context creation failed");
            return -ENOMEM;
            }
          else
            {
            info->context_id = ctx->id;
            return 0;
            }
        }

      case CIOCRYPTO_CONTEXT_CLOSE:
        {
          FAR struct cryptocore_context_s *ctx;
          ctx = cryptocore_context_find( (int)arg );
          if( ctx == NULL)
            {
              return -ENOENT;
            }
          return cryptocore_context_destroy(ctx);
        }

      case CIOCRYPTO_CONTEXT_INFO:
        {
          FAR struct cryptodev_context_info_s *info = (FAR struct cryptodev_context_info_s*)arg;
          FAR struct cryptocore_context_s *ctx;
          ctx = cryptocore_context_find( info->context_id );
          if( ctx == NULL)
            {
              return -ENOENT;
            }

          /* copy the info */

          info->module_id  = ctx->module->id;
          info->flags      = ctx->flags;
          info->nkeys_used = ctx->nkeys_used;
          info->nkeys_free = ctx->nkeys_free;

          return 0;
        }

      case CIOCRYPTO_ALG_INFO:
      case CIOCRYPTO_ALG_SETPARAM:
      case CIOCRYPTO_KEY_FIND:
      case CIOCRYPTO_KEY_INFO:
      case CIOCRYPTO_KEY_CREATE:
      case CIOCRYPTO_KEY_DELETE:
      case CIOCRYPTO_KEY_SETVALUE:
      case CIOCRYPTO_KEY_TRANSFER:
      case CIOCRYPTO_CIPHER_INIT:
      case CIOCRYPTO_CIPHER_UPDATE:
      case CIOCRYPTO_CIPHER_FINAL:
      case CIOCRYPTO_DS_INIT:
      case CIOCRYPTO_DS_UPDATE:
      case CIOCRYPTO_DS_FINAL:
      case CIOCRYPTO_HASH_INIT:
      case CIOCRYPTO_HASH_UPDATE:
      case CIOCRYPTO_HASH_FINAL:
      case CIOCRYPTO_DERIVE:
      case CIOCRYPTO_WRAP:
      case CIOCRYPTO_UNWRAP:
      case CIOCRYPTO_GEN_RANDOM:
        return -EACCES;
	
      default:
        return -EINVAL;
    }
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

void devcrypto_register(void)
{
  cryptlldbg("Registering /dev/crypto device\n");
  (void)register_driver("/dev/crypto", &g_cryptodevops, 0666, NULL);
}

