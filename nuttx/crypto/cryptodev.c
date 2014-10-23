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
#include <stdio.h>

#include <nuttx/fs/fs.h>

#include <nuttx/crypto/crypto.h>
#include <nuttx/crypto/cryptodev.h>

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
      int *dest = (int*)arg;
      *dest = 3;
      return 0;
    }
	
  case CIOCRYPTO_MODULE_INFO:
    {
      struct cryptodev_module_info_s *info = (struct cryptodev_module_info_s*)arg;
      if(info->module_index>2)
      {
        return -ENODEV;
      }
      sprintf(info->name,"Module_%04d",info->module_index);
      info->flags = 0;
      info->nkeys_used = 0;
      info->nkeys_free = 1;
      info->nalgs = 1;
      return 0;
    }

  case CIOCRYPTO_CONTEXT_OPEN:
  case CIOCRYPTO_CONTEXT_CLOSE:
  case CIOCRYPTO_CONTEXT_INFO:
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
  cryptdbg("Registering /dev/crypto device\n");
  (void)register_driver("/dev/crypto", &g_cryptodevops, 0666, NULL);
}
