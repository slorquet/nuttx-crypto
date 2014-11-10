/****************************************************************************
 * drivers/crypto/softmod.c
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

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nuttx/crypto/cryptomod.h>
#include <nuttx/crypto/crypto.h>

static unsigned char g_authenticated = FALSE;

int softmod_key_count(FAR int *used, FAR int *avail)
{
  *used = 1;
  *avail = 1;
  return 0;
}

int softmod_authenticate(FAR char *pin, int pinlen, uint32_t flags)
{
  /*UNBELIEVABLY INSECURE PIN CHECK*/
  if(pinlen!=4) return -EACCES;
  if(strcmp(pin,"1234")) return -EACCES;
  g_authenticated = TRUE;
  return 0;
}

//Private data

static struct cryptomod_operations_s g_softcryptomodops =
{
  softmod_authenticate,
  /*keys management*/
  softmod_key_count,
  /*algs management*/
  /*cipher ops*/
  /*ds ops*/
  /*hash ops*/
  /*derive,wrap,unwrap*/
  /*genrandom*/
};

/****************************************************************************
 * Public Functions
 ****************************************************************************/

void cryptomod_softmod_register(void)
{
  cryptomod_register("software", &g_softcryptomodops, 0);
}

