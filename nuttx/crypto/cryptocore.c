/****************************************************************************
 * crypto/cryptocore.c
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

/*glue logic for all crypto framework*/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/types.h>
#include <stdbool.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <debug.h>

#include <nuttx/fs/fs.h>
#include "cryptocore.h"

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/
struct cryptocore_module_t *modules_head;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/

 /****************************************************************************
 * Name: cryptocore_module_find
 *
 * Description:
 *   Returns a crypto module structure given a module name.
 *   If the module is not found, returns NULL.
 *   TODO constant time search
 *
 **************************************************************************/

struct cryptocore_module_s *cryptocore_module_find(char *name, uint32_t id)
{
  struct cryptocore_module_s *cur;
  for(cur = modules_head; cur != NULL; cur = cur->next)
  {
    if(!strncmp(cur->name, name, 16))
    {
      return cur;
    }
  }
  return NULL;
}

 /****************************************************************************
 * Name: up_cryptoinitialize
 *
 * Description:
 *   Initialize the cryptographic subsystem. Setup session management and prepare
 *   for registration of device/board specific crypto modules.
 *
 **************************************************************************/

int up_cryptoinitialize(void)
{
  int res = OK;

  cryptdbg("Starting crypto core initialization\n");
  //Initialize an empty list of crypto modules
  //This list will be populated when board specific code calls cryptocore_module_register
  modules_head = NULL;
  
#ifdef CONFIG_CRYPTO_CONTEXT_STATIC
  //Setup variables in static session
  //Number of keys is CRYPTO_CONTEXT_STATIC_KEYS
#endif
  
  //Initialize list of dynamic sessions

  return res;
}
