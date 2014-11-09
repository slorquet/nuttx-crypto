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
#include <nuttx/crypto/cryptomod.h>
#include "cryptocore.h"

#define max(a,b) ((a)>(b)?(a):(b))

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/
FAR struct cryptocore_module_s  *modules_head;
FAR struct cryptocore_session_s *sessions_head;

#ifdef CONFIG_CRYPTO_SESSION_CACHE
FAR struct cryptocore_session_s *sessions_cache[CONFIG_CRYPTO_SESSION_CACHE_COUNT];
#endif

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
 *   if name is null, Returns a crypto module structure given its index.
 *   else, Returns a crypto module structure given its name.
 *   If the module is not found, returns NULL.
 *
 **************************************************************************/

FAR struct cryptocore_module_s *cryptocore_module_find(FAR char *modname, uint32_t modid)
{
  FAR struct cryptocore_module_s *cur;
  char locname[16];
  int index = 0;

  memcpy(locname, modname, max(strlen(modname),16) );
  cryptlldbg("name=%s id=%d\n", modname, modid);

  for (cur = modules_head; cur != NULL; cur = cur->next)
    {
      if (modname)
        {
          /*find by name*/
          if(!memcmp(cur->name, locname, 16))
            {
              return cur;
            }
        }
      else
        {
          /*find by ID*/
          if (index==modid)
            {
              return cur;
            }
        }
    }
  return NULL;
}

 /****************************************************************************
 * Name: cryptocore_module_count
 *
 * Description:
 *   Returns the number of registered modules
 *
 **************************************************************************/

int cryptocore_module_count(void)
{
  FAR struct cryptocore_module_s *cur;
  int count = 0;

  for (cur = modules_head; cur != NULL; cur = cur->next)
    {
      count++;
    }

  return count;
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

  cryptlldbg("Starting crypto core initialization\n");

  /*
   * Initialize an empty list of crypto modules
   * This list will be populated when board specific code calls cryptocore_module_register
   */

  modules_head = NULL;

  /* Initialize list of dynamic sessions */
  
  sessions_head = NULL;

  return res;
}

