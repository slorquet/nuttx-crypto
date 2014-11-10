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

#include <nuttx/kmalloc.h>
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
FAR struct cryptocore_context_s *contexts_head;

int context_nextid = 1; /* identifier of the next context to be created */

#ifdef CONFIG_CRYPTO_CONTEXT_CACHE
struct cryptocore_cache_entry
{
  FAR struct cryptocore_context_s *context; /* pointer to the cached context */
  int                              lru;     /* insertion order, used for eviction */
};

struct cryptocore_cache_entry_s context_cache[CONFIG_CRYPTO_CONTEXT_CACHE_COUNT];
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
 * Name: cryptocore_context_alloc
 *
 * Description:
 *   Allocates and initialize a new context for an hosting module.
 *
 **************************************************************************/

FAR struct cryptocore_context_s * cryptocore_context_alloc(FAR struct cryptocore_module_s *host)
{
  FAR struct cryptocore_context_s *ctx;

  /* allocate */

  ctx = (FAR struct cryptocore_context_s*)kmm_zalloc(sizeof(struct cryptocore_context_s));
  if (ctx==NULL)
    {
      cryptlldbg("ERROR: Failed to allocate a context\n");
      return NULL;
    }

  /* link */

  ctx->next = contexts_head;
  contexts_head = ctx;

  /* populate */

  ctx->module = host;
  ctx->id     = context_nextid;
  context_nextid++;
  host->contexts += 1;

  cryptlldbg("allocated context %d at %p\n", ctx->id, ctx);

  return ctx;
}

 /****************************************************************************
 * Name: cryptocore_context_release
 *
 * Description:
 *   Releases all resources used by a context, without attempting to remove it
 *   from the global contexts list.
 *
 **************************************************************************/

int cryptocore_context_release(FAR struct cryptocore_context_s *ctx)
{
  cryptlldbg("freeing context %d at %p\n", ctx->id, ctx);

  /* free all temp keys */

  /* free the object */

  kmm_free(ctx);

  return 0;
}

 /****************************************************************************
 * Name: cryptocore_context_destroy
 *
 * Description:
 *   Remove a context from the global list, then release it.
 *
 **************************************************************************/

int cryptocore_context_destroy(FAR struct cryptocore_context_s *ctx)
{
  FAR struct cryptocore_context_s *cur;
  FAR struct cryptocore_context_s *prev;

  /* browse the context list to find the entry and its parent */

  for (prev = NULL, cur = contexts_head; cur != NULL; prev=cur, cur = cur->next)
    {
      if (cur == ctx)
        {
          /* entry was found. Action depends on prev */

          if (prev == NULL)
            {
              /* we are removing the first entry */

              contexts_head = cur->next;
            }
          else
            {
              /* we are removing an entry inside the list */

              prev->next = cur->next;
            }
          return cryptocore_context_release(cur);
        }
    }

    /* if we reach the end of list, the context was not found */

    return -ENOENT;
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
  
  contexts_head = NULL;

  return res;
}

