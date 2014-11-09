/****************************************************************************
 * crypto/cryptomod.c
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

/*Functions used by cryptographic module implementations*/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/types.h>
#include <errno.h>
#include <debug.h>
#include <string.h>
#include <stdint.h>
#include <nuttx/crypto/cryptomod.h>
#include <nuttx/kmalloc.h>

#include "cryptocore.h"

extern struct cryptocore_module_s *modules_head;

/****************************************************************************
 * Public Functions
 ****************************************************************************/

 /****************************************************************************
 * Name: cryptomod_register
 *
 * Description:
 *   Register a crypto module to the core. When registration is successful,
 *   the registered module becomes visible in enumeration and can be used
 *   to create a crypto session.
 *
 **************************************************************************/

int cryptomod_register(char *name, FAR struct cryptomod_operations_s *ops, uint32_t flags)
{
  FAR struct cryptocore_module_s *mod;
  char                           locname[16];
  int                            namelen;

  cryptlldbg("registering: %s\n",name);

  /* truncate the name if too long */

  namelen = strlen(name);
  if (namelen > 16)
    {
      namelen = 16;
    }

  /* copy the name to local buffer, then pad */

  memcpy(locname, name, namelen);
  for (; namelen < 16; namelen++)
    {
      locname[namelen]=0;
    }

  /* check that no module with that name already exists */

  for (mod = modules_head; mod != NULL; mod = mod->next)
    {
      if (memcmp(mod->name, name, 16))
        {
          cryptlldbg("ERROR: module already exists\n");
          return -EEXIST;
        }
    }

  /* allocate the module */

  mod = (FAR struct cryptocore_module_s*)kmm_zalloc(sizeof(struct cryptocore_module_s));
  if (!mod)
    {
      cryptlldbg("ERROR: Failed to allocate module\n");
      return -ENOMEM;
    }

  /* link */

  mod->next    = modules_head;
  modules_head = mod;

  /* Populate the driver entries */

  memcpy(mod->name, locname, 16);
  mod->sessions = 0;
  mod->ops      = ops;
  mod->flags    = flags;

  cryptlldbg("Done [%s]\n", mod->name);

  return 0;
}

