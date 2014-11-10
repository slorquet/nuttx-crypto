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

int cryptomod_register(FAR char *name, FAR struct cryptomod_operations_s *ops, uint32_t flags)
{
  FAR struct cryptocore_module_s *mod;
  int namelen;

  /* truncate the name if too long */

  namelen = strlen(name);
  if (namelen > 16)
    {
      namelen = 16;
    }

  /* check that no module with that name already exists */

  mod = cryptocore_module_find(name, 0);
  if (mod != NULL)
    {
      cryptlldbg("ERROR: module '%s' already exists\n",name);
       return -EEXIST;
    }

  /* allocate and link the module */

  mod = cryptocore_module_alloc();

  if (!mod)
    {
      cryptlldbg("ERROR: Failed to allocate module '%s'\n",name);
      return -ENOMEM;
    }

  /* Populate the driver entries */

  memcpy(mod->name, name, namelen);
  mod->ops      = ops;
  mod->flags    = flags;

  cryptlldbg("Done [%s]\n", mod->name);

  return 0;
}

