/****************************************************************************
 * crypto/cryptocore.h
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

#ifndef __CRYPTO_CRYPTOCORE_H
#define __CRYPTO_CRYPTOCORE_H

#include <stdint.h>

struct cryptocore_module_s
{
  FAR struct cryptocore_module_s    *next;     /* link to the next module in list */
  int                                id;       /* module_id used by communication with clients */
  char                               name[16]; /* module name, zero padded */
  FAR struct cryptomod_operations_s *ops;      /* device specific operations */
  int                                contexts; /* number of opened contexts */
  uint32_t                           flags;    /* need pin, hardware, etc */
};

struct cryptocore_context_s
{
  FAR struct cryptocore_context_s  *next;   /* link to the next context in list */
  int                               id;     /* context_id used by communication with clients */
  FAR struct cryptocore_module_s   *module; /* crypto module hosting this context */
  uint32_t                          flags;  /* context flags */
  int                               nkeys_used;
  int                               nkeys_free;
};

FAR struct cryptocore_module_s *cryptocore_module_alloc(void);
FAR struct cryptocore_module_s *cryptocore_module_find(FAR char *modname, int modid);
int cryptocore_module_count(void);

FAR struct cryptocore_context_s *cryptocore_context_alloc(FAR struct cryptocore_module_s *host, uint32_t flags);
FAR struct cryptocore_context_s *cryptocore_context_find(int ctxid);
int cryptocore_context_destroy(FAR struct cryptocore_context_s *ctx);

#endif // __CRYPTO_CRYPTOCORE_H

