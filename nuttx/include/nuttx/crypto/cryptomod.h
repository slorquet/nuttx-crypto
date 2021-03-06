/****************************************************************************
 * include/nuttx/crypto/cryptomod.h
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

/*interface used to implement drivers for crypto modules*/

#ifndef __INCLUDE_NUTTX_CRYPTO_CRYPTOMOD_H
#define __INCLUDE_NUTTX_CRYPTO_CRYPTOMOD_H

#include <stdint.h>

struct cryptomod_operations_s
{
  int (*authenticate)(int step, int indatalen, FAR uint8_t *indata, FAR int *outdatalen, FAR uint8_t *outdata);
  /*keys management*/
  int (*key_count)(FAR int *used, FAR int *avail);
  /*algs management*/
  /*cipher ops*/
  /*ds ops*/
  /*hash ops*/
  /*derive,wrap,unwrap*/
  /*genrandom*/
};

int cryptomod_register(char *name, FAR struct cryptomod_operations_s *ops, uint32_t flags);

int up_cryptoinitialize(void);

#ifdef CONFIG_CRYPTO_SOFTMODULE
void cryptomod_softmod_register(void);
#endif

#endif /* __INCLUDE_NUTTX_CRYPTO_CRYPTOMOD_H */
