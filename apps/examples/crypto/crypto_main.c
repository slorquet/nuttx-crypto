/****************************************************************************
 * examples/crypto/crypto_main.c
 *
 *   Copyright (C) 2008, 2011-2014 Gregory Nutt. All rights reserved.
 *   Author: Sebastien Lorquet <sebastien@lorquet.fr>
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
#include <stdio.h>
#include <unistd.h>

/****************************************************************************
 * Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * crypto_main
 ****************************************************************************/

void usage(void)
{
  printf(
    "tool for crypto API\n"
    "cryptool <CMD> [args]\n"
    "  toklist       list available tokens\n"
    "  tokinfo <id>  info about a token\n"
    "  keylist <id>  list all keys in a token\n"
    "\n"
    "report bugs to nuttx@yahoogroups.com and sebastien@lorquet.fr\n"
  );
}

#ifdef CONFIG_BUILD_KERNEL
int main(int argc, FAR char *argv[])
#else
int crypto_main(int argc, char *argv[])
#endif
{
  int fd;
  
  if(argc<2)
  {
    usage();
    return 0;
  }

  fd = open("/dev/crypto", O_RDWR);
  if(fd<0)
  {
    printf("cannot open /dev/crypto\n");
    return 1;
  }
  
  if(!strcmp(argv[1], "toklist"))
  {
    //enumerate tokens
  }
  else if(!strcmp(argv[1], "tokinfo"))
  {
    //retrieve token info
  }
  else if(!strcmp(argv[1], "keylist"))
  {
    //enumerate keys in a token
  }
  else
  {
    printf("unknown command '%s'\n", argv[1]);
  }

  close(fd);
  
  return 0;
}
