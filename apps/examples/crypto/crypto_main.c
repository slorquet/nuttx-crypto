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
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <nuttx/crypto/crypto.h>

/****************************************************************************
 * Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/

static void usage(void)
{
  printf(
    "Example Tool for crypto API\n"
    "cryptool <CMD> [args]\n"
    "  modlist       list available modules\n"
    "  keylist <id>  list all keys in a modules\n"
    "\n"
    "Report bugs to nuttx@yahoogroups.com and sebastien@lorquet.fr\n"
  );
}

static void modules_list(void)
{
  struct crypto_module_info_s info;
  int i;
  int err;
  int count = crypto_module_count();
  printf("Number of available modules: %d\n",count);
  for (i=0;i<count;i++)
    {
      err=crypto_module_info(i,&info);
      if (!err)
        {
          printf("%2d [%16s] %08X %d/%d\n",i,info.name,info.flags,info.nkeysused,info.nkeysfree);
        }
      else
        {
          printf("%2d ! Cannot get info, err=%d\n",i,err);
        }
    }
}

static void keys_list(int modid)
{
  if(modid>=crypto_module_count())
    {
      printf("Invalid module id\n");
      return;
    }
  printf("Enumerating keys of module %d\n",modid);
}

/****************************************************************************
 * crypto_main
 ****************************************************************************/

#ifdef CONFIG_BUILD_KERNEL
int main(int argc, FAR char *argv[])
#else
int cryptool_main(int argc, char *argv[])
#endif
{
  int fd;
  
  if (argc<2)
    {
      usage();
      return 0;
    }

  fd = open("/dev/crypto", O_RDWR);
  if (fd<0)
    {
      printf("cannot open /dev/crypto\n");
      return 1;
    }

  crypto_init_fd(fd);
  
  if (!strcmp(argv[1], "modlist"))
    {
      /* enumerate tokens */
      modules_list();
    }
  else if (!strcmp(argv[1], "keylist"))
    {
      /* enumerate keys in a module */
      /* need an arg: module index */
      int id;
      if(argc!=3)
        {
          usage();
          return 1;
        }
      id = atoi(argv[2]);
      keys_list(id);
    }
  else
    {
      printf("unknown command '%s'\n", argv[1]);
    }

  crypto_close();
  
  return 0;
}

