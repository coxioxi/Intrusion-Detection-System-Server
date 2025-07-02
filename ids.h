#ifndef __ids_h__
#define __ids_h__

#include <sys/types.h>

typedef struct
{
  char filename[64];
  mode_t mode;
  size_t size;
  char cksum[12];
  bool valid;
} ids_entry_t;

#endif
