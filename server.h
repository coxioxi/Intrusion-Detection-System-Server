#ifndef __ids_server_h__
#define __ids_server_h__

#include <sys/types.h>

typedef enum
{
  REQUEST = 1,
  RESPONSE,
  ERROR
} msg_type_t;

typedef struct
{
  long type;
  mode_t mode;
  size_t size;
  char cksum[12];
} ids_resp_t;

typedef struct
{
  long type;
  char filename[64];
} ids_req_t;

#endif
