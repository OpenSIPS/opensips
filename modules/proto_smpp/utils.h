#ifndef _PROTO_SMPP_UTILS_H_
#define _PROTO_SMPP_UTILS_H_

#include <stdint.h>

int copy_fixed_str(char *to, char *from, int n);
int copy_var_str(char *to, char *from);
int copy_u8(char *to, uint8_t from);
int copy_u32(char *to, uint32_t from);

#endif
