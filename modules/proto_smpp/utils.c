#include <stdint.h>

#include "utils.h"

int copy_fixed_str(char *to, char *from, int n)
{
	int iret = n;

	while (n--) {
		*to++ = *from++;
	}

	return iret;
}

int copy_var_str(char *to, char *from)
{
	int iret = 1;

	while (*from) {
		*to++ = *from++;
		iret++;
	}
	*to++ = '\0';

	return iret;
}

int copy_u8(char *to, uint8_t from)
{
	*to++ = from;
	return 1;
}

int copy_u32(char *to, uint32_t from)
{
	uint8_t *from8 = (uint8_t*)&from;
	*to++ = from8[3];
	*to++ = from8[2];
	*to++ = from8[1];
	*to++ = from8[0];

	return 4;
}

