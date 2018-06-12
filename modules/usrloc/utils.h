#ifndef __UTILS_H__
#define __UTILS_H__

#include "../../msg_parser.h"

#define PARANOID


#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define SUCCESS 1
#define FAILURE 0


char* trim(char* _s);
char* eat_lws(char* _b);
struct hdr_field* remove_crlf(struct hdr_field* _hf);

char* strlower(char* _s, int len);
char* strupper(char* _s, int len);


void mutex_down(int id);
void mutex_up  (int id);


char* parse_to(char* _to);

char* find_not_quoted(char* _b, char c);
char* eat_name(char* _b);

#endif
