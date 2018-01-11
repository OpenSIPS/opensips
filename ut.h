/*
 * - various general purpose functions
 *
 * Copyright (C) 2001-2003 FhG Fokus
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 */


#ifndef ut_h
#define ut_h

#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <limits.h>
#include <unistd.h>
#include <ctype.h>

#include "config.h"
#include "dprint.h"
#include "sr_module.h"
#include "action.h"
#include "str.h"
#include "evi/evi_modules.h"
#include "evi/evi_core.h"

#include "mem/mem.h"
#include "mem/shm_mem.h"

typedef struct _int_str_t {
	union {
		int i;
		str s;
	};
	unsigned char is_str;
} int_str_t;

struct sip_msg;

/* zero-string wrapper */
#define ZSW(_c) ((_c)?(_c):"")

/* str initialization */
#define str_init(_string)  {_string, sizeof(_string) - 1}

/* returns string beginning and length without insignificant chars */
#define trim_len( _len, _begin, _mystr ) \
	do{ 	static char _c; \
		(_len)=(_mystr).len; \
		while ((_len) && ((_c=(_mystr).s[(_len)-1])==0 || _c=='\r' || \
					_c=='\n' || _c==' ' || _c=='\t' )) \
			(_len)--; \
		(_begin)=(_mystr).s; \
		while ((_len) && ((_c=*(_begin))==' ' || _c=='\t')) { \
			(_len)--;\
			(_begin)++; \
		} \
	}while(0)

#define trim_r( _mystr ) \
	do{	static char _c; \
		while( ((_mystr).len) && ( ((_c=(_mystr).s[(_mystr).len-1]))==0 ||\
									_c=='\r' || _c=='\n' ) \
				) \
			(_mystr).len--; \
	}while(0)

/* right and left space trimming */
#define trim_spaces_lr(_s_) \
	do{\
		for(;(_s_).s[(_s_).len-1]==' ';(_s_).s[--(_s_).len]=0);\
		for(;(_s_).s[0]==' ';(_s_).s=(_s_).s+1,(_s_).len--);\
	}while(0);

/* right and left space trimming without '0' padding */
#define str_trim_spaces_lr(_s_) \
	do{\
		for(;(_s_).s[(_s_).len-1]==' ';--(_s_).len);\
		for(;(_s_).s[0]==' ';(_s_).s=(_s_).s+1,(_s_).len--);\
	}while(0);


#define  translate_pointer( _new_buf , _org_buf , _p) \
	( (_p)?(_new_buf + (_p-_org_buf)):(0) )

#define via_len(_via) \
	((_via)->bsize-((_via)->name.s-\
		((_via)->hdr.s+(_via)->hdr.len)))

#ifdef __GNUC__
#define ALLOW_UNUSED __attribute__ ((unused))
#else
#define ALLOW_UNUSED
#endif

#define PTR_STRING_SIZE  2+16+1
#define PTR_STR_SIZE     2+16

/* char to hex conversion table */
static char fourbits2char[16] = { '0', '1', '2', '3', '4', '5',
	'6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };


/* converts a str to an u. short, returns the u. short and sets *err on
 * error and if err!=null
  */
static inline unsigned short str2s(const char* s, unsigned int len,
									int *err)
{
	unsigned short ret;
	int i;
	unsigned char *limit;
	unsigned char *str;

	/*init*/
	str=(unsigned char*)s;
	ret=i=0;
	limit=str+len;

	for(;str<limit ;str++){
		if ( (*str <= '9' ) && (*str >= '0') ){
				ret=ret*10+*str-'0';
				i++;
				if (i>5) goto error_digits;
		}else{
				//error unknown char
				goto error_char;
		}
	}
	if (err) *err=0;
	return ret;

error_digits:
	LM_DBG("too many letters in [%.*s]\n", (int)len, s);
	if (err) *err=1;
	return 0;
error_char:
	LM_DBG("unexpected char %c in %.*s\n", *str, (int)len, s);
	if (err) *err=1;
	return 0;
}


static inline int btostr( char *p,  unsigned char val)
{
	unsigned int a,b,i =0;

	if ( (a=val/100)!=0 )
		*(p+(i++)) = a+'0';         /*first digit*/
	if ( (b=val%100/10)!=0 || a)
		*(p+(i++)) = b+'0';        /*second digit*/
	*(p+(i++)) = '0'+val%10;              /*third digit*/

	return i;
}


/* 2^64~= 16*10^18 => 19+1+1 sign + digits + \0 */
#define INT2STR_MAX_LEN  (1+19+1+1)

/* INTeger-TO-Buffer-STRing : converts a 64-bit integer to a string
 * IMPORTANT: the provided buffer must be at least INT2STR_MAX_LEN size !! */
static inline char* int2bstr(uint64_t l, char *s, int* len)
{
	int i;

	i=INT2STR_MAX_LEN-2;
	s[INT2STR_MAX_LEN-1]=0; /* null terminate */
	do{
		s[i]=l%10+'0';
		i--;
		l/=10;
	}while(l && (i>=0));
	if (l && (i<0)){
		LM_CRIT("overflow error\n");
	}
	if (len) *len=(INT2STR_MAX_LEN-2)-i;
	return &s[i+1];
}


/* INTeger-TO-STRing : convers a 64-bit integer to a string
 * returns a pointer to a static buffer containing l in asciiz & sets len */
extern char int2str_buf[INT2STR_MAX_LEN];
static inline char* int2str(uint64_t l, int* len)
{
	return int2bstr( l, int2str_buf, len);
}


/* Signed INTeger-TO-STRing: convers a long to a string
 * returns a pointer to a static buffer containing l in asciiz & sets len */
static inline char* sint2str(long l, int* len)
{
	int sign;
	char *p;

	sign = 0;
	if(l<0) {
		sign = 1;
		l = -l;
	}
	p = int2str((unsigned long)l, len);
	if(sign) {
		*(--p) = '-';
		if (len) (*len)++;
	}
	return p;
}


/* faster memchr version */
static inline char* q_memchr(char* p, int c, unsigned int size)
{
	char* end;

	end=p+size;
	for(;p<end;p++){
		if (*p==(unsigned char)c) return p;
	}
	return NULL;
}


/* faster memrchr version */
static inline char* q_memrchr(char* p, int c, unsigned int size)
{
	char* cursor;

	cursor=p+size-1;
	for(;cursor>=p;cursor--){
		if (*cursor==(unsigned char)c) return cursor;
	}
	return NULL;
}


inline static int reverse_hex2int( char *c, int len )
{
	char *pc;
	int r;
	char mychar;

	r=0;
	for (pc=c+len-1; len>0; pc--, len--) {
		r <<= 4 ;
		mychar=*pc;
		if ( mychar >='0' && mychar <='9') r+=mychar -'0';
		else if (mychar >='a' && mychar <='f') r+=mychar -'a'+10;
		else if (mychar  >='A' && mychar <='F') r+=mychar -'A'+10;
		else return -1;
	}
	return r;
}

inline static int int2reverse_hex( char **c, int *size, unsigned int nr )
{
	unsigned short digit;

	if (*size && nr==0) {
		**c = '0';
		(*c)++;
		(*size)--;
		return 1;
	}

	while (*size && nr ) {
		digit = nr & 0xf ;
		**c= digit >= 10 ? digit + 'a' - 10 : digit + '0';
		nr >>= 4;
		(*c)++;
		(*size)--;
	}
	return nr ? -1 /* number not processed; too little space */ : 1;
}

/* same functions, higher representation 64 bit*/
/* if unsafe requested when first non numerical character shall be
 * met the number shall be returned; avoid giving the
 * exact len of the number */
inline static int64_t reverse_hex2int64( char *c, int len, int unsafe)
{
	char *pc;
	int64_t r;
	char mychar;

	r=0;
	for (pc=c+len-1; len>0; pc--, len--) {
		r <<= 4 ;
		mychar=*pc;
		if ( mychar >='0' && mychar <='9') r+=mychar -'0';
		else if (mychar >='a' && mychar <='f') r+=mychar -'a'+10;
		else if (mychar  >='A' && mychar <='F') r+=mychar -'A'+10;
		else if (unsafe)
			return r;
		else return -1;
	}
	return r;
}

inline static int64_t int64_2reverse_hex( char **c, int *size, uint64_t nr )
{
	unsigned short digit;

	if (*size && nr==0) {
		**c = '0';
		(*c)++;
		(*size)--;
		return 1;
	}

	while (*size && nr ) {
		digit = nr & 0xf ;
		**c= digit >= 10 ? digit + 'a' - 10 : digit + '0';
		nr >>= 4;
		(*c)++;
		(*size)--;
	}
	return nr ? -1 /* number not processed; too little space */ : 1;
}


inline static int hexstr2int(char *c, int len, unsigned int *val)
{
	char *pc;
	int r;
	char mychar;

	r=0;
	for (pc=c; pc<c+len; pc++) {
		r <<= 4 ;
		mychar=*pc;
		if ( mychar >='0' && mychar <='9') r+=mychar -'0';
		else if (mychar >='a' && mychar <='f') r+=mychar -'a'+10;
		else if (mychar  >='A' && mychar <='F') r+=mychar -'A'+10;
		else return -1;
	}
	*val = r;
	return 0;
}


/* double output length assumed ; does NOT zero-terminate */
inline static int string2hex(
	/* input */ unsigned char *str, int len,
	/* output */ char *hex )
{
	int orig_len;

	if (len==0) {
		*hex='0';
		return 1;
	}

	orig_len=len;
	while ( len ) {

		*hex=fourbits2char[((*str) >> 4) & 0x0f];
		hex++;
		*hex=fourbits2char[(*str) & 0x0f];
		hex++;
		len--;
		str++;

	}
	return orig_len-len;
}

/* portable sleep in microseconds (no interrupt handling now) */

inline static void sleep_us( unsigned int nusecs )
{
	struct timeval tval;
	tval.tv_sec=nusecs/1000000;
	tval.tv_usec=nusecs%1000000;
	select(0, NULL, NULL, NULL, &tval );
}


/* portable determination of max_path */
inline static int pathmax(void)
{
#ifdef PATH_MAX
	static int pathmax=PATH_MAX;
#else
	static int pathmax=0;
#endif
	if (pathmax==0) { /* init */
		pathmax=pathconf("/", _PC_PATH_MAX);
		pathmax=(pathmax<=0)?PATH_MAX_GUESS:pathmax+1;
	}
	return pathmax;
}

inline static int hex2int(char hex_digit)
{
	if (hex_digit>='0' && hex_digit<='9')
		return hex_digit-'0';
	if (hex_digit>='a' && hex_digit<='f')
		return hex_digit-'a'+10;
	if (hex_digit>='A' && hex_digit<='F')
		return hex_digit-'A'+10;
	/* no valid hex digit ... */
	LM_ERR("'%c' is no hex char\n", hex_digit );
	return -1;
}

/* Un-escape URI user  -- it takes a pointer to original user
   str, as well as the new, unescaped one, which MUST have
   an allocated buffer linked to the 'str' structure ;
   (the buffer can be allocated with the same length as
   the original string -- the output string is always
   shorter (if escaped characters occur) or same-long
   as the original one).

   only printable characters are permitted

	<0 is returned on an unescaping error, length of the
	unescaped string otherwise
*/
inline static int un_escape(str *user, str *new_user )
{
 	int i, j, value;
	int hi, lo;

	if( new_user==0 || new_user->s==0) {
		LM_CRIT("called with invalid param\n");
		return -1;
	}

	new_user->len = 0;
	j = 0;

	for (i = 0; i < user->len; i++) {
		if (user->s[i] == '%') {
			if (i + 2 >= user->len) {
				LM_ERR("escape sequence too short in"
					" '%.*s' @ %d\n",
					user->len, user->s, i );
				goto error;
			}
			hi=hex2int(user->s[i + 1]);
			if (hi<0) {
				LM_ERR(" non-hex high digit in an escape"
					" sequence in '%.*s' @ %d\n",
					user->len, user->s, i+1 );
				goto error;
			}
			lo=hex2int(user->s[i + 2]);
			if (lo<0) {
				LM_ERR("non-hex low digit in an escape sequence in "
					"'%.*s' @ %d\n",
					user->len, user->s, i+2 );
				goto error;
			}
			value=(hi<<4)+lo;
			if (value < 32 || value > 126) {
				LM_ERR("non-ASCII escaped character in '%.*s' @ %d\n",
					user->len, user->s, i );
				goto error;
			}
			new_user->s[j] = value;
			i+=2; /* consume the two hex digits, for cycle will move to the next char */
		} else {
			new_user->s[j] = user->s[i];
		}
        j++; /* good -- we translated another character */
	}
	new_user->len = j;
	return j;

error:
	new_user->len = j;
	return -1;
}


/*
 * Convert a string to lower case
 */
static inline void strlower(str* _s)
{
	int i;

	for(i = 0; i < _s->len; i++) {
		_s->s[i] = tolower(_s->s[i]);
	}
}

/*
 * Convert a str into a short integer
 */
static inline int str2short(str* _s, unsigned short *_r)
{
	int i;

	if (_s==0 || _s->s == 0 || _s->len == 0 || _r == 0)
		return -1;

	*_r = 0;
	for(i = 0; i < _s->len; i++) {
		if ((_s->s[i] >= '0') && (_s->s[i] <= '9')) {
			*_r *= 10;
			*_r += _s->s[i] - '0';
		} else {
			return -1;
		}
	}

	return 0;
}

/*
 * Convert a str into integer
 */
static inline int str2int(str* _s, unsigned int* _r)
{
	int i;

	if (_s==0 || _s->s == 0 || _s->len == 0 || _r == 0)
		return -1;

	*_r = 0;
	for(i = 0; i < _s->len; i++) {
		if ((_s->s[i] >= '0') && (_s->s[i] <= '9')) {
			*_r *= 10;
			*_r += _s->s[i] - '0';
		} else {
			return -1;
		}
	}

	return 0;
}

/*
 * Convert a str into a big integer
 */
static inline int str2int64(str* _s, uint64_t *_r)
{
	int i;

	if (_s==0 || _s->s == 0 || _s->len == 0 || _r == 0)
		return -1;

	*_r = 0;
	for(i = 0; i < _s->len; i++) {
		if ((_s->s[i] >= '0') && (_s->s[i] <= '9')) {
			*_r *= 10;
			*_r += _s->s[i] - '0';
		} else {
			return -1;
		}
	}

	return 0;
}


/*
 * Convert a str into signed integer
 */
static inline int str2sint(str* _s, int* _r)
{
	int i;
	int s;

	if (_s==0 || _s->s == 0 || _s->len == 0 || _r == 0)
		return -1;

	*_r = 0;
	s = 1;
	i=0;
	if(_s->s[i]=='-') {
		s=-1;
		i++;
	} else if (_s->s[i]=='+') {
		i++;
	}
	for(; i < _s->len; i++) {
		if ((_s->s[i] >= '0') && (_s->s[i] <= '9')) {
			*_r *= 10;
			*_r += _s->s[i] - '0';
		} else {
			//Preserve sign for partially converted strings
			*_r *= s;
			return -1;
		}
	}
	*_r *= s;
	return 0;
}


/*
 * Convert a str (base 10 or 16) into integer
 */
static inline int strno2int( str *val, unsigned int *mask )
{
	/* hexa or decimal*/
	if (val->len>2 && val->s[0]=='0' && val->s[1]=='x') {
		return hexstr2int( val->s+2, val->len-2, mask);
	} else {
		return str2int( val, mask);
	}
}


/*
 * Make a copy of a str structure using shm_malloc
 */
static inline int shm_str_dup(str* dst, const str* src)
{
	dst->s = shm_malloc(src->len);
	if (!dst->s) {
		LM_ERR("no shared memory left\n");
		return -1;
	}

	memcpy(dst->s, src->s, src->len);
	dst->len = src->len;
	return 0;
}

/*
 * Make a copy of an str structure using shm_malloc
 *	  + an additional '\0' byte, so you can make use of dst->s
 */
static inline int shm_nt_str_dup(str* dst, const str* src)
{
	if (!src || !src->s)
		return -1;

	memset(dst, 0, sizeof *dst);

	dst->s = shm_malloc(src->len + 1);
	if (!dst->s) {
		LM_ERR("no shared memory left\n");
		return -1;
	}

	memcpy(dst->s, src->s, src->len);
	dst->len = src->len;
	dst->s[dst->len] = '\0';
	return 0;
}

static inline char *shm_strdup(const char *str)
{
	char *rval;
	int len;

	if (!str)
		return NULL;

	len = strlen(str) + 1;
	rval = shm_malloc(len);
	if (!rval)
		return NULL;
	memcpy(rval, str, len);
	return rval;
}

/*
 * Ensure the given (str *) points to an SHM buffer of at least "size" bytes
 *
 * Return: 0 on success, -1 on failure
 */
static inline int shm_str_extend(str *in, int size)
{
	char *p;

	if (in->len < size) {
		p = shm_realloc(in->s, size);
		if (!p) {
			LM_ERR("oom\n");
			return -1;
		}

		in->s = p;
		in->len = size;
	}

	return 0;
}

/*
 * Make a copy of a str structure using pkg_malloc
 */
static inline int pkg_str_dup(str* dst, const str* src)
{
	dst->s = pkg_malloc(src->len);
	if (dst->s==NULL)
	{
		LM_ERR("no private memory left\n");
		return -1;
	}

	memcpy(dst->s, src->s, src->len);
	dst->len = src->len;
	return 0;
}

static inline char *pkg_strdup(const char *str)
{
	char *rval;
	int len;

	if (!str)
		return NULL;

	len = strlen(str) + 1;
	rval = pkg_malloc(len);
	if (!rval)
		return NULL;
	memcpy(rval, str, len);
	return rval;
}

/* Extend the given buffer only if needed */
static inline int pkg_str_resize(str *in, int size)
{
	char *p;

	if (in->len < size) {
		p = pkg_realloc(in->s, size);
		if (!p) {
			LM_ERR("oom\n");
			return -1;
		}

		in->s = p;
		in->len = size;
	}

	return 0;
}

/*
 * compare two str's
 */
static inline int str_strcmp(const str *stra, const str *strb)
{
	int i;
	int alen;
	int blen;
	int minlen;

	if(stra==NULL || strb==NULL || stra->s ==NULL || strb->s==NULL
	|| stra->len<0 || strb->len<0)
	{
		LM_ERR("bad parameters\n");
		return -2;
	}

	alen = stra->len;
	blen = strb->len;
	minlen = (alen < blen ? alen : blen);


	for (i = 0; i < minlen; i++) {
		const char a = stra->s[i];
		const char b = strb->s[i];
		if (a < b)
			return -1;
		if (a > b)
			return 1;
	}
	if (alen < blen)
		return -1;
	else if (alen > blen)
		return 1;
	else
		return 0;
}

/*
 * search strb in stra
 */
static inline char* str_strstr(const str *stra, const str *strb)
{
	int i;
	int len;

	if (stra==NULL || strb==NULL || stra->s==NULL || strb->s==NULL
			|| stra->len<=0 || strb->len<=0) {
		LM_ERR("bad parameters\n");
		return NULL;
	}

	if (strb->len > stra->len) {
		LM_ERR("string to find should be smaller than the string"
				"to search into\n");
		return NULL;
	}


	len=0;
	while (stra->len-len >= strb->len){
		if (stra->s[len] != strb->s[0]) {
			len++;
			continue;
		}

		for (i=1; i<strb->len; i++)
			if (stra->s[len+i]!=strb->s[i]) {
				len++;
				break;
			}

		if (i != strb->len)
			continue;

		return stra->s+len;
	}


	return NULL;
}

/*
 * case-insensitive compare n chars of two str's
 */
static inline int str_strncasecmp(const str *stra, const str *strb, int n)
{
	int i;

	if(stra==NULL || strb==NULL || stra->s ==NULL || strb->s==NULL
	|| stra->len<0 || strb->len<0)
	{
		LM_ERR("bad parameters\n");
		return -2;
	}

	if (stra->len<n || strb->len<n) {
		LM_ERR("input strings don't have at least [n=%d] characters\n", n);
		return -2;
	}

	for (i = 0; i < n; i++) {
		const char a = tolower(stra->s[i]);
		const char b = tolower(strb->s[i]);
		if (a < b)
			return -1;
		if (a > b)
			return 1;
	}

	return 0;

}

/*
 * case-insensitive compare two str's
 */
static inline int str_strcasecmp(const str *stra, const str *strb)
{
	int i;
	int alen;
	int blen;
	int minlen;

	if(stra==NULL || strb==NULL || stra->s ==NULL || strb->s==NULL
	|| stra->len<0 || strb->len<0)
	{
		LM_ERR("bad parameters\n");
		return -2;
	}
	alen = stra->len;
	blen = strb->len;
	minlen = (alen < blen ? alen : blen);

	for (i = 0; i < minlen; i++) {
		const char a = tolower(stra->s[i]);
		const char b = tolower(strb->s[i]);
		if (a < b)
			return -1;
		if (a > b)
			return 1;
	}
	if (alen < blen)
		return -1;
	else if (alen > blen)
		return 1;
	else
		return 0;
}

#define start_expire_timer(begin,threshold) \
	do { \
		if ((threshold))	\
			gettimeofday(&(begin), NULL); \
	} while(0) \

#define stop_expire_timer(begin,threshold,func_info,extra_s,extra_len,tcp) \
	do { \
		if ((threshold)) \
			log_expiry(get_time_diff(&(begin)),(threshold),(func_info),(extra_s),(extra_len),tcp); \
	} while(0)



int tcp_timeout_con_get;
int tcp_timeout_receive_fd;
int tcp_timeout_send;

#define reset_tcp_vars(threshold) \
	do { \
		if (threshold) \
		{ \
			tcp_timeout_con_get=0; \
			tcp_timeout_receive_fd=0; \
			tcp_timeout_send=0; \
		} \
	} while(0)

#define get_time_difference(begin,threshold,tcp_dbg) \
	do { \
		if ((threshold)) \
			tcp_dbg = get_time_diff(&(begin)); \
	} while(0)


static inline int get_time_diff(struct timeval *begin)
{
	struct timeval end;
	long seconds,useconds,mtime;

	gettimeofday(&end,NULL);
	seconds  = end.tv_sec  - begin->tv_sec;
	useconds = end.tv_usec - begin->tv_usec;
	mtime = ((seconds) * 1000000 + useconds);

	return mtime;
}

#define reset_longest_action_list(threshold) \
	do { \
		if ((threshold)) { \
			min_action_time=0; \
			memset(longest_action,0,LONGEST_ACTION_SIZE*sizeof(action_time)); \
		} \
	} while (0)

static inline void log_expiry(int time_diff,int expire,
					const char *func_info,char *extra_dbg,int dbg_len,int tcp)
{
	str param;
	evi_params_p list;
	static str func_str = str_init("source");
	static str time_str = str_init("time");
	static str extra_str = str_init("extra");
	int i;

	if (time_diff > expire)
	{
		if (tcp) {
			LM_WARN("threshold exceeded : tcp took too long : "
				"con_get=%d, rcv_fd=%d, send=%d. Source : %.*s\n",
				tcp_timeout_con_get,tcp_timeout_receive_fd,
				tcp_timeout_send,dbg_len,extra_dbg);
			time_diff = tcp_timeout_send + tcp_timeout_receive_fd +
				tcp_timeout_con_get;
		} else
			LM_WARN("threshold exceeded : %s took too long - %d us."
					"Source : %.*s\n",func_info,time_diff,dbg_len,extra_dbg);

		if (memcmp(func_info,"msg",3) == 0) {
			for (i=0;i<LONGEST_ACTION_SIZE;i++) {
				if (longest_action[i].a) {
					if ((unsigned char)longest_action[i].a->type == MODULE_T)
					LM_WARN("#%i is a module action : %s - %dus - line %d\n",i+1,
							((cmd_export_t*)(longest_action[i].a->elem[0].u.data))->name,
							longest_action[i].a_time,longest_action[i].a->line);
					else
					LM_WARN("#%i is a core action : %d - %dus - line %d\n",i+1,
							longest_action[i].a->type,
							longest_action[i].a_time,longest_action[i].a->line);
				}
			}
		}
		if (evi_probe_event(EVI_THRESHOLD_ID)) {

			param.s = (char *)func_info;
			param.len = strlen(func_info);
			if (!(list = evi_get_params()))
				return;
			if (evi_param_add_str(list, &func_str, &param)) {
				LM_ERR("unable to add func parameter\n");
				goto error;
			}
			if (evi_param_add_int(list, &time_str, &time_diff)) {
				LM_ERR("unable to add time parameter\n");
				goto error;
			}
			param.s = extra_dbg;
			param.len = dbg_len;
			if (evi_param_add_str(list, &extra_str, &param)) {
				LM_ERR("unable to add extra parameter\n");
				goto error;
			}
			if (evi_raise_event(EVI_THRESHOLD_ID, list)) {
				LM_ERR("unable to send event\n");
			}

		} else {
			LM_DBG("no event raised\n");
		}
	}
	return;
error:
	evi_free_params(list);
}

static inline int get_timestamp(int *sec,int *usec)
{
	struct timeval t;

	if (gettimeofday(&t,NULL) != 0)
	{
		LM_ERR("failed to get time of day\n");
		return -1;
	}

	*sec = t.tv_sec;
	*usec = t.tv_usec;

	return 0;
}

/*
 * checks if the string is a token as defined in rfc3261
 * returns:
 *  -1 - if the string is invalid
 *  1 - if the string is a token
 *  0 - not a token
 */
static inline int str_check_token( str * in)
{
	char *p;

	if (!in || !in->s || !in->len)
		return -1;

	p = in->s + in->len;
	while (p > in->s) {
		p--;
		if (!(
				/* alphanum */
				(*p >= 'a' && *p <= 'z') ||
				(*p >= 'A' && *p <= 'Z') ||
				(*p >= '0' && *p <= '9') ||
				/* other */
				*p == '-' || *p == '.' ||
				*p == '!' || *p == '%' ||
				*p == '*' || *p == '_' ||
				*p == '+' || *p == '`' ||
				*p == '\'' || *p == '~'
				))
			return 0;
	}
	return 1;
}


/*
 * l_memmem() returns the location of the first occurrence of data
 * pattern b2 of size len2 in memory block b1 of size len1 or
 * NULL if none is found. Obtained from NetBSD.
 */
static inline void * l_memmem(const void *b1, const void *b2,
													size_t len1, size_t len2)
{
	/* Initialize search pointer */
	char *sp = (char *) b1;

	/* Initialize pattern pointer */
	char *pp = (char *) b2;

	/* Initialize end of search address space pointer */
	char *eos = sp + len1 - len2;

	/* Sanity check */
	if(!(b1 && b2 && len1 && len2))
		return NULL;

	while (sp <= eos) {
		if (*sp == *pp)
			if (memcmp(sp, pp, len2) == 0)
				return sp;

		sp++;
	}

	return NULL;
}


int user2uid(int* uid, int* gid, char* user);

int group2gid(int* gid, char* group);

char * NTcopy_str( str *s );

/* utility function to give each children a unique seed */
void seed_child(unsigned int seed);


int parse_reply_codes( str *options_reply_codes_str,
		int **options_reply_codes, int *options_codes_no);

void base64encode(unsigned char *out, unsigned char *in, int inlen);
int base64decode(unsigned char *out,unsigned char *in,int len);

/*
 * "word64" is a combination between:
 *   - RFC 3261-compatible "word" token characters
 *   - modulo-64 encoding of base64
 */
void word64encode(unsigned char *out, unsigned char *in, int inlen);
int word64decode(unsigned char *out, unsigned char *in, int len);

#define calc_base64_encode_len(_l) (((_l)/3 + ((_l)%3?1:0))*4)
#define calc_max_base64_decode_len(_l) ((_l)*3/4)

#define calc_word64_encode_len calc_base64_encode_len
#define calc_max_word64_decode_len calc_max_base64_decode_len


#endif
