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

/* the amount of decimals to be displayed for "float" and "double" values */
#define FLOATING_POINT_PRECISION 8

/* zero-string wrapper */
#define ZSW(_c) ((_c)?(_c):"")

/* returns string beginning and length without insignificant chars */
#define trim_len( _len, _begin, _mystr ) \
	do{ 	static char _c; \
		(_len)=(_mystr).len; \
		while ((_len) && ((_c=(_mystr).s[(_len)-1])==0 || is_ws(_c))) \
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

#define TIMEVAL_MS_DIFF(_tva, _tvb) \
	((((_tvb).tv_sec * 1000000UL + (_tvb).tv_usec) - \
	 ((_tva).tv_sec * 1000000UL + (_tva).tv_usec)) / 1000UL)

/**
 * _add_last() - Walk the @next_member field of any struct and append last.
 * @what: Pointer to the struct that is to be appended.
 * @where: Pointer to the list that is to be appended to.
 * @next_member: The name of the member used to link to the next ones.
 *
 * If the list @where is NULL, @what will be assigned to it.
 */
#define _add_last(what, where, next_member) \
	do { \
		if (!(where)) { \
			(where) = (what); \
		} else { \
			typeof(where) __wit = (where); \
			while (__wit->next_member) \
				__wit = __wit->next_member; \
			__wit->next_member = (what); \
		} \
	} while (0)

/**
 * add_last() - Walk the "->next" field of any struct and append last.
 * @what: Pointer to the struct that is to be appended.
 * @where: Pointer to the list that is to be appended to.
 *
 * If the list @where is NULL, @what will be assigned to it.
 */
#define add_last(what, where) \
	_add_last(what, where, next)

/**
 * pkg_free_all() - pkg_free() each element of the given (circular) list.
 * @things: Pointer to the list that is to be freed in succession.
 *
 * The list is walked using "->next".
 */
#define pkg_free_all(things) \
	do { \
		typeof(things) pos = NULL, head = (things); \
		while ((things) && ((things) != head || !pos)) \
			{ pos = (things); (things) = (things)->next; pkg_free(pos); } \
	} while (0)

/**
 * shm_free_all() - shm_free() each element of the given (circular) list.
 * @things: Pointer to the list that is to be freed in succession.
 *
 * The list is walked using "->next".
 */
#define shm_free_all(things) \
	do { \
		typeof(things) pos = NULL, head = (things); \
		while ((things) && ((things) != head || !pos)) \
			{ pos = (things); (things) = (things)->next; shm_free(pos); } \
	} while (0)

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
#define INT2STR_BUF_NO    7
extern char int2str_buf[INT2STR_BUF_NO][INT2STR_MAX_LEN];
static inline char* int2str(uint64_t l, int* len)
{
	static unsigned int it = 0;

	if ((++it)==INT2STR_BUF_NO) it = 0;
	return int2bstr( l, int2str_buf[it], len);
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

static inline char* double2str(double d, int* len)
{
	static int buf;

	buf = (buf + 1) % INT2STR_BUF_NO;
	*len = snprintf(int2str_buf[buf], INT2STR_MAX_LEN - 1, "%0.*lf",
	                FLOATING_POINT_PRECISION, d);
	int2str_buf[buf][*len] = '\0';

	return int2str_buf[buf];
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


inline static int reverse_hex2int( char *c, int len, unsigned int *r)
{
	char *pc;
	char mychar;

	*r=0;
	for (pc=c+len-1; len>0; pc--, len--) {
		(*r) <<= 4 ;
		mychar=*pc;
		if ( mychar >='0' && mychar <='9') (*r)+=mychar -'0';
		else if (mychar >='a' && mychar <='f') (*r)+=mychar -'a'+10;
		else if (mychar  >='A' && mychar <='F') (*r)+=mychar -'A'+10;
		else return -1;
	}
	return 0;
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
inline static int reverse_hex2int64( char *c, int len, int unsafe, uint64_t *r)
{
	char *pc;
	char mychar;

	*r=0;
	for (pc=c+len-1; len>0; pc--, len--) {
		(*r) <<= 4 ;
		mychar=*pc;
		if ( mychar >='0' && mychar <='9') (*r)+=mychar -'0';
		else if (mychar >='a' && mychar <='f') (*r)+=mychar -'a'+10;
		else if (mychar  >='A' && mychar <='F') (*r)+=mychar -'A'+10;
		else if (unsafe)
			return 0;
		else return -1;
	}
	return 0;
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
	return orig_len * 2;
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

/* faster than glibc equivalents */
#define _isdigit(c) ((c) >= '0' && (c) <= '9')
#define _isalpha(c) \
	(((c) >= 'a' && (c) <= 'z') || \
	 ((c) >= 'A' && (c) <= 'Z'))
#define _isxdigit(c) \
	(((c) >= '0' && (c) <= '9') || \
	 ((c) >= 'a' && (c) <= 'f') || \
	 ((c) >= 'A' && (c) <= 'F'))
#define _isalnum(c) (_isalpha(c) || _isdigit(c))

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

static inline void unescape_crlf(str *in_out)
{
	char *p, *lim = in_out->s + in_out->len;

	if (ZSTR(*in_out))
		return;

	for (p = in_out->s; p < lim; p++) {
		if (*p == '\\' && p + 1 < lim) {
			if (*(p + 1) == 'r') {
				*p = '\r';
				memmove(p + 1, p + 2, lim - (p + 2));
				in_out->len--;
			} else if (*(p + 1) == 'n') {
				*p = '\n';
				memmove(p + 1, p + 2, lim - (p + 2));
				in_out->len--;
			}
		}
	}
}

static inline int _is_e164(const str* _user, int require_plus)
{
	char *d, *start, *end;

	if (_user->len < 1)
		return -1;

	if (_user->s[0] == '+') {
		start = _user->s + 1;
	} else {
		if (require_plus)
			return -1;
		start = _user->s;
	}

	end = _user->s + _user->len;
	if (end - start < 2 || end - start > 15)
		return -1;

	for (d = start; d < end; d++)
		if (!_isdigit(*d))
			return -1;

	return 1;
}
#define is_e164(_user) _is_e164(_user, 1)

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
		dst->len = 0;
		return -1;
	}

	memcpy(dst->s, src->s, src->len);
	dst->len = src->len;
	return 0;
}


/*
 * Make a copy of an str structure using shm_malloc
 *	  + an additional '\0' byte, so you can make use of dst->s
 *
 * dst == src is allowed!
 */
static inline int shm_nt_str_dup(str* dst, const str* src)
{
	const str _src = *src;

	if (!_src.s) {
		memset(dst, 0, sizeof *dst);
		return 0;
	}

	dst->s = shm_malloc(src->len + 1);
	if (!dst->s) {
		LM_ERR("no shared memory left\n");
		dst->len = 0;
		if (dst == src)
			*dst = _src;
		return -1;
	}

	memcpy(dst->s, _src.s, _src.len);
	dst->len = _src.len;
	dst->s[_src.len] = '\0';
	return 0;
}

/*
 * Make a copy of an str structure using pkg_malloc
 *	  + an additional '\0' byte, so you can make use of dst->s
 *
 * dst == src is allowed!
 */
static inline int pkg_nt_str_dup(str* dst, const str* src)
{
	const str _src = *src;

	if (!_src.s) {
		memset(dst, 0, sizeof *dst);
		return 0;
	}

	dst->s = pkg_malloc(_src.len + 1);
	if (!dst->s) {
		LM_ERR("no private memory left\n");
		dst->len = 0;
		if (dst == src)
			*dst = _src;
		return -1;
	}

	memcpy(dst->s, _src.s, _src.len);
	dst->len = _src.len;
	dst->s[_src.len] = '\0';
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
 * Ensure "dst" matches the content of "src" without leaking memory
 *
 * Note: if you just want to dup a string, use "shm_str_dup()" instead
 */
static inline int shm_str_sync(str* dst, const str* src)
{
	if (ZSTRP(src)) {
		if (dst->s)
			shm_free(dst->s);
		memset(dst, 0, sizeof *dst);
		return 0;
	}

	if (shm_str_extend(dst, src->len) != 0) {
		LM_ERR("oom\n");
		return -1;
	}

	memcpy(dst->s, src->s, src->len);
	dst->len = src->len;
	return 0;
}


static inline void shm_str_clean(str* dst)
{
	if (dst->s)
		shm_free(dst->s);
	memset(dst, 0, sizeof *dst);
}


/*
 * Make a copy of a str structure using pkg_malloc
 */
static inline int pkg_str_dup(str* dst, const str* src)
{
	dst->s = pkg_malloc(src->len);
	if (!dst->s) {
		LM_ERR("no private memory left\n");
		dst->len = 0;
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
static inline int pkg_str_extend(str *in, int size)
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
 * test if two str's are equal
 */
static inline int str_match(const str *a, const str *b)
{
	return a->len == b->len && !memcmp(a->s, b->s, a->len);
}


/*
 * test if two str's are equal, case-insensitive
 */
static inline int str_casematch(const str *a, const str *b)
{
	char *p, *q, *end;

	if (a->len != b->len)
		return 0;

	p = a->s;
	q = b->s;
	end = p + a->len;

	if (p == end || p == q)
		return 1;

	do {
		if (tolower(*p) != tolower(*q++))
			return 0;
	} while (++p < end);

	return 1;
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
#ifdef EXTRA_DEBUG
		LM_DBG("bad parameters\n");
#endif
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
 * compares a str with a const null terminated string
 */
static inline int str_match_nt(const str *a, const char *b)
{
	return a->len == strlen(b) && !memcmp(a->s, b, a->len);
}

/*
 * compares a str with a const null terminated string, case-insensitive
 */
static inline int str_casematch_nt(const str *a, const char *b)
{
	return a->len == strlen(b) && !strncasecmp(a->s, b, a->len);
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
#ifdef EXTRA_DEBUG
		LM_DBG("bad parameters\n");
#endif
		return NULL;
	}

	if (strb->len > stra->len)
		return NULL;

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
#ifdef EXTRA_DEBUG
		LM_DBG("bad parameters\n");
#endif
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
#ifdef EXTRA_DEBUG
		LM_DBG("bad parameters\n");
#endif
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
		if (threshold)	\
			gettimeofday(&(begin), NULL); \
	} while(0) \

#define __stop_expire_timer(begin,threshold,func_info, \
                           extra_s,extra_len,tcp,_slow_stat) \
	do { \
		if (threshold) { \
			int __usdiff__ = get_time_diff(&(begin)); \
			if (__usdiff__ > (threshold)) { \
				log_expiry(__usdiff__,(threshold),(func_info), \
				           (extra_s),(extra_len),tcp); \
				if (_slow_stat) \
					inc_stat(_slow_stat); \
			} \
		} \
	} while(0)

#define stop_expire_timer(begin,threshold,func_info,extra_s,extra_len,tcp) \
	__stop_expire_timer(begin,threshold,func_info, \
	                   extra_s,extra_len,tcp,(stat_var *)NULL)

#define _stop_expire_timer(begin,threshold,func_info,extra_s,extra_len,tcp, \
							slow, total) \
	do { \
		__stop_expire_timer(begin,threshold,func_info, \
							extra_s,extra_len,tcp,slow); \
		if (total) \
			inc_stat(total); \
	} while (0)

extern int tcp_timeout_con_get;
extern int tcp_timeout_receive_fd;
extern int tcp_timeout_send;

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
					if ((unsigned char)longest_action[i].a->type == CMD_T)
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

/**
 * Make any database URL log-friendly by masking its password, if any
 * Note: makes use of a single, static buffer -- use accordingly!
 */
char *db_url_escape(const str *url);
static inline char *_db_url_escape(char *url)
{
	return db_url_escape(_str(url));
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

void base64urlencode(unsigned char *out, unsigned char *in, int inlen);
int base64urldecode(unsigned char *out,unsigned char *in,int len);

/*
 * "word64" is a combination between:
 *   - RFC 3261-compatible "word" token characters
 *   - modulo-64 encoding of base64
 */
void word64encode(unsigned char *out, unsigned char *in, int inlen);
int word64decode(unsigned char *out, unsigned char *in, int len);

void _base32encode(unsigned char *out, unsigned char *in, int inlen,
	unsigned char pad_char);
int _base32decode(unsigned char *out, unsigned char *in, int len,
	unsigned char pad_char);

#define base32encode(out, in, inlen) _base32encode(out, in, inlen, '=')

/* also accepts lowercase letters as equivalent encoding characters
 * of uppercase letters */
#define base32decode(out, in, len) _base32decode(out, in, len, '=')

/* same as base32 but uses '-' instead of '=' as pad character */
#define word32encode(out, in, inlen) _base32encode(out, in, inlen, '-')
#define word32decode(out, in, len) _base32decode(out, in, len, '-')

#define calc_base64_encode_len(_l) (((_l)/3 + ((_l)%3?1:0))*4)
#define calc_max_base64_decode_len(_l) ((_l)*3/4)

#define calc_word64_encode_len calc_base64_encode_len
#define calc_max_word64_decode_len calc_max_base64_decode_len

#define calc_base32_encode_len(_l) (((_l)/5 + ((_l)%5?1:0))*8)
#define calc_max_base32_decode_len(_l) ((_l)*5/8)

#define calc_word32_encode_len calc_base32_encode_len
#define calc_max_word32_decode_len calc_max_base32_decode_len

#endif
