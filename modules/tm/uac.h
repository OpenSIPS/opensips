/*
 * $Id$
 *
 */

#ifndef _UAC_H
#define _UAC_H

#include <stdio.h>
#include "config.h"
#include "t_dlg.h"

/* number of random digits in beginning of a string --
   please multiples of 2 */
#define RAND_DIGITS	6
/* maximum size of pid in hex characters */
#define MAX_PID_LEN	4
/* maximum seq size in hex chars */
#define MAX_SEQ_LEN (T_TABLE_POWER*2)

extern char *uac_from;
extern char *fifo;
extern int fifo_mode;
extern char call_id[RAND_DIGITS+1+MAX_PID_LEN+1+MAX_SEQ_LEN+1];
extern char from_tag[ MD5_LEN +1];

void uac_init();
void uac_child_init( int rank );
void generate_callid();

typedef int (*tuac_f)(str *msg_type, str *dst, str *headers,str *body,
	transaction_cb completion_cb );

int t_uac( 
	/* MESSAGE, OPTIONS, etc. */
	str *msg_type,  
	/* sip:foo@bar, will be put in r-uri and To */
	str *dst,	
	/* all other header fields separated by CRLF, including 
	   Content-type if body attached, excluding HFs
	   generated by UAC: To, Content_length, CSeq, Call-ID, Via, From
	*/
	str *headers, 
	/* body of the message if any */
	str *body,
	/* completion callback (optional) */
	transaction_cb completion_cb,
	/* callback parameter */
	void *cbp,
	struct dialog *dlg );

int fifo_uac( FILE *stream, char *response_file );
#endif
