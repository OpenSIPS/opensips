/*
 * $Id$
 *
 * History:
 * -------
 * 2003-03-29 Created by janakj
 */

#ifndef DLG_H
#define DLG_H


#include "../../str.h"
#include "../../parser/parse_rr.h"
#include "../../parser/msg_parser.h"


/*
 * Dialog sequence
 */
typedef struct dlg_seq {
	unsigned int value;    /* Sequence value */
	unsigned char is_set;  /* is_set flag */
} dlg_seq_t;


/*
 * Dialog state
 */
typedef enum dlg_state {
	DLG_NEW = 0,   /* New dialog, no reply received yet */
	DLG_EARLY,     /* Early dialog, provisional response received */
	DLG_CONFIRMED, /* Confirmed dialog, 2xx received */
	DLG_DESTROYED  /* Destroyed dialog */
} dlg_state_t;


/*
 * Structure describing a dialog identifier
 */
typedef struct dlg_id {
	str call_id;    /* Call-ID */
	str rem_tag;    /* Remote tag of the dialog */
	str loc_tag;    /* Local tag of the dialog */
} dlg_id_t;


/*
 * Structure representing dialog state
 */
typedef struct dlg {
	dlg_id_t id;            /* Dialog identifier */
	dlg_seq_t loc_seq;      /* Local sequence number */
	dlg_seq_t rem_seq;      /* Remote sequence number */
	str loc_uri;            /* Local URI */
	str rem_uri;            /* Remote URI */
	str rem_target;         /* Remote target URI */
	unsigned char secure;   /* Secure flag -- currently not used */
	dlg_state_t state;      /* State of the dialog */
	rr_t* route_set;        /* Route set */
} dlg_t;


/*
 * Create a new dialog
 */
int new_dlg_uac(str* _cid, str* _ltag, unsigned int _lseq, str* _luri, str* _ruri, dlg_t** _d);


/*
 * A response arrived, update dialog
 */
int dlg_response_uac(dlg_t* _d, struct sip_msg* _m);


/*
 * Establishing a new dialog, UAS side
 */
int new_dlg_uas(struct sip_msg* _req, int _code, str* _tag, dlg_t** _d);


/*
 * UAS side - update a dialog from a request
 */
int dlg_request_uas(dlg_t* _d, struct sip_msg* _m);


/*
 * Destroy a dialog state
 */
void free_dlg(dlg_t* _d);


/*
 * Print a dialog structure, just for debugging
 */
void print_dlg(dlg_t* _d);


#endif /* DLG_H */
