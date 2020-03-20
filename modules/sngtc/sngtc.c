/**
 * Copyright (C) 2013 OpenSIPS Solutions
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
 * History
 * -------
 * 2013-06-05  created (liviu)
 *
 */

#include <string.h>
#include <unistd.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../error.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../parser/sdp/sdp.h"
#include "../../data_lump.h"
#include "../../ut.h"
#include "../../pt.h"
#include "../../net/net_udp.h"
#include "../../net/net_tcp.h"
#include "../../mod_fix.h"
#include "../dialog/dlg_load.h"

#include <sng_tc/sngtc_node.h>

#include "sngtc.h"
#include "sngtc_proc.h"

static struct codec_mapping codec_str_mappings[] = {
	{ {"AMR",  3},    8000,   0, SNGTC_CODEC_AMR_475   },
	{ {"AMR",  3},    8000,   1, SNGTC_CODEC_AMR_515   },
	{ {"AMR",  3},    8000,   2, SNGTC_CODEC_AMR_590   },
	{ {"AMR",  3},    8000,   3, SNGTC_CODEC_AMR_670   },
	{ {"AMR",  3},    8000,   4, SNGTC_CODEC_AMR_740   },
	{ {"AMR",  3},    8000,   5, SNGTC_CODEC_AMR_795   },
	{ {"AMR",  3},    8000,   6, SNGTC_CODEC_AMR_1020  },
	{ {"AMR",  3},    8000,   7, SNGTC_CODEC_AMR_1220  },
	{ {"G722", 4},    8000,  -1, SNGTC_CODEC_G722      },
	{ {"G723", 4},    8000,  -1, SNGTC_CODEC_G723_1    },
	{ {"G723", 4},    8000,  -1, SNGTC_CODEC_G723_1    },
	{ {"G726-16", 7}, 8000,  -1, SNGTC_CODEC_G726_16   },
	{ {"G726-24", 7}, 8000,  -1, SNGTC_CODEC_G726_24   },
	{ {"G726-32", 7}, 8000,  -1, SNGTC_CODEC_G726_32   },
	{ {"G726-40", 7}, 8000,  -1, SNGTC_CODEC_G726_40   },
	{ {"G729", 4},    8000,  -1, SNGTC_CODEC_G729AB    },
	{ { "GSM", 3},    8000,  -1, SNGTC_CODEC_GSM_FR    },
	{ {"iLBC", 4},    8000,  -1, SNGTC_CODEC_ILBC      },
	{ { "L16", 3},    44100, -1, SNGTC_CODEC_L16_2     },
	{ { "L16", 3},    44100, -1, SNGTC_CODEC_L16_1     },
	{ {"PCMA", 4},    8000,  -1, SNGTC_CODEC_PCMA      },
	{ {"PCMA", 4},    8000,  -1, SNGTC_CODEC_PCMA      },
	{ {"PCMU", 4},    8000,  -1, SNGTC_CODEC_PCMU      },
	{ {"SIREN", 5},   16000, -1, SNGTC_CODEC_SIREN7_24 },
	{ { 0, 0 }, -1, -1, -1 }
};

/* Mappings of standard payload types and Sangoma codecs */
static struct codec_mapping codec_int_mappings[] = {
	{ { "0", 1}, 8000,  -1, SNGTC_CODEC_PCMU   },
	{ { "3", 1}, 8000,  -1, SNGTC_CODEC_GSM_FR },
	{ { "4", 1}, 8000,  -1, SNGTC_CODEC_G723_1 },
	{ { "8", 1}, 8000,  -1, SNGTC_CODEC_PCMA   },
	{ { "9", 1}, 8000,  -1, SNGTC_CODEC_G722   },
	{ { "10",2}, 44100, -1, SNGTC_CODEC_L16_2  },
	{ { "11",2}, 44100, -1, SNGTC_CODEC_L16_1  },
	{ { "18",2}, 8000,  -1, SNGTC_CODEC_G729AB },
	{ { "0", 0}, -1, -1, -1 }
};

/* internal module variables */
static str dlg_key_sngtc_info     = str_init("SngTc");

static str sdp_buffer = { NULL, 0 };

/* results of matchings on all streams of two endpoints */
static struct codec_pair codec_matches[MAX_STREAMS];

/* force a certain IP for the transcoding card (most often a public IP) */
static str card_ip_a, card_ip_b;

/* index of the current SIP UDP receiver's pipe */
static int pipe_index;

/* one R+W pipe for each SIP UDP receiver process */
int *sip_workers_pipes;

/* pipe for the sangoma worker */
int sangoma_pipe[2];

/* generic module functions */
static int mod_init(void);
static int child_init(int rank);
static void mod_destroy(void);

static sngtc_init_cfg_t sngtc_init_cfg;
static struct dlg_binds dlg_binds;


/* module specific functions */
static int sngtc_offer(struct sip_msg *msg);
static int w_sngtc_callee_answer(struct sip_msg *msg,
                                 str *gp_ip_a, str *gp_ip_b);
static int sngtc_callee_answer(struct sip_msg *msg);
static int sngtc_caller_answer(struct sip_msg *msg);

static int sng_logger(int level, char *fmt, ...);

static proc_export_t procs[] = {
	{ "sangoma_worker", NULL, NULL, sangoma_worker_loop, 1, 0 },
	{ 0, 0, 0, 0, 0, 0 },
};

static param_export_t params[] = {
	{ 0, 0, 0 }
};

static cmd_export_t cmds[] = {
	{"sngtc_offer", (cmd_function)sngtc_offer, {{0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE},
	{"sngtc_caller_answer", (cmd_function)sngtc_caller_answer, {{0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE},
	{"sngtc_callee_answer", (cmd_function)w_sngtc_callee_answer, {
		{CMD_PARAM_STR,0,0},
		{CMD_PARAM_STR,0,0}, {0,0,0}},
		REQUEST_ROUTE|ONREPLY_ROUTE},
	{0,0,{{0,0,0}},0}
};

static dep_export_t deps = {
	{ /* OpenSIPS module dependencies */
		{ MOD_TYPE_DEFAULT, "dialog", DEP_ABORT },
		{ MOD_TYPE_NULL, NULL, 0 },
	},
	{ /* modparam dependencies */
		{ NULL, NULL },
	},
};

struct module_exports exports= {
	"sngtc",
	MOD_TYPE_DEFAULT,/* class of this module */
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	0,
	&deps,           /* OpenSIPS module dependencies */
	cmds,
	0,
	params,
	0,
	0,
	0,
	0,				/* exported transformations */
	procs,
	0,
	mod_init,
	(response_function) 0,
	(destroy_function)mod_destroy,
	child_init,
	0               /* reload confirm function */
};

int sng_create_rtp(void * usr_priv, sngtc_codec_request_leg_t *codec_reg_leg,
                   sngtc_codec_reply_leg_t* codec_reply_leg, void **rtp_fd)
{
	LM_DBG("create_rtp callback\n");

	return 0;
}

int sng_create_rtp_port(void * usr_priv, uint32_t host_ip, uint32_t *rtp_port,
                        void **rtp_fd)
{
	LM_DBG("create_rtp_port callback\n");

	return 0;
}

int sng_destroy_rtp(void * usr_priv, void *fd)
{
	LM_DBG("destroy_rtp callback\n");

	return 0;
}

int sng_release_rtp_port(void * usr_priv, uint32_t host_ip, uint32_t rtp_port,
                         void *rtp_fd)
{
	LM_DBG("release_rtp_port callback\n");

	return 0;
}

void free_transcoding_sessions(struct sngtc_session_list *first)
{
	struct sngtc_session_list *session, *aux;
	struct sngtc_request req;
	int rc;

	req.type        = REQ_FREE_SESSION;
	req.response_fd = sip_workers_pipes[pipe_index + WRITE_END];

	for (session = first; session; ) {

		LM_DBG("freeing transcoding session %p\n", session->reply);
		sngtc_print_reply(L_DBG, session->reply);

		req.sng_reply = session->reply;

		if (write(sangoma_pipe[WRITE_END], &req, sizeof(req)) < 0) {
			LM_ERR("failed to write on sangoma pipe fd %d (%d: %s)\n",
			       sangoma_pipe[WRITE_END], errno, strerror(errno));
			goto free_mem;
		}

		if (read(sip_workers_pipes[pipe_index + READ_END], &rc, sizeof(rc)) < 0) {
			LM_ERR("failed to read sangoma worker reply on pipe fd %d (%d: %s)\n",
			       sip_workers_pipes[pipe_index + READ_END], errno,
			       strerror(errno));
			goto free_mem;
		}

		if (rc != 0) {
			LM_ERR("failed to free transcoding session\n");
			sngtc_print_reply(L_ERR, session->reply);
		}

		LM_DBG("successfully freed transcoding session\n");

free_mem:
		aux = session;
		session = session->next;

		shm_free(aux);
	}
}

/**
 * sngtc_dlg_terminated (callback) - completely free the struct sngtc_info *
 * attached to the dialog.
 *
 * Also releases the ongoing transcoding session(s) at card level
 */
void sngtc_dlg_terminated(struct dlg_cell *dlg, int type,
                          struct dlg_cb_params *params)
{
	str info_ptr;
	struct sngtc_info *info;
	int rc;

	rc = dlg_binds.fetch_dlg_value(dlg, &dlg_key_sngtc_info, &info_ptr, 0);

	if (rc == -1) {
		LM_ERR("failed to fetch caller sdp\n");
		return;
	} else  if (rc == -2)
		return;

	LM_DBG("freeing the sdp buffer\n");

	info = *(struct sngtc_info **)info_ptr.s;
	LM_DBG("Info ptr: %p\n", info);

	free_transcoding_sessions(info->sessions);

	if (info->caller_sdp.s)
		shm_free(info->caller_sdp.s);
	if (info->modified_caller_sdp.s)
		shm_free(info->modified_caller_sdp.s);

	shm_free(info);

	if (dlg_binds.store_dlg_value(dlg, &dlg_key_sngtc_info, NULL) < 0)
		LM_ERR("failed to clear dlg val with caller sdp\n");
}

static int mod_init(void)
{
	int i;
	int max_processes = count_child_processes();

	LM_INFO("initializing module\n");

	memset(&dlg_binds, 0, sizeof(dlg_binds));
	if (load_dlg_api(&dlg_binds) != 0) {
		LM_ERR("failed to load dlg api\n");
		return -1;
	}

	sdp_buffer.s = pkg_malloc(SDP_BUFFER_SIZE);
	if (!sdp_buffer.s) {
		LM_ERR("insufficient pkg memory\n");
		return -1;
	}

	LM_DBG("Children: %d\n", max_processes);

    sip_workers_pipes = pkg_malloc(2 * max_processes *
	                                sizeof(*sip_workers_pipes));
    if (!sip_workers_pipes) {
        LM_ERR("Not enough pkg mem\n");
        return -1;
    }

	if (pipe(sangoma_pipe) != 0) {
		LM_ERR("Failed to create sangoma worker pipe\n");
		return -1;
	}

	LM_DBG("Sangoma pipe: [%d %d]\n", sangoma_pipe[0], sangoma_pipe[1]);

	for (i = 0; i < max_processes; i++) {
		if (pipe(sip_workers_pipes + 2 * i) != 0) {
			LM_ERR("Failed to create pipe for UDP receiver %d\n", i);
			return -1;
		}

		LM_DBG("SIP pipe: [%d %d]\n", sip_workers_pipes[2 * i],
		       sip_workers_pipes[2 * i + 1]);
	}

	sngtc_init_cfg.operation_mode   = SNGTC_MODE_SOAP_CLIENT;
	sngtc_init_cfg.log              = sng_logger;
	sngtc_init_cfg.create_rtp       = sng_create_rtp;
	sngtc_init_cfg.create_rtp_port  = sng_create_rtp_port;
	sngtc_init_cfg.destroy_rtp      = sng_destroy_rtp;
	sngtc_init_cfg.release_rtp_port = sng_release_rtp_port;

	if (sngtc_detect_init_modules(&sngtc_init_cfg, &i) != 0) {
		LM_ERR("failed to detect vocallo modules\n");
		return -1;
	}

	LM_DBG("Detected %d vocallo modules\n", i);

	if (sngtc_activate_modules(&sngtc_init_cfg, &i) != 0) {
		LM_ERR("failed to activate vocallo modules\n");
		return -1;
	}

	LM_DBG("Activated %d vocallo modules\n", i);

	return 0;
}

static int child_init(int rank)
{
	LM_DBG("init child\n");

	if (rank < 1 )
		return 0;

	pipe_index = 2 * (process_no);

	close(sip_workers_pipes[pipe_index + WRITE_END]);

	LM_DBG("proc index: %d\n", pipe_index / 2);

	return 0;
}

static void mod_destroy(void)
{
	LM_INFO("destroying module\n");
}

static int sng_logger(int level, char *fmt, ...)
{
	va_list args;
	char buffer[256];

	va_start(args, fmt);

	vsnprintf(buffer, 256, fmt, args);

	switch (level) {
		LM_DBG("%s\n", buffer);
		break;

	case SNGTC_LOGLEVEL_INFO:
	case SNGTC_LOGLEVEL_STATS:
		LM_INFO("%s\n", buffer);
		break;

	case SNGTC_LOGLEVEL_WARN:
		LM_WARN("%s\n", buffer);
		break;

	case SNGTC_LOGLEVEL_ERROR:
		LM_ERR("%s\n", buffer);
		break;

	case SNGTC_LOGLEVEL_CRIT:
	default:
		LM_CRIT("%s\n", buffer);
	}

	va_end(args);

	return 0;
}

/**
 * store_sngtc_info - stores the caller's SDP body in the current dialog
 * in a struct sngtc_info *
 */
int store_sngtc_info(struct dlg_cell *dlg, str *body)
{
	struct sngtc_info *info;
	str st;

	/* duplicate the body in shm and store the pointer in the dialog */
	info = shm_malloc(sizeof(*info));
	if (!info) {
		LM_ERR("no more shm\n");
		return -1;
	}

	memset(info, 0, sizeof(*info));

	lock_init(&info->lock);
	info->caller_sdp.s = shm_malloc(body->len);
	if (!info->caller_sdp.s) {
		LM_ERR("no more shm\n");
		goto exit;
	}

	info->caller_sdp.len = body->len; /* SDP parser needs starting CRLF */
	memcpy(info->caller_sdp.s, body->s, info->caller_sdp.len);

	st.s   = (void *)&info;
	st.len = sizeof(void *);
	LM_DBG("storing info ptr: %p\n", (void *) st.s);
	if (dlg_binds.store_dlg_value(dlg, &dlg_key_sngtc_info, &st) != 0) {
		LM_ERR("failed to store msg body in dialog\n");
		goto exit;
	}

	LM_DBG("CALLER SDP: '%.*s' [%d]\n", info->caller_sdp.len,
	       info->caller_sdp.s, info->caller_sdp.len);

	return 0;

exit:
	if (info) {
		if (info->caller_sdp.s)
			shm_free(info->caller_sdp.s);
		shm_free(info);
	}

	return -1;
}

/**
 * sngtc_offer - will remove the SDP body of an early negotiation INVITE and
 * store it in the newly created dialog as a dlg_val.
 *
 * @return: 1 on success, negative on failure
 */
static int sngtc_offer(struct sip_msg *msg)
{
	struct hdr_field *hf;
	struct lump *lump;
	struct dlg_cell *dlg;
	struct sngtc_info *info = NULL;
	str body, totag, st;

	if (dlg_binds.create_dlg(msg, 0) < 0) {
		LM_ERR("failed to create dialog\n");
		return SNGTC_ERR;
	}

	dlg = dlg_binds.get_dlg();
	if (!dlg) {
		LM_ERR("failed to fetch current dialog\n");
		return SNGTC_ERR;
	}

	if (get_body(msg, &body) != 0 || body.len <= 0) {
		LM_ERR("can only do transcoding for early negotiation INVITES\n");
		return SNGTC_SDP_ERR;
	}

	totag = get_to(msg)->tag_value;

	/* INVITE retransmissions will skip this part */
	if (dlg_binds.fetch_dlg_value(dlg, &dlg_key_sngtc_info, &st, 0) != 0) {

		if (store_sngtc_info(dlg, &body) != 0) {
			LM_ERR("failed to create sngtc info struct\n");
			return SNGTC_ERR;
		}

		/* register a callback to free the above */
		if (dlg_binds.register_dlgcb(dlg,
			DLGCB_EXPIRED|DLGCB_FAILED|DLGCB_TERMINATED|DLGCB_DESTROY,
		    sngtc_dlg_terminated, NULL, NULL) != 0) {

			LM_ERR("failed to register dialog callback\n");
			return SNGTC_ERR;
		}

	/* for re-INVITES, just recreate the struct sngtc_info */
	} else if (totag.s && totag.len != 0) {
		info = *(struct sngtc_info **)(st.s);

		free_transcoding_sessions(info->sessions);
		if (info->caller_sdp.s)
			shm_free(info->caller_sdp.s);
		if (info->modified_caller_sdp.s)
			shm_free(info->modified_caller_sdp.s);

		if (store_sngtc_info(dlg, &body) != 0) {
			LM_ERR("failed to create sngtc info struct\n");
			return SNGTC_ERR;
		}

		shm_free(info);
	}

	LM_DBG("SDP body:\n");
	LM_DBG("%.*s\n", body.len, body.s);

	hf = msg->content_type;

	/* delete the Content-Type header, we're setting up late negotiation */
	lump = del_lump(msg, hf->name.s - msg->buf, hf->len, HDR_OTHER_T);
	if (!lump) {
		LM_ERR("no more pkg mem\n");
		return SNGTC_ERR;
	}

	/* trim the entire SDP body */
	lump = del_lump(msg, body.s - msg->buf, body.len, HDR_OTHER_T);
	if (!lump) {
		LM_ERR("no more pkg mem\n");
		return SNGTC_ERR;
	}

	return 1;
}

/**
 * sngtc_get_codec_str - obtains the sngtc mapping for the given encoding name
 *
 * @return: on success: enum sngtc_codec_definition
 *          on failure: -1
 *
 * TODO: optimize: binary search (5 iterations instead of 25?)
 */
static int sngtc_get_codec_str(str *encode)
{
	int i;

	for (i = 0; codec_str_mappings[i].bitrate != -1; i++)
		if (codec_str_mappings[i].name.len == encode->len &&
		    str_strcasecmp(&codec_str_mappings[i].name, encode) == 0)
			return codec_str_mappings[i].sng_codec;

	return -1;
}

/**
 * sngtc_get_codec_int - obtains the sngtc mapping for the given payload type
 *
 * @return: on success: enum sngtc_codec_definition
 *          on failure: -1
 *
 * TODO: optimize: binary search (3 iterations instead of 8?)
 */
static int sngtc_get_codec_int(str *payload)
{
	int i;

	for (i = 0; codec_int_mappings[i].bitrate != -1; i++)
		if (codec_int_mappings[i].name.len == payload->len &&
		    str_strcasecmp(&codec_int_mappings[i].name, payload) == 0)
			return codec_int_mappings[i].sng_codec;

	return -1;
}

/**
 * remove_sdp_stream_attrs - removes all attributes from the specified stream
 *
 * @return: struct lump * with the removed information
 */
static struct lump *remove_sdp_stream_attrs(struct sip_msg *msg,
                                      struct sdp_stream_cell *stream)
{
	struct lump *lump;
	char *attrs_end = NULL;

	LM_DBG("Removing all %d codecs from SDP stream: |%.*s|\n",
	       stream->payloads_num, stream->payloads.len, stream->payloads.s);

	/* find the last parsed structure of the last attribute */
	if (stream->payload_attr->fmtp_string.len > 0) {
		attrs_end = stream->payload_attr->fmtp_string.s +
		          stream->payload_attr->fmtp_string.len;
	} else if (stream->payload_attr->rtp_params.len > 0) {
		attrs_end = stream->payload_attr->rtp_params.s +
		          stream->payload_attr->rtp_params.len;
	} else if (stream->payload_attr->rtp_clock.len > 0) {
		attrs_end = stream->payload_attr->rtp_clock.s +
		          stream->payload_attr->rtp_clock.len;
	}

	if (!attrs_end) {
		LM_ERR("invalid SDP stream received\n");
		print_sdp_stream(stream, L_ERR);
		return NULL;
	}

	lump = del_lump(msg, stream->payloads.s - msg->buf,
	                attrs_end - stream->payloads.s, HDR_OTHER_T);
	if (!lump) {
		LM_ERR("failed to add del lump\n");
		return NULL;
	}

	return lump;
}

int replace_sdp_stream_port(struct sip_msg *msg, struct sdp_stream_cell *stream,
                            unsigned int transcoder_port)
{
	struct lump *lump;
	char *p;

	lump = del_lump(msg, stream->port.s - msg->buf,
	                stream->port.len, HDR_OTHER_T);
	if (!lump) {
		LM_ERR("failed to add del lump\n");
		return -1;
	}

	p = pkg_malloc(6);
	if (!p) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	sprintf(p, "%d", transcoder_port);

	if (!insert_new_lump_after(lump, p, strlen(p), HDR_OTHER_T)) {
		LM_ERR("no more pkg mem\n");
		return -1;
	}

	return 0;
}

/**
 * write_sdp_stream_attr - writes a single attribute in the SDP stream, after
 * all the attributes had been previously wiped off with a del_lump operation
 *
 * If @reply is non-NULL, a 'c=IN IP4 X.X.X.X' line is added to the stream,
 * containing the transcoder card IP
 *
 * @return: 0 on success, negative on failure
 */
static int write_sdp_stream_attr(struct sip_msg *msg, struct lump *del_lump,
                                 struct sdp_payload_attr *attr,
                                 struct sngtc_codec_reply *reply)
{
	char *buf;
	int len = 0;
	struct in_addr addr;

	len += 2 * attr->rtp_payload.len + A_LINE_PREFIX_LEN + INET_ADDRSTRLEN +
	       attr->rtp_enc.len + 1 + 1 + attr->rtp_clock.len + 2 + C_LINE_LEN +
	       2 * CRLF_LEN;

	buf = pkg_malloc(len);
	if (!buf) {
		LM_ERR("no more pkg memory\n");
		return SNGTC_ERR;
	}

	if (reply) {

		len = sprintf(buf, "%.*s%s"
		                   "c=IN IP4 ", attr->rtp_payload.len,
						   attr->rtp_payload.s, CRLF);

		if (card_ip_b.s)
			len += sprintf(buf + len, "%.*s%s"
			                    "a=rtpmap:%.*s %.*s/%.*s",
			                    card_ip_b.len, card_ip_b.s, CRLF,
			                    attr->rtp_payload.len, attr->rtp_payload.s,
			                    attr->rtp_enc.len, attr->rtp_enc.s,
			                    attr->rtp_clock.len, attr->rtp_clock.s);
		else {
			addr.s_addr = ntohl(reply->a.codec_ip);

			if (!inet_ntop(AF_INET, &addr, buf + len, INET_ADDRSTRLEN)) {
				LM_ERR("Failed to convert IP from binary to string\n");
				return SNGTC_ERR;
			}

			while (buf[len])
				len++;

			len += sprintf(buf + len, "%s"
			                    "a=rtpmap:%.*s %.*s/%.*s", CRLF,
			                    attr->rtp_payload.len, attr->rtp_payload.s,
			                    attr->rtp_enc.len, attr->rtp_enc.s,
			                    attr->rtp_clock.len, attr->rtp_clock.s);
		}
	} else
		len = sprintf(buf, "%.*s%s"
		              "a=rtpmap:%.*s %.*s/%.*s",
		              attr->rtp_payload.len, attr->rtp_payload.s, CRLF,
		              attr->rtp_payload.len, attr->rtp_payload.s,
		              attr->rtp_enc.len, attr->rtp_enc.s,
		              attr->rtp_clock.len, attr->rtp_clock.s);

	if (!insert_new_lump_after(del_lump, buf, len, HDR_OTHER_T)) {
		LM_ERR("failed to insert lump with codec result\n");
		return SNGTC_ERR;
	}

	return 0;
}

/**
 * create_transcoding_session - creates a new Sangoma transcoding session and
 * adds it to the current dialog's list of ongoing transcoding sessions
 *
 * @info : output parameter, holds a list with all tc sessions on the card
 */
static struct sngtc_codec_reply *create_transcoding_session(
                   struct sngtc_codec_request *request, struct sngtc_info *info)
{
	struct sngtc_codec_reply *reply;
	struct sngtc_session_list *session;
	struct sngtc_request req;
	int rc;

	session = shm_malloc(sizeof(*session) + sizeof(*reply));
	if (!session) {
		LM_ERR("no more shm mem\n");
		return NULL;
	}

	reply = (struct sngtc_codec_reply *)(session + 1);
	session->next = NULL;
	session->reply = reply;

	LM_DBG("creating sng transcoding session\n");

	req.type        = REQ_CREATE_SESSION;
	req.response_fd = sip_workers_pipes[pipe_index + WRITE_END];
	req.sng_req     = *request;
	req.sng_reply   = reply;

	if (write(sangoma_pipe[WRITE_END], &req, sizeof(req)) < 0) {
		LM_ERR("failed to write on sangoma pipe fd %d (%d: %s)\n",
		       sangoma_pipe[WRITE_END], errno, strerror(errno));
		goto out_free;
	}

	if (read(sip_workers_pipes[pipe_index + READ_END], &rc, sizeof(rc)) < 0) {
		LM_ERR("failed to read sangoma worker reply on pipe fd %d (%d: %s)\n",
			sip_workers_pipes[pipe_index + READ_END], errno, strerror(errno));
		goto out_free;
	}

	if (rc != 0) {
		LM_ERR("failed to create sangoma transcoding session\n");
		goto out_free;
	}

	LM_DBG("created new transcoding session\n");
	sngtc_print_reply(L_DBG, reply);

	if (!info->sessions)
		info->sessions = info->last_session = session;
	else {
		info->last_session->next = session;
		info->last_session       = session;
	}

	return reply;

out_free:
	free_transcoding_sessions(info->sessions);
	shm_free(session);
	return NULL;
}

/**
 * match_codecs - intersects the attributes of SDP streams @s1 and @s2 and
 * stores the results in the @pair parameter
 *
 * @return:
 *    SNGTC_ON  - streams are incompatible, transcoding will be performed
 *    SNGTC_OFF - streams have at least 1 common codec
 *    SNGTC_UNSUP_CODECS - card cannot transcode from/into any codecs
 *    SNGTC_BAD_SDP - one stream has no attributes at all
 */
static int match_codecs(struct sdp_stream_cell *s1,
                        struct sdp_stream_cell *s2, struct codec_pair *pair)
{
	struct sdp_payload_attr *att1, *att2, *tatt1, *tatt2;
	int common_codec, tc1, tc2;
	int c1, c2;
	int i, j;

	common_codec = tc1 = tc2 = 0;
	att1 = att2 = tatt1 = tatt2 = NULL;

	LM_DBG("stream 1: %d codecs\n", s1->payloads_num);
	for (i = 0; i < s1->payloads_num && !common_codec; i++) {
		att1 = s1->p_payload_attr[i];

		LM_DBG("Codec: '%.*s'\n", att1->rtp_enc.len, att1->rtp_enc.s);

		if (att1->rtp_enc.len != 0)
			c1 = sngtc_get_codec_str(&att1->rtp_enc);
		else
			c1 = sngtc_get_codec_int(&att1->rtp_payload);

		if (!tc1 && c1 > 0) {
			tatt1 = att1;
			tc1 = c1;
		}

		LM_DBG("stream 2: %d codecs\n", s2->payloads_num);
		for (j = 0; j < s2->payloads_num; j++) {
			att2 = s2->p_payload_attr[j];

			LM_DBG("Codec: '%.*s'\n", att2->rtp_enc.len, att2->rtp_enc.s);

			/* if the attribute has a 'a=rtpmap' line, get that enc,
			 * otherwise use the default one for the payload type
			 */
			if (att2->rtp_enc.len != 0)
				c2 = sngtc_get_codec_str(&att2->rtp_enc);
			else
				c2 = sngtc_get_codec_int(&att2->rtp_payload);

			if (!tc2 && c2 > 0) {
				tatt2 = att2;
				tc2 = c2;
			}

			if (c1 == c2 && c1 != -1) {
				common_codec = 1;
				break;
			}
		}
	}

	if (!att1 || !att2) {
		LM_ERR("received bogus sdp with no attributes\n");

		LM_ERR("caller:\n");
		print_sdp_stream(s1, L_ERR);

		LM_ERR("callee:\n");
		print_sdp_stream(s2, L_ERR);
		pair->status = SNGTC_BAD_SDP;

		return SNGTC_BAD_SDP;
	}

	if (!tc1 || !tc2) {
		LM_ERR("endpoints have no common codecs and at least one side "
		       "contains only unsupported Sangoma codecs\n");

		LM_ERR("caller:\n");
		print_sdp_stream(s1, L_ERR);

		LM_ERR("callee:\n");
		print_sdp_stream(s2, L_ERR);
		pair->status = SNGTC_UNSUP_CODECS;

		return SNGTC_UNSUP_CODECS;
	}

	if (!common_codec) {
		pair->att1   = tatt1;
		pair->att2   = tatt2;
		pair->tc1    = tc1;
		pair->tc2    = tc2;
		pair->status = SNGTC_ON;
		return SNGTC_ON;
	}

	pair->att1   = att1;
	pair->att2   = att2;
	pair->status = SNGTC_OFF;

	return SNGTC_OFF;
}

static int process_stream(struct sdp_stream_cell *s1, struct sdp_stream_cell *s2,
                          str *src, str *dst, unsigned char idx)
{
	int rc = 0, len;
	struct sdp_payload_attr *att = codec_matches[idx].att2;
	struct in_addr addr;

	if (s1->next && s2->next)
		rc = process_stream(s1->next, s2->next, src, dst, idx - 1);
	else if (s1->next || s2->next)
		LM_ERR("found different number of SDP streams - choosing min\n");

	/* check if attribute port must be rewritten */
	if (codec_matches[idx].status == SNGTC_ON) {

		LM_DBG("codec tc status: TC ON\n");

		len = s1->port.s - src->s;
		memcpy(dst->s + dst->len, src->s, len);
		dst->len += len;
		dst->len += sprintf(dst->s + dst->len, "%d",
		                    codec_matches[idx].reply->b.codec_udp_port);
		src->s += len + s1->port.len;
	} else
		LM_DBG("codec tc status: TC OFF\n");

	/* copy everything up to the rtp payload list (0 3 101 ...)  */
	len = s1->p_payload_attr[0]->rtp_payload.s - src->s;
	memcpy(dst->s + dst->len, src->s, len);
	dst->len += len;
	src->s += len;

	if (codec_matches[idx].status == SNGTC_ON) {

		dst->len += sprintf(dst->s + dst->len, "%.*s%s"
		                                       "c=IN IP4 ",
							att->rtp_payload.len, att->rtp_payload.s, CRLF);

		if (card_ip_a.s)
			dst->len += sprintf(dst->s + dst->len, "%.*s%s"
			                        "a=rtpmap:%.*s %.*s/%.*s",
			                        card_ip_a.len, card_ip_a.s, CRLF,
			                        att->rtp_payload.len, att->rtp_payload.s,
			                        att->rtp_enc.len,     att->rtp_enc.s,
			                        att->rtp_clock.len,   att->rtp_clock.s);
		else {
			addr.s_addr = ntohl(codec_matches[idx].reply->b.codec_ip);
			if (!inet_ntop(AF_INET, &addr, dst->s + dst->len, INET_ADDRSTRLEN)) {
				LM_ERR("Failed to convert IP from binary to string\n");
				return SNGTC_ERR;
			}

			while (dst->s[dst->len])
				dst->len++;

			dst->len += sprintf(dst->s + dst->len, "%s"
			                        "a=rtpmap:%.*s %.*s/%.*s", CRLF,
			                        att->rtp_payload.len, att->rtp_payload.s,
			                        att->rtp_enc.len,     att->rtp_enc.s,
			                        att->rtp_clock.len,   att->rtp_clock.s);
		}
	} else
		dst->len += sprintf(dst->s + dst->len, "%.*s%s"
		                    "a=rtpmap:%.*s %.*s/%.*s",
		                    att->rtp_payload.len, att->rtp_payload.s, CRLF,
		                    att->rtp_payload.len, att->rtp_payload.s,
		                    att->rtp_enc.len,     att->rtp_enc.s,
		                    att->rtp_clock.len,   att->rtp_clock.s);

	return rc;
}

/**
 * performs the following operations at 200 OK time (early neg <-> late neg):
 *
 * - alters the callee's 200 OK message (adds the final decided codec)
 * - alters the caller's SDP (in memory), so it can be attached @ ACK
 * - opens transcoding sessions on the card if necessary
 *
 * Note: assumes all streams are on corresponding positions in both SDPs
 */
static int process_session(struct sip_msg *msg, struct sngtc_info *info, str *src,
                           str *dst, struct sdp_session_cell *s1,
                           struct sdp_session_cell *s2)
{
	struct sdp_stream_cell *sm1, *sm2;
	struct sngtc_session_list *tc_session;
	struct sngtc_codec_request request;
	struct sngtc_codec_reply *reply = NULL;
	struct codec_pair pair;
	struct lump *lump, *nl;
	struct in_addr addr;
	int rc = 0, ret, tc_on = 0;
	int idx;
	char buf[INET_ADDRSTRLEN];
	str repl;

	if (s1->next && s2->next)
		rc = process_session(msg, info, src, dst, s1->next, s2->next);
	else if (s1->next || s2->next)
		LM_ERR("endpoints have a different number of SDP sessions"
		       " - choosing min number\n");

	if (rc != 0)
		goto out;

	tc_session = info->sessions;
	for (idx = MAX_STREAMS - 1, sm1 = s1->streams, sm2 = s2->streams; sm1 && sm2;
	     sm1 = sm1->next, sm2 = sm2->next, idx--) {

		ret = match_codecs(sm1, sm2, &pair);
		codec_matches[idx] = pair;

		switch (ret) {

		case SNGTC_OFF:

			LM_DBG("NO NEED FOR TRANSCODING\n");

			/* delete codecs from 200 OK; write endpoint A codec */
			/* ip and port stay the same */
			lump = remove_sdp_stream_attrs(msg, sm2);
			if (!lump) {
				LM_ERR("failed to clear sdp codecs\n");
				return SNGTC_SDP_ERR;
			}

			LM_DBG("sdp stream:\n");
			print_sdp_stream(sm2, L_DBG);

			ret = write_sdp_stream_attr(msg, lump, pair.att2, NULL);
			if (ret != 0) {
				LM_ERR("failed to write sdp stream codec\n");
				return ret;
			}

			break;

		case SNGTC_ON:

			tc_on = 1;

			if (is_processed(info))
				goto use_existing_sessions;

			LM_DBG("TRANSCODING ([%d] %.*s:%.*s <--> [%d] %.*s:%.*s)\n",
			       pair.tc1, s1->ip_addr.len, s1->ip_addr.s, sm1->port.len,
				   sm1->port.s, pair.tc2, s2->ip_addr.len, s2->ip_addr.s,
				   sm2->port.len, sm2->port.s);

			memset(&request, 0, sizeof(request));

			request.usr_priv = NULL;

			/* Codec, ms, IP and port for side A */
			request.a.codec_id = pair.tc1;
			request.a.ms = 0;
			sprintf(buf, "%.*s", s1->ip_addr.len, s1->ip_addr.s);
			ret = inet_pton(AF_INET, buf, &addr);
			if (ret != 1) {
				LM_ERR("failed to convert ip %s to binary form (%d)\n",
				       s1->ip_addr.s, ret);
				return SNGTC_ERR;
			}
			request.a.host_ip = htonl(addr.s_addr);
			request.a.host_netmask = (unsigned int)-1;
			if (str2int(&sm1->port, &request.a.host_udp_port) != 0)
				LM_ERR("Failed to parse integer stored in port str '%.*s'\n",
						sm1->port.len, sm1->port.s);

			/* Codec, ms, IP and port for side B */
			request.b.codec_id = pair.tc2;
			request.b.ms = 0;
			sprintf(buf, "%.*s", s2->ip_addr.len, s2->ip_addr.s);
			ret = inet_pton(AF_INET, buf, &addr);
			if (ret != 1) {
				LM_ERR("failed to convert ip %.*s to binary form (%d)\n",
				       s2->ip_addr.len, s2->ip_addr.s, ret);
				return SNGTC_ERR;
			}
			request.b.host_ip = htonl(addr.s_addr);
			request.b.host_netmask = (unsigned int)-1;
			if (str2int(&sm2->port, &request.b.host_udp_port) != 0)
				LM_ERR("Failed to parse integer stored in port str '%.*s'\n",
						sm2->port.len, sm2->port.s);

			LM_DBG("Transcoding request: %d:%d <--> %d:%d\n", request.a.host_ip,
			       request.a.host_udp_port, request.b.host_ip,
			       request.b.host_udp_port);

			reply = create_transcoding_session(&request, info);
			if (!reply) {
				LM_ERR("Failed to create a transcoding session on the card\n");
				return SNGTC_TC_ERR;
			}

use_existing_sessions:

			LM_DBG("NEW TC SESSION!\n");

			if (is_processed(info)) {
				reply = tc_session->reply;
				tc_session = tc_session->next;
			}

			codec_matches[idx].reply = reply;

			/**
			 * delete codecs from 200 OK
			 * write the common codec
			 * replace IP with ip of Sangoma card
			 * replace port with endpoint A newly opened port on card
			 */
			lump = remove_sdp_stream_attrs(msg, sm2);
			if (!lump) {
				LM_ERR("failed to clear sdp codecs\n");
				return SNGTC_SDP_ERR;
			}

			nl = del_lump(msg, s2->ip_addr.s - msg->buf, s2->ip_addr.len, 0);
			if (!nl) {
				LM_ERR("failed to add del lump\n");
				return SNGTC_ERR;
			}

			if (pkg_str_dup(&repl, &card_ip_b) != 0) {
				LM_ERR("failed to dup in pkg mem\n");
				return SNGTC_ERR;
			}

			if (!insert_new_lump_after(nl, repl.s, repl.len, HDR_OTHER_T)) {
				LM_ERR("failed to insert lump with codec result\n");
				return SNGTC_ERR;
			}

			if (replace_sdp_stream_port(msg, sm2,
			                            reply->a.codec_udp_port) != 0) {
				LM_ERR("failed to rewrite sdp stream port\n");
				return SNGTC_ERR;
			}

			if (write_sdp_stream_attr(msg, lump, pair.att1, reply) != 0) {
				LM_ERR("failed to write sdp stream codecs\n");
				return SNGTC_ERR;
			}

			break;

		case SNGTC_UNSUP_CODECS:

			LM_ERR("endpoints have no common codecs and at least one side "
			       "contains only unsupported Sangoma codecs\n");

			LM_ERR("caller:\n");
			print_sdp_stream(sm1, L_ERR);

			LM_ERR("callee:\n");
			print_sdp_stream(sm2, L_ERR);
			return SNGTC_SDP_ERR;

		case SNGTC_BAD_SDP:

			LM_ERR("received bogus sdp with no attributes\n");

			LM_ERR("caller:\n");
			print_sdp_stream(sm1, L_ERR);

			LM_ERR("callee:\n");
			print_sdp_stream(sm2, L_ERR);
			return SNGTC_SDP_ERR;
		}
	}

	if (tc_on) {
		LM_DBG("transcoding: ON\n");

		memcpy(dst->s + dst->len, src->s, s1->ip_addr.s - src->s);
		dst->len += s1->ip_addr.s - src->s;
		dst->len += sprintf(dst->s + dst->len, "%.*s",
		                    card_ip_a.len, card_ip_a.s);
		src->s += s1->ip_addr.s - src->s + s1->ip_addr.len;
	} else
		LM_DBG("transcoding: OFF\n");

	rc |= process_stream(s1->streams, s2->streams, src, dst, MAX_STREAMS - 1);
out:
	return rc;
}

static int w_sngtc_callee_answer(struct sip_msg *msg,
                                 str *gp_ip_a, str *gp_ip_b)
{
	if (!gp_ip_a) {
		card_ip_a.s = card_ip_b.s = NULL;
		goto out;
	}

	card_ip_a = *gp_ip_a;

	if (!gp_ip_b) {
		card_ip_b.s = NULL;
		goto out;
	}

	card_ip_b = *gp_ip_b;

out:
	return sngtc_callee_answer(msg);
}

/**
 * sngtc_callee_answer - handles the SDP offer of the callee
 *
 * At this point, we have both offers of the endpoints, and can decide whether
 * transcoding is needed or not.
 */
static int sngtc_callee_answer(struct sip_msg *msg)
{
	struct dlg_cell *dlg;
	struct sngtc_info *info;
	str caller_sdp, dst;
	sdp_info_t sdp;
	str *sdp_ptr;
	int rc;

	LM_DBG("sngtc_callee_answer\n");

	dlg = dlg_binds.get_dlg();
	if (!dlg) {
		LM_ERR("failed to fetch current dialog\n");
		return SNGTC_ERR;
	}

	/* get the pointer to the SDP body of the caller */
	if (dlg_binds.fetch_dlg_value(dlg, &dlg_key_sngtc_info, &dst, 0) != 0) {
		LM_ERR("failed to fetch caller sdp\n");
		return SNGTC_ERR;
	}

	info = *(struct sngtc_info **)(dst.s);
	sdp_ptr = &info->caller_sdp;

	LM_DBG("ptrs: %p %p\n", sdp_ptr, info->caller_sdp.s);

	caller_sdp.len = sdp_ptr->len;
	caller_sdp.s   = sdp_ptr->s;

	lock_get(&info->lock);

	LM_DBG("FETCHED CALLER SDP: '%.*s' [%d]\n", caller_sdp.len, caller_sdp.s,
	       caller_sdp.len);

	memset(&sdp, 0, sizeof(sdp));
	if (parse_sdp_session(&caller_sdp, 0, NULL, &sdp) != 0) {
		LM_ERR("failed to parse caller sdp body\n");
		rc = SNGTC_SDP_ERR;
		goto out_free;
	}

	if (!parse_sdp(msg)) {
		LM_ERR("failed to parse callee sdp body\n");
		rc = SNGTC_SDP_ERR;
		goto out_free;
	}

	dst.s = sdp_buffer.s;
	dst.len = 0;

	/* perform all 200 OK SDP changes and pre-compute the ACK SDP body */
	rc = process_session(msg, info, &caller_sdp, &dst, sdp.sessions,
	                     get_sdp(msg)->sessions);
	if (rc != 0) {
		LM_ERR("failed to rewrite SDP bodies of the endpoints\n");
		goto out_free;
	}

	if (!is_processed(info)) {
		dst.s = sdp_buffer.s;
		LM_DBG("caller ACK SDP: '%.*s'\n", dst.len, dst.s);

		info->modified_caller_sdp.s = shm_malloc(dst.len);
		if (!info->modified_caller_sdp.s) {
			LM_ERR("no more shm memory\n");
			rc = SNGTC_ERR;
			goto out_free;
		}

		memcpy(info->modified_caller_sdp.s, dst.s, dst.len);
		info->modified_caller_sdp.len = dst.len;
	}

	info->flags |= PROCESSED_FLAG;
	lock_release(&info->lock);

	if (sdp.sessions)
		free_sdp_content(&sdp);

	return 1;

out_free:
	free_transcoding_sessions(info->sessions);
	lock_release(&info->lock);

	if (sdp.sessions)
		free_sdp_content(&sdp);

	return rc;
}

/**
 * sngtc_caller_answer - attaches an SDP body to ACK requests
 */
static int sngtc_caller_answer(struct sip_msg *msg)
{
	char *p;
	str body;
	struct dlg_cell *dlg;
	struct lump *lump;
	struct sngtc_info *info;
	int len;

	LM_DBG("processing ACK\n");

	if (get_body(msg, &body) != 0 || body.len > 0) {
		LM_ERR("ACK should not contain a SDP body\n");
		return SNGTC_ERR;
	}

	dlg = dlg_binds.get_dlg();
	if (!dlg) {
		LM_ERR("failed to fetch current dialog\n");
		return SNGTC_ERR;
	}

	/* get the SDP body from the INVITE which was mangled at 200 OK */
	if (dlg_binds.fetch_dlg_value(dlg, &dlg_key_sngtc_info, &body, 0) != 0) {
		LM_ERR("failed to fetch caller sdp\n");
		return SNGTC_ERR;
	}

	info = *(struct sngtc_info **)(body.s);

	/* duplicate the SDP in pkg mem for the lumps mechanism */
	if (pkg_str_dup(&body, &info->modified_caller_sdp) != 0) {
		LM_ERR("failed to dup in pkg mem\n");
		return SNGTC_ERR;
	}

	LM_DBG("Duplicated SDP: '%.*s'\n", body.len, body.s);

	lump = anchor_lump(msg, msg->content_length->name.s - msg->buf, 0);
	if (!lump) {
		LM_ERR("failed to insert anchor lump\n");
		return SNGTC_ERR;
	}

	p = pkg_malloc(SDP_CONTENT_TYPE_LEN);
	if (!p) {
		LM_ERR("no more pkg memory\n");
		return SNGTC_ERR;
	}

	/* add the Content-Type header */

	memcpy(p, "Content-Type: application/sdp\r\n", SDP_CONTENT_TYPE_LEN);

	if (!insert_new_lump_before(lump, p, SDP_CONTENT_TYPE_LEN, 0)) {
		LM_ERR("failed to insert Content-Type lump\n");
		return SNGTC_ERR;
	}

	LM_DBG("blen: %d\n", msg->content_length->body.len);

	lump = del_lump(msg, msg->content_length->body.s - msg->buf,
	                msg->content_length->body.len, HDR_OTHER_T);
	if (!lump) {
		LM_ERR("failed to insert del lump for the content length\n");
		return SNGTC_ERR;
	}

	p = pkg_malloc(CONTENT_LEN_DIGITS);
	if (!p) {
		LM_ERR("no more pkg memory\n");
		return SNGTC_ERR;
	}

	LM_DBG("len: %d\n", body.len);

	len = sprintf(p, "%d", body.len);

	if (!insert_new_lump_after(lump, p, len, HDR_OTHER_T)) {
		LM_ERR("failed to insert Content-Length lump\n");
		return SNGTC_ERR;
	}

	lump = anchor_lump(msg, msg->len - CRLF_LEN, 0);
	if (!lump) {
		LM_ERR("failed to insert anchor lump\n");
		return SNGTC_ERR;
	}

	if (!insert_new_lump_before(lump, body.s, body.len, 0)) {
		LM_ERR("failed to insert SDP body lump\n");
		return SNGTC_ERR;
	}

	return 1;
}

