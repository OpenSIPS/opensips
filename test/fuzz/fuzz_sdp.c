/*
 * Copyright (c) 2026 OpenSIPS Project fuzzing effort
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fuzz_sdp - exercise the SDP parser and the SIP body machinery.
 *
 * Threat model:
 * - Untrusted input: the fuzz input is the *body* of a SIP request, i.e.
 *   bytes received straight off the wire from any SIP peer.  SDP bodies are
 *   parsed on every session setup; multipart/mixed bodies are parsed before
 *   the SDP parts are extracted.
 * - Trust boundary crossed: parse_sdp_session() (raw SDP text -> session/
 *   stream trees), parse_sdp() + parse_sip_body() (SIP-level body handling,
 *   Content-Type dispatch and multipart splitting), and the stream/session
 *   lookup helpers.
 * - Attacker controls: the whole body (both raw SDP and the canned-message
 *   paths where the body is spliced into a valid INVITE).
 * - Real bug here: memory-safety violation, leak or crash on malformed SDP
 *   lines (o=/c=/m=/a= handling, attribute indexing, line folding, empty
 *   lines, huge counts) or on malformed multipart bodies.
 *
 * Design notes:
 * - path A parses the raw input as one SDP session blob;
 * - path B splices the input as application/sdp body of a canned INVITE
 *   (Content-Length fixed up in the constructor) and runs the full
 *   parse_msg -> parse_sdp pipeline;
 * - path C splices the input as the first part of a multipart/mixed body
 *   (second part text/plain) to drive the MIME splitter;
 * - the sdp_info_t is cleaned with free_sdp() on every path; the sip_msg
 *   with free_sip_msg(), so LSan reports only genuine product leaks;
 * - inputs are capped at 16 KiB; embedded NULs are rejected (parsers are
 *   line/printf-oriented, not the surface under test).
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../parser/sdp/sdp.h"
#include "../parser/msg_parser.h"
#include "../parser/parse_body.h"

#include "../dprint.h"
#include "../globals.h"
#include "../cmds.h"
#include "../lib/list.h"
#include "../sr_module.h"
#include "../sr_module_deps.h"
#include "../socket_info.h"
#include "../msg_translator.h"

#include "../test/fuzz/fuzz_standalone.h"

#define MAX_BODY_LEN (16 * 1024)

static char msg_inv[MAX_BODY_LEN + 1024];
static char msg_multipart[MAX_BODY_LEN + 1024];
static char mp_body[MAX_BODY_LEN + 512];

static const char inv_hdrs[] =
	"INVITE sip:bob@example.org SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKabc\r\n"
	"From: <sip:alice@example.com>;tag=ta123\r\n"
	"To: <sip:bob@example.org>\r\n"
	"Call-ID: cid-1@10.0.0.2\r\n"
	"CSeq: 314 INVITE\r\n"
	"Contact: <sip:alice@10.0.0.2:5060>\r\n"
	"Max-Forwards: 70\r\n"
	"Content-Type: application/sdp\r\n";

static const char mp_hdrs[] =
	"INVITE sip:bob@example.org SIP/2.0\r\n"
	"Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKabc\r\n"
	"From: <sip:alice@example.com>;tag=ta123\r\n"
	"To: <sip:bob@example.org>\r\n"
	"Call-ID: cid-1@10.0.0.2\r\n"
	"CSeq: 314 INVITE\r\n"
	"Contact: <sip:alice@10.0.0.2:5060>\r\n"
	"Max-Forwards: 70\r\n"
	"Content-Type: multipart/mixed;boundary=fuzz-bnd\r\n";

static const char mp_tail[] =
	"--fuzz-bnd\r\n"
	"Content-Type: text/plain\r\n"
	"\r\n"
	"trailer part\r\n"
	"--fuzz-bnd--\r\n";

int LLVMFuzzerTestOneInput(const char *data, size_t size)
{
	static char wbuf[MAX_BODY_LEN];
	str body;
	sdp_info_t *sdp;
	sdp_session_cell_t *sess;
	struct sip_msg msg = {};
	int i, n, blen;

	if (size == 0 || size > MAX_BODY_LEN)
		return 0;

	for (i = 0; i < (int)size; i++)
		if (data[i] == 0)
			return 0;

	memcpy(wbuf, data, size);

	/* path A: raw SDP session parse */
	body.s = wbuf;
	body.len = size;
	sdp = new_sdp();
	if (sdp != NULL) {
		if (parse_sdp_session(&body, 0, NULL, sdp) == 0) {
			n = sdp->sessions_num;
			for (i = 0; i < n; i++)
				get_sdp_session(sdp, i);
		}
		free_sdp(sdp);
	}

	/* path B: canned INVITE with the input as application/sdp body */
	snprintf(msg_inv, sizeof(msg_inv),
	    "%sContent-Length: %zu\r\n\r\n%.*s", inv_hdrs, size, (int)size,
	    wbuf);
	msg.buf = msg_inv;
	msg.len = strlen(msg_inv);
	if (parse_msg(msg.buf, msg.len, &msg) == 0) {
		msg.rcv.src_ip.af = AF_INET;
		parse_headers(&msg, HDR_EOH_F, 0);
		sdp = parse_sdp(&msg);
		if (sdp != NULL) {
			n = sdp->sessions_num;
			for (i = 0; i < n; i++) {
				sess = get_sdp_session(sdp, i);
				if (sess != NULL && sess->streams_num > 0 &&
				    sess->streams != NULL)
					get_sdp_payload4index(sess->streams,
					    0);
			}
		}
	}
	free_sip_msg(&msg);

	/* path C: multipart/mixed with the input as the SDP part */
	blen = snprintf(mp_body, sizeof(mp_body),
	    "--fuzz-bnd\r\nContent-Type: application/sdp\r\n\r\n%.*s\r\n%s",
	    (int)size, wbuf, mp_tail);
	snprintf(msg_multipart, sizeof(msg_multipart),
	    "%sContent-Length: %d\r\n\r\n%.*s", mp_hdrs, blen, blen, mp_body);
	memset(&msg, 0, sizeof(msg));
	msg.buf = msg_multipart;
	msg.len = strlen(msg_multipart);
	if (parse_msg(msg.buf, msg.len, &msg) == 0) {
		msg.rcv.src_ip.af = AF_INET;
		parse_headers(&msg, HDR_EOH_F, 0);
		parse_sdp(&msg);
	}
	free_sip_msg(&msg);

	return 0;
}
