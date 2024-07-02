/*
 * Copyright (C) 2017 OpenSIPS Project
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 *
 * History:
 * ---------
 *  2017-06-20  created (razvanc)
 */

#include <string.h>
#include "siprec_body.h"
#include "siprec_sess.h"
#include "../../parser/sdp/sdp.h"
#include "../../mem/shm_mem.h"
#include "../../msg_translator.h"
#include "../../ut.h"
#include "../../trim.h"

void srs_free_stream(struct srs_sdp_stream *stream)
{
	list_del(&stream->list);
	shm_free(stream);
}

int srs_fill_sdp_stream(int label, int medianum, siprec_uuid *uuid,
		struct src_sess *sess, struct src_part *part)
{
	struct list_head *it;
	struct srs_sdp_stream *stream = NULL;

	/* first, search for a corresponding stream */
	list_for_each(it, &part->streams) {
		stream = list_entry(it, struct srs_sdp_stream, list);
		/* if we have a uuid, it is possible that we've already
		 * created it */
		if (uuid) {
			if (siprec_cmp_uuid(uuid, &stream->uuid) == 0)
				break;
		} else if (stream->medianum == medianum) {
			/* if not, we might have the same medianum, so we need
			 * to update it */
			break;
		}
		stream = NULL;
	}
	if (stream) {
		if (uuid)
			memcpy(stream->uuid, uuid, sizeof *uuid);
		stream->label = label;
		return 0;
	}

	stream = shm_malloc(sizeof *stream);
	if (!stream) {
		LM_ERR("cannot allocate memory for new stream!\n");
		return -1;
	}
	memset(stream, 0, sizeof *stream);
	stream->label = label;
	stream->medianum = medianum;

	if (uuid)
		memcpy(stream->uuid, uuid, sizeof *uuid);
	else
		siprec_build_uuid(stream->uuid);
	list_add_tail(&stream->list, &part->streams);
	sess->streams_no++;

	return 0;
}

#define OSS_BOUNDARY_HDR CRLF "--" OSS_BOUNDARY CRLF
#define OSS_BOUNDARY_HDR_LEN (sizeof(OSS_BOUNDARY_HDR) - 1)
#define OSS_BOUNDARY_HDR_END CRLF "--" OSS_BOUNDARY "--" CRLF
#define OSS_BOUNDARY_HDR_END_LEN (sizeof(OSS_BOUNDARY_HDR_END) - 1)

#define OSS_CT_HDR "Content-Type: "
#define OSS_CT_HDR_LEN (sizeof(OSS_CT_HDR) - 1)

#define OSS_CT_SDP_HDR OSS_CT_HDR "application/sdp" CRLF
#define OSS_CT_SDP_HDR_LEN (sizeof(OSS_CT_SDP_HDR) - 1)

#define OSS_CT_SREC_HDR OSS_CT_HDR "application/rs-metadata+xml" CRLF
#define OSS_CT_SREC_HDR_LEN (sizeof(OSS_CT_SREC_HDR) - 1)

#define OSS_CD_SREC_HDR "Content-Disposition: recording-session" CRLF
#define OSS_CD_SREC_HDR_LEN (sizeof(OSS_CD_SREC_HDR) - 1)

struct srec_buffer {
	int length;
	str *buffer;
};

#define SIPREC_BUF_INC 512
#define SIPREC_ENSURE_SIZE(_size, _b) \
	do { \
		if ((_b)->length - (_b)->buffer->len < _size) { \
			do \
				(_b)->length += SIPREC_BUF_INC; \
			while ((_b)->length - (_b)->buffer->len < _size); \
			(_b)->buffer->s = pkg_realloc((_b)->buffer->s, (_b)->length); \
			if (!(_b)->buffer->s) { \
				LM_ERR("not enough pkg memory to build body!\n"); \
				return -1; \
			} \
		}\
	} while(0)
#define SIPREC_COPY_STR(_s, _b) \
	do { \
		SIPREC_ENSURE_SIZE(_s.len, _b); \
		memcpy((_b)->buffer->s + (_b)->buffer->len, _s.s, _s.len); \
		(_b)->buffer->len += _s.len; \
	} while(0)
#define SIPREC_COPY(_ct, _b) \
	do { \
		str tmp = str_init(_ct); \
		SIPREC_COPY_STR(tmp, _b); \
	} while(0)
#define SIPREC_COPY_INT(_i, _b); \
	do { \
		str tmp; \
		tmp.s = int2str(_i, &tmp.len); \
		SIPREC_COPY_STR(tmp, _b); \
	} while(0)
#define SIPREC_COPY_CHAR(_c, _b); \
	do { \
		SIPREC_ENSURE_SIZE(1, _b); \
		(_b)->buffer->s[(_b)->buffer->len++] = (_c); \
	} while(0)

#if 0
static int srs_build_sdp(struct src_sess *sess, struct srec_buffer *buf)
{
	int p;
	str media_ip;
	struct srs_sdp_stream *stream;
	struct list_head *it;
	/*
	 * SDP body format we use:
	 *
	 * v=0
	 * o=- <timestamp> <version> IN IP4 <mediaip>
	 * s=-
	 * c=IN IP4 <mediaip>
	 * t=0 0
	 * <streams*>
	 */
	str header1 = str_init("v=0" CRLF "o=- ");
	str header2 = str_init(" IN IP4 ");
	str header3 = str_init(CRLF "s=-" CRLF "c=IN IP4 ");
	str header4 = str_init("t=0 0" CRLF);
	str localh = str_init("127.0.0.1");
	str crlf_str = str_init(CRLF);

	media_ip = (sess->media.s?sess->media:localh);

	SIPREC_COPY_STR(header1, buf);
	SIPREC_COPY_INT(sess->ts, buf);
	SIPREC_COPY_CHAR(' ', buf);
	SIPREC_COPY_INT(sess->version, buf);
	SIPREC_COPY_STR(header2, buf);
	SIPREC_COPY_STR(media_ip, buf);
	SIPREC_COPY_STR(header3, buf);
	SIPREC_COPY_STR(media_ip, buf);
	SIPREC_COPY_STR(crlf_str, buf);
	SIPREC_COPY_STR(header4, buf);
	for (p = 0; p < sess->participants_no; p++) {
		list_for_each(it, &sess->participants[p].streams) {
			stream = list_entry(it, struct srs_sdp_stream, list);
			SIPREC_COPY_STR(stream->body, buf);
		}
	}

	return 1;
}
#endif

#define SIPREC_COPY_OPEN_TAG(_t, _b) \
		SIPREC_COPY("<" _t ">", _b);
#define SIPREC_COPY_CLOSE_TAG(_t, _b) \
		SIPREC_COPY("</" _t ">", _b);
#define SIPREC_COPY_UUID(_u, _b) \
	do { \
		str tmp; \
		tmp.s = (char *)_u; \
		tmp.len = SIPREC_UUID_LEN; \
		SIPREC_COPY_STR(tmp, buf); \
	} while(0)

static int srs_build_xml(struct src_sess *sess, struct srec_buffer *buf)
{
	str ts;
	int p, op;
	char time_buf[256];
	struct tm t;
	struct list_head *it;
	struct srs_sdp_stream *stream;
	str xml_header = str_init("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		"<recording xmlns='urn:ietf:params:xml:ns:recording:1'>\r\n\t");

	/* add headers */
	SIPREC_COPY_STR(xml_header, buf);
	SIPREC_COPY_OPEN_TAG("datamode", buf);
	SIPREC_COPY("complete", buf);
	SIPREC_COPY_CLOSE_TAG("datamode", buf);
	if (sess->group.s) {
		SIPREC_COPY("\r\n\t<group group_id=\"", buf);
		SIPREC_COPY_STR(sess->group, buf);
		SIPREC_COPY("\">", buf);

		if (sess->group_custom_extension.s) {
			LM_DBG("group_custom_extension: %.*s\n", sess->group_custom_extension.len, sess->group_custom_extension.s);
			LM_DBG("group_custom_extension.len: %d\n", sess->group_custom_extension.len);

			// add group custom extensions
			SIPREC_COPY("\r\n\t\t", buf);
			SIPREC_COPY_STR(sess->group_custom_extension, buf);
		}

		SIPREC_COPY("\r\n\t</group>", buf);
	}

	SIPREC_COPY("\r\n\t<session session_id=\"", buf);
	SIPREC_COPY_UUID(sess->uuid, buf);
	if (!sess->group.s && !sess->dlg && !sess->session_custom_extension.s)
		SIPREC_COPY("\"/>\r\n", buf);
	else {
		SIPREC_COPY("\">", buf);
		if (sess->dlg) {
			SIPREC_COPY("\r\n\t\t", buf);
			SIPREC_COPY_OPEN_TAG("sipSessionID", buf);
			SIPREC_COPY_STR(sess->dlg->callid, buf);
			SIPREC_COPY_CLOSE_TAG("sipSessionID", buf);
		}
		if (sess->group.s) {
			SIPREC_COPY("\r\n\t\t", buf);
			SIPREC_COPY_OPEN_TAG("group-ref", buf);
			SIPREC_COPY_STR(sess->group, buf);
			SIPREC_COPY_CLOSE_TAG("group-ref", buf);
		}

		if (sess->session_custom_extension.s) {
			// add session custom extensions
			SIPREC_COPY("\r\n\t\t", buf);
			SIPREC_COPY_STR(sess->session_custom_extension, buf);
		}

		SIPREC_COPY("\r\n\t</session>\r\n", buf);
	}

	for (p = 0; p < sess->participants_no; p++) {
		if (!sess->participants[p].aor.s && !sess->participants[p].xml_val.s)
			continue;
		SIPREC_COPY("\t<participant participant_id=\"", buf);
		SIPREC_COPY_UUID(sess->participants[p].uuid, buf);
		SIPREC_COPY("\">\r\n", buf);
		if (sess->participants[p].xml_val.s)
			SIPREC_COPY_STR(sess->participants[p].xml_val, buf);
		else {
			SIPREC_COPY("\t\t<nameID aor=\"", buf);
			SIPREC_COPY_STR(sess->participants[p].aor, buf);
			if (sess->participants[p].name.s) {
				SIPREC_COPY("\">\r\n\t\t\t<name>", buf);
				SIPREC_COPY_STR(sess->participants[p].name, buf);
				SIPREC_COPY("</name>\r\n\t\t</nameID>", buf);
			} else
				SIPREC_COPY("\"/>", buf);
		}
		SIPREC_COPY("\r\n\t</participant>\r\n", buf);
	}

	for (p = 0; p < sess->participants_no; p++) {
		if (!sess->participants[p].aor.s && !sess->participants[p].xml_val.s)
			continue;
		list_for_each(it, &sess->participants[p].streams) {
			stream = list_entry(it, struct srs_sdp_stream, list);
			SIPREC_COPY("\t<stream stream_id=\"", buf);
			SIPREC_COPY_UUID(stream->uuid, buf);
			SIPREC_COPY("\" session_id=\"", buf);
			SIPREC_COPY_UUID(sess->uuid, buf);
			SIPREC_COPY("\">\r\n\t\t<label>", buf);
			SIPREC_COPY_INT(stream->label, buf);
			SIPREC_COPY("</label>\r\n\t</stream>\r\n", buf);
		}
	}
	SIPREC_COPY("\t<sessionrecordingassoc session_id=\"", buf);
	SIPREC_COPY_UUID(sess->uuid, buf);
	SIPREC_COPY("\">\r\n\t\t<associate-time>", buf);
	localtime_r(&sess->ts, &t);
	ts.s = time_buf;
	ts.len = strftime(time_buf, 256, "%Y-%m-%dT%T%z", &t);
	SIPREC_COPY_STR(ts, buf);
	SIPREC_COPY("</associate-time>\r\n\t</sessionrecordingassoc>\r\n", buf);

	for (p = 0; p < sess->participants_no; p++) {
		if (!sess->participants[p].aor.s && !sess->participants[p].xml_val.s)
			continue;
		SIPREC_COPY("\t<participantsessionassoc participant_id=\"", buf);
		SIPREC_COPY_UUID(sess->participants[p].uuid, buf);
		SIPREC_COPY("\" session_id=\"", buf);
		SIPREC_COPY_UUID(sess->uuid, buf);
		SIPREC_COPY("\">\r\n\t\t<associate-time>", buf);
		localtime_r(&sess->participants[p].ts, &t);
		ts.s = time_buf;
		ts.len = strftime(time_buf, 256, "%Y-%m-%dT%T%z", &t);
		SIPREC_COPY_STR(ts, buf);
		SIPREC_COPY("</associate-time>\r\n\t</participantsessionassoc>\r\n", buf);
	}

	/* build stream associations */
	for (p = 0; p < sess->participants_no; p++) {
		if (!sess->participants[p].aor.s && !sess->participants[p].xml_val.s)
			continue;
		SIPREC_COPY("\t<participantstreamassoc participant_id=\"", buf);
		SIPREC_COPY_UUID(sess->participants[p].uuid, buf);
		SIPREC_COPY("\">\r\n", buf);
		list_for_each(it, &sess->participants[p].streams) {
			stream = list_entry(it, struct srs_sdp_stream, list);
			/* TODO: check if stream is active */
			SIPREC_COPY("\t\t<send>", buf);
			SIPREC_COPY_UUID(stream->uuid, buf);
			SIPREC_COPY("</send>\r\n", buf);
		}
		/* add the streams of all the other participants */
		for (op = 0; op < sess->participants_no; op++) {
			if (op == p)
				continue;
			if (!sess->participants[op].aor.s && !sess->participants[op].xml_val.s)
				continue;

			list_for_each(it, &sess->participants[op].streams) {
				stream = list_entry(it, struct srs_sdp_stream, list);
				/* TODO: check if stream is active */
				SIPREC_COPY("\t\t<recv>", buf);
				SIPREC_COPY_UUID(stream->uuid, buf);
				SIPREC_COPY("</recv>\r\n", buf);
			}
		}
		SIPREC_COPY("\t</participantstreamassoc>\r\n", buf);
	}

	SIPREC_COPY_CLOSE_TAG("recording", buf);

	return 1;
}

/*
 * You need to free the body->s after using it!
 */
int srs_build_body(struct src_sess *sess, str *sdp, str *body)
{
	struct srec_buffer buf;
	str boundary = str_init(CRLF "--" OSS_BOUNDARY CRLF);
	str boundary_end = str_init(CRLF "--" OSS_BOUNDARY "--" CRLF);
	str content_type = str_init("Content-Type: application/");
	str sdp_content_type = str_init("sdp" CRLF);
	str siprec_content_type = str_init("rs-metadata+xml" CRLF);
	str siprec_content_disposition =
		str_init("Content-Disposition: recording-session" CRLF);
	str tmp;

	body->s = 0;
	body->len = 0;
	buf.buffer = body;
	buf.length = 0;

	/* body may be a multipart consisting on a SDP and a SIPREC XML */

	/* first boundary */
	/* we do not add the first CRLF, because the message generator already
	 * adds it */
	tmp.s = boundary.s + 2;
	tmp.len = boundary.len - 2;
	SIPREC_COPY_STR(tmp, &buf);

	/* Content-Type of SDP */
	SIPREC_COPY_STR(content_type, &buf);
	SIPREC_COPY_STR(sdp_content_type, &buf);
	SIPREC_COPY(CRLF, &buf);

	if (sdp->s && sdp->len > 0)
		SIPREC_COPY_STR((*sdp), &buf);

	/* add second bondary */
	SIPREC_COPY_STR(boundary, &buf);

	/* Content-Type of SIPREC */
	SIPREC_COPY_STR(content_type, &buf);
	SIPREC_COPY_STR(siprec_content_type, &buf);
	SIPREC_COPY_STR(siprec_content_disposition, &buf);
	SIPREC_COPY(CRLF, &buf);

	if (srs_build_xml(sess, &buf) < 0)
		return -1;

	/* add final boundary */
	SIPREC_COPY_STR(boundary_end, &buf);

	return 0;
}
