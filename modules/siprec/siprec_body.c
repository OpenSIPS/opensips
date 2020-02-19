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

struct rtpproxy_binds srec_rtp;

int siprec_port_min = 35000;
int siprec_port_max = 65000;
int *siprec_port;
gen_lock_t *siprec_port_lock;

int srs_init(void)
{
	int tmp;
	if (siprec_port_min < 0 || siprec_port_min > 65535) {
		LM_ERR("invalid minimum port value %d\n", siprec_port_min);
		return -1;
	}
	if (siprec_port_max < 0 || siprec_port_max > 65535) {
		LM_ERR("invalid maximum port value %d\n", siprec_port_max);
		return -1;
	}
	if (siprec_port_max < siprec_port_min) {
		LM_NOTICE("port_max < port_min - swapping their values!\n");
		tmp = siprec_port_min;
		siprec_port_min = siprec_port_max;
		siprec_port_max = tmp;
	}

	siprec_port = shm_malloc(sizeof *siprec_port);
	if (!siprec_port) {
		LM_ERR("cannot alloc siprec port!\n");
		return -1;
	}
	*siprec_port = siprec_port_min;

	siprec_port_lock = lock_alloc();
	if (!siprec_port_lock) {
		LM_ERR("cannot alloc siprec port lock!\n");
		shm_free(siprec_port);
		return -1;
	}
	lock_init(siprec_port_lock);
	return 0;
}

static int srs_new_port(void)
{
	int port;
	lock_get(siprec_port_lock);
	if ((*siprec_port)++ >= siprec_port_max)
		*siprec_port = siprec_port_min;
	port = *siprec_port;
	lock_release(siprec_port_lock);
	return port;
}

static struct srs_sdp_stream *srs_get_stream(struct src_sess *ss, int label, int *part)
{
	int p;
	struct list_head *it;
	struct srs_sdp_stream *stream;

	for (p = 0; p < ss->participants_no; p++)
		list_for_each(it, &ss->participants[p].streams) {
			stream = list_entry(it, struct srs_sdp_stream, list);
			if (stream->label == label) {
				if (part)
					*part = p;
				return stream;
			}
		}
	return NULL;
}

void srs_free_stream(struct srs_sdp_stream *stream)
{
	list_del(&stream->list);
	if (stream->body.s)
		shm_free(stream->body.s);
	shm_free(stream);
}

static struct srs_sdp_stream *srs_get_part_stream(struct src_part *part, int medianum)
{
	struct list_head *it;
	struct srs_sdp_stream *stream;
	list_for_each(it, &part->streams) {
		stream = list_entry(it, struct srs_sdp_stream, list);
		if (stream->medianum == medianum)
			return stream;
	}
	return NULL;
}

/*
 * return the first character in the line if found,
 * and the entire line in line parameter
 */
static char srs_get_sdp_line(char *start, char *end, str *line)
{
	char *p = start;

	/* eat the spaces at the beginning */
	while (p < end && is_ws(*p))
		p++;
	/* nothing here */
	if (p == end)
		return 0;
	line->s = p;
	/* search for \r or \n */
	while (p < end && *p != '\r' && *p != '\n')
		p++;
	while (p < end && is_ws(*p))
		p++;
	line->len = p - line->s;
	if (line->len)
		return *line->s;
	else
		return 0;
}

int srs_add_raw_sdp_stream(int label, int medianum, str *body,
		siprec_uuid *uuid, struct src_sess *sess, struct src_part *part)
{
	struct srs_sdp_stream *stream = NULL;

	stream = shm_malloc(sizeof *stream);
	if (!stream) {
		LM_ERR("cannot allocate memory for new stream!\n");
		return -1;
	}
	memset(stream, 0, sizeof *stream);
	stream->body.s = shm_malloc(body->len);
	if (!stream->body.s) {
		LM_ERR("cannot add body for the loaded stream!\n");
		shm_free(stream);
		return -1;
	}
	stream->label = label;
	stream->medianum = medianum;
	memcpy(stream->body.s, body->s, body->len);
	stream->body.len = body->len;

	memcpy(stream->uuid, uuid, sizeof *uuid);
	list_add_tail(&stream->list, &part->streams);
	sess->streams_no++;

	return 0;
}

int srs_fill_sdp_stream(struct sip_msg *msg, struct src_sess *sess,
		struct src_part *part, int update)
{
	char sdp_type;
	char *tmps;
	char *allocated_buf;
	int label_len, media_inactive, tmp_len;
	sdp_info_t *msg_sdp;
	sdp_session_cell_t *msg_session;
	sdp_stream_cell_t *msg_stream;
	str tmp_buf, globals_buf, media_buf, line;
	char *start, *end;
	int streams_no = 0;
	int medianum = 0;
	int label;
	int stream_port;

	struct srs_sdp_stream *stream = NULL;

	msg_sdp = parse_sdp(msg);
	if (!msg_sdp)
		return 0;
	allocated_buf = NULL;
	/*
	 * we are only interested by streams, because everything else will be
	 * generated by us
	 */
	for (msg_session = msg_sdp->sessions; msg_session;
			msg_session = msg_session->next) {
		/* we first compute the global lines */

		/*
		 * we need to parse it line by line, because the parser does not
		 * support that; we allocate the whole body in sdp and adjust in shm
		 */
		allocated_buf = pkg_malloc(msg_session->body.len);
		if (!allocated_buf) {
			LM_ERR("no more pkg memory to build body stream!\n");
			return -1;
		}
		tmp_buf.s = allocated_buf;
		tmp_buf.len = 0;

		start = msg_session->body.s;
		end = start + msg_session->body.len;

		while ((sdp_type = srs_get_sdp_line(start, end, &line)) != 0) {
			/* globals are just until they reach m= line */
			if (sdp_type == 'm')
				break;
			/* XXX: we need separate buffers for each type, because they need
			 * to be all in order when we put them in the session */
			else if (sdp_type == 'b' ||sdp_type == 'z' || sdp_type == 'k' || sdp_type == 'a') {
				memcpy(tmp_buf.s + tmp_buf.len, line.s, line.len);
				tmp_buf.len += line.len;
			}
			start += line.len;
		}
		globals_buf = tmp_buf;

		for (msg_stream = msg_session->streams; msg_stream;
				msg_stream = msg_stream->next) {

			/* if it is not RTP, we are not interested */
			if (!msg_stream->is_rtp)
				continue;

			/* use the rest of the buffer here */
			tmp_buf.s += globals_buf.len;
			tmp_buf.len = 0;
			media_buf.s = 0;
			media_buf.len = 0;

			start = msg_stream->body.s;
			end = start + msg_stream->body.len;

			media_inactive = msg_stream->is_on_hold ? 1: 0;
			medianum++;

			if (update) {
				stream = srs_get_part_stream(part, medianum);
				if (!stream) {
					LM_ERR("cannot find stream for medianum = %d\n", medianum);
					goto stream_error;
				}
				stream_port = stream->port;
			} else {
				stream_port = srs_new_port();
			}

			while ((sdp_type = srs_get_sdp_line(start, end, &line)) != 0) {
				switch (sdp_type) {
				case 'm':
					/*
					 * the m line needs to be copied almost idetically, except
					 * the port needs to be altered to make sure it does not
					 * overlap
					 */
					media_buf = tmp_buf;

					/* media */
					memcpy(media_buf.s, line.s, msg_stream->port.s - line.s);
					media_buf.len += msg_stream->port.s - line.s;

					/* port */
					tmps = int2str(stream_port, &tmp_len);
					memcpy(media_buf.s + media_buf.len, tmps, tmp_len);
					media_buf.len += tmp_len;
					media_buf.s[media_buf.len++] = ' ';

					/* the rest of the transport */
					tmp_len = line.len - (msg_stream->transport.s - line.s);
					memcpy(media_buf.s + media_buf.len, msg_stream->transport.s, tmp_len);
					media_buf.len += tmp_len;

					/* adjust the tmp_buf */
					tmp_buf.s += media_buf.len;
					tmp_buf.len = 0;
					break;

				case 'a':
					/* we skip a=send/recv/only and a=label attributes
					 * because they will be added later by us */
					if (line.len > 8 /* a=label: */ &&
							memcmp(line.s + 2, "label:", 6) == 0)
						break;
					else if (line.len > 2 /* a= */ + 8 + 1/* \r */ &&
							(line.s[10] == '\r' || line.s[10] == '\n')) {
						if (memcmp(line.s + 2, "sendrecv", 8) == 0 ||
								memcmp(line.s + 2, "sendonly", 8) == 0) {
							media_inactive = 0;
							break;
						}
						if (memcmp(line.s + 2, "recvonly", 8) == 0 ||
								memcmp(line.s + 2, "inactive", 8) == 0) {
							media_inactive = 1;
							break;
						}
						LM_INFO("check passed for [%.*s]\n", 8, line.s + 2);
					}
				case 'b':
				case 'k':
					memcpy(tmp_buf.s + tmp_buf.len, line.s, line.len);
					tmp_buf.len += line.len;
					break;
				}
				start += line.len;
			}

			if (update) {
				/* get the stream from the participant */
				if (stream->body.s) {
					shm_free(stream->body.s);
					stream->body.s = NULL;
				}
				label = stream->label;
			} else {

				stream = shm_malloc(sizeof *stream);
				if (!stream) {
					LM_ERR("cannot alloc new stream!\n");
					goto stream_error;
				}
				memset(stream, 0, sizeof *stream);

				stream->medianum = medianum;

				/* initialize uuid */
				siprec_build_uuid(stream->uuid);
				stream->port = stream_port;

				label = sess->streams_no + 1;
				/* all good, add it into the sdp */
				stream->label = label;
			}
			/* compute the extra length of the stream */
			tmp_len = 12/* a=inactive\r\n or a=sendonly\r\n */;
			tmps = int2str(label, &label_len);
			tmp_len += 8 /* a=label: */ + label_len + 2 /* \r\n */;

			/* create a new stream to dump all data into */
			stream->body.s = shm_malloc(globals_buf.len +
					media_buf.len + tmp_buf.len + tmp_len);
			if (!stream->body.s) {
				LM_ERR("cannot alloc new body for stream!\n");
				goto stream_error;
			}

			/* m line */
			memcpy(stream->body.s, media_buf.s, media_buf.len);
			stream->body.len = media_buf.len;

			memcpy(stream->body.s + stream->body.len, globals_buf.s, globals_buf.len);
			stream->body.len += globals_buf.len;

			memcpy(stream->body.s + stream->body.len, tmp_buf.s, tmp_buf.len);
			stream->body.len += tmp_buf.len;

			/* a=label line */
			memcpy(stream->body.s + stream->body.len, "a=label:", 8);
			stream->body.len += 8;
			memcpy(stream->body.s + stream->body.len, tmps, label_len);
			stream->body.len += label_len;
			memcpy(stream->body.s + stream->body.len, "\r\na=", 4);
			stream->body.len += 4;

			/* sendonly or inactive */
			if (media_inactive)
				memcpy(stream->body.s + stream->body.len, "inactive\r\n", 10);
			else
				memcpy(stream->body.s + stream->body.len, "sendonly\r\n", 10);
			stream->body.len += 10;

			if (!update) {
				list_add_tail(&stream->list, &part->streams);
				sess->streams_no++;
			}

			streams_no++;
		}
		pkg_free(allocated_buf);
	}
	return streams_no;
stream_error:
	pkg_free(allocated_buf);
	return -1;
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

	media_ip = (sess->media_ip.s?sess->media_ip:localh);

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
		SIPREC_COPY("\"/>", buf);
	}
	SIPREC_COPY("\r\n\t<session session_id=\"", buf);
	SIPREC_COPY_UUID(sess->uuid, buf);
	if (!sess->group.s && !sess->dlg)
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
int srs_build_body(struct src_sess *sess, str *body, int type)
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

	if (type & SRS_BOTH) {
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
	}

	if (type & SRS_SDP && srs_build_sdp(sess, &buf) < 0)
		return -1;

	if (type & SRS_BOTH) {
		/* add second bondary */
		SIPREC_COPY_STR(boundary, &buf);

		/* Content-Type of SIPREC */
		SIPREC_COPY_STR(content_type, &buf);
		SIPREC_COPY_STR(siprec_content_type, &buf);
		SIPREC_COPY_STR(siprec_content_disposition, &buf);
		SIPREC_COPY(CRLF, &buf);
	}
	
	if (type & SRS_XML && srs_build_xml(sess, &buf) < 0)
		return -1;

	if (type & SRS_BOTH) {
		/* add final boundary */
		SIPREC_COPY_STR(boundary_end, &buf);
	}

	return 0;
}

int srs_handle_media(struct sip_msg *msg, struct src_sess *sess)
{
	int len;
	int label;
	int part = 0;
	int streams_no = -1;
	struct srs_sdp_stream *stream = NULL;
	sdp_info_t *msg_sdp;
	sdp_attr_t *attr;
	sdp_stream_cell_t *msg_stream;
	sdp_session_cell_t *msg_session;
	str destination;
	str *from_tag, *to_tag;

	msg_sdp = parse_sdp(msg);
	if (!msg_sdp) {
		LM_ERR("mising or invalid SDP!\n");
		return -1;
	}

	for (msg_session = msg_sdp->sessions; msg_session;
			msg_session = msg_session->next) {
		for (msg_stream = msg_session->streams; msg_stream;
				msg_stream = msg_stream->next) {
			/* first get the label, to know which stream we are talking about */
			label = -1;
			for (attr = msg_stream->attr; attr && label == -1; attr = attr->next) {
				if (attr->value.len != 0 && attr->attribute.len == 5 &&
					memcmp(attr->attribute.s, "label", 5) == 0) {
					if (str2sint(&attr->value, &label) < 0) {
						LM_ERR("invalid label number: %.*s - should have been numeric\n",
								attr->value.len, attr->value.s);
						continue;
					}
					stream = srs_get_stream(sess, label, &part);
					if (!stream) {
						LM_ERR("unknown media stream label: %d\n", label);
						label = -2;
					}
					break;
				}
			}
			if (label < 0 || !stream) {
				LM_INFO("SDP stream not processed for [%.*s]\n",
						msg_stream->body.len, msg_stream->body.s);
				continue;
			}
			LM_DBG("found stream %p for label %d\n", stream, label);

			len = 4/* udp: */;
			/* if there is an IP in the stream, use it, otherwise use the
			 * SDP session IP */
			if (msg_stream->ip_addr.len)
				len += msg_stream->ip_addr.len;
			else
				len += msg_session->ip_addr.len;
			len += 1/* : */ + msg_stream->port.len;

			/* build the socket to stream to */
			destination.s = pkg_malloc(len);
			if (!destination.s) {
				LM_ERR("cannot allocate destination buffer!\n");
				return -1;
			}
			memcpy(destination.s, "udp:", 4);
			destination.len = 4;
			if (msg_stream->ip_addr.len) {
				memcpy(destination.s + destination.len, msg_stream->ip_addr.s,
						msg_stream->ip_addr.len);
				destination.len += msg_stream->ip_addr.len;
			} else {
				memcpy(destination.s + destination.len, msg_session->ip_addr.s,
						msg_session->ip_addr.len);
				destination.len += msg_session->ip_addr.len;
			}
			destination.s[destination.len++] = ':';
			memcpy(destination.s + destination.len, msg_stream->port.s,
					msg_stream->port.len);
			destination.len += msg_stream->port.len;

			if (part) {
				from_tag = &sess->dlg->legs[callee_idx(sess->dlg)].tag;
				to_tag = &sess->dlg->legs[DLG_CALLER_LEG].tag;
			} else {
				from_tag = &sess->dlg->legs[DLG_CALLER_LEG].tag;
				to_tag = &sess->dlg->legs[callee_idx(sess->dlg)].tag;
			}

			if (srec_rtp.start_recording(&sess->dlg->callid, from_tag, to_tag,
					(sess->rtpproxy.s ? &sess->rtpproxy: NULL),
					NULL, &destination, stream->medianum) < 0) {
				LM_ERR("cannot start recording for stream %p (label=%d)\n",
						stream, stream->label);
			} else
				streams_no++;

			pkg_free(destination.s);
		}
	}

	return streams_no;
}


