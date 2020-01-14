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

#include "siprec_sess.h"
#include "siprec_body.h"
#include "siprec_logic.h"
#include "../../bin_interface.h"

struct tm_binds srec_tm;
struct dlg_binds srec_dlg;
static str srec_dlg_name = str_init("siprecX_ctx");

static struct src_sess *src_create_session(str *rtp, str *m_ip, str *grp,
		struct socket_info *si, int version, time_t ts, str *hdrs, siprec_uuid *uuid)
{
	struct src_sess *ss = shm_malloc(sizeof *ss + (rtp ? rtp->len : 0) +
			(m_ip ? m_ip->len : 0) + (grp ? grp->len : 0) + (hdrs ? hdrs->len : 0));
	if (!ss) {
		LM_ERR("not enough memory for creating siprec session!\n");
		return NULL;
	}
	memset(ss, 0, sizeof *ss);
	ss->socket = si;
	if (rtp) {
		ss->rtpproxy.s = (char *)(ss + 1);
		memcpy(ss->rtpproxy.s, rtp->s, rtp->len);
		ss->rtpproxy.len = rtp->len;
	}

	if (m_ip) {
		ss->media_ip.s = (char *)(ss + 1) + ss->rtpproxy.len;
		memcpy(ss->media_ip.s, m_ip->s, m_ip->len);
		ss->media_ip.len = m_ip->len;
	} else {
		ss->media_ip.s = NULL;
		ss->media_ip.len = 0;
	}

	if (grp) {
		ss->group.s = (char *)(ss + 1) + ss->rtpproxy.len + ss->media_ip.len;
		memcpy(ss->group.s, grp->s, grp->len);
		ss->group.len = grp->len;
	}

	if (hdrs && hdrs->len) {
		ss->headers.s = (char *)(ss + 1) + ss->rtpproxy.len + ss->media_ip.len +
			ss->group.len;
		memcpy(ss->headers.s, hdrs->s, hdrs->len);
		ss->headers.len = hdrs->len;
	}
	memcpy(ss->uuid, uuid, sizeof(*uuid));
	ss->participants_no = 0;
	ss->ts = ts;

	INIT_LIST_HEAD(&ss->srs);

	lock_init(&ss->lock);
	ss->ref = 0;

	return ss;
}

struct src_sess *src_new_session(str *srs, str *rtp, str *m_ip, str *grp,
		str *hdrs, struct socket_info *si)
{
	struct src_sess *sess;
	struct srs_node *node;
	char *p, *end;
	str s;

	siprec_uuid uuid;
	siprec_build_uuid(uuid);

	sess = src_create_session(rtp, m_ip, grp, si, 0, time(NULL), hdrs, &uuid);
	if (!sess)
		return NULL;

	/* parse the srs here */
	end = srs->s + srs->len;
	do {
		p = end - 1;
		while (p > srs->s && *p != ',')
			p--;
		if (p == srs->s)
			s.s = p;
		else
			s.s = p + 1; /* skip ',' */
		s.len = end - s.s;
		end = p;

		trim(&s);
		node = shm_malloc(sizeof(*node) + s.len);
		if (!node) {
			LM_ERR("cannot add srs node information!\n");
			src_free_session(sess);
			return NULL;
		}
		node->uri.s = (char *)(node + 1);
		node->uri.len = s.len;
		memcpy(node->uri.s, s.s, s.len);
		list_add(&node->list, &sess->srs);
		LM_DBG("add srs_uri %.*s\n", node->uri.len, node->uri.s);
	} while (end > srs->s);

	return sess;
}


void src_free_participant(struct src_part *part)
{
	struct srs_sdp_stream *stream;
	struct list_head *it, *tmp;

	list_for_each_safe(it, tmp, &part->streams) {
		stream = list_entry(it, struct srs_sdp_stream, list);
		srs_free_stream(stream);
	}
	if (part->aor.s)
		shm_free(part->aor.s);
	if (part->xml_val.s)
		shm_free(part->xml_val.s);
}

void src_unref_session(void *p)
{
	SIPREC_UNREF((struct src_sess *)p);
}

void src_free_session(struct src_sess *sess)
{
	int p;
	struct srs_node *node;

	/* extra check here! */
	if (sess->ref != 0) {
		LM_BUG("freeing session=%p with ref=%d\n", sess, sess->ref);
		return;
	}

	for (p = 0; p < sess->participants_no; p++)
		src_free_participant(&sess->participants[p]);
	while (!list_empty(&sess->srs)) {
		node = list_entry(sess->srs.next, struct srs_node, list);
		LM_DBG("freeing %.*s\n", node->uri.len, node->uri.s);
		list_del(&node->list);
		shm_free(node);
	}
	srec_logic_destroy(sess);
	lock_destroy(&sess->lock);
	shm_free(sess);
}

int src_add_participant(struct src_sess *sess, str *aor, str *name,
					str *xml_val, siprec_uuid *uuid, time_t *start)
{
	struct src_part *part;
	if (sess->participants_no >= SRC_MAX_PARTICIPANTS) {
		LM_ERR("no more space for new participants (have %d)!\n",
				sess->participants_no);
		return -1;
	}
	part = &sess->participants[sess->participants_no];
	INIT_LIST_HEAD(&part->streams);
	if (uuid)
		memcpy(part->uuid, uuid, sizeof *uuid);
	else
		siprec_build_uuid(part->uuid);

	if (xml_val) {
		part->xml_val.s = shm_malloc(xml_val->len);
		if (!part->xml_val.s) {
			LM_ERR("out of shared memory!\n");
			return -1;
		}
		memcpy(part->xml_val.s, xml_val->s, xml_val->len);
		part->xml_val.len = xml_val->len;
	} else {
		part->xml_val.s = NULL;

		part->aor.s = shm_malloc(aor->len + (name ? name->len: 0));
		if (!part->aor.s) {
			LM_ERR("out of shared memory!\n");
			return -1;
		}

		part->aor.len = aor->len;
		memcpy(part->aor.s, aor->s, aor->len);
		if (name) {
			/* remove the quotes, if provided */
			if (name->len > 2 && name->s[0] == '"') {
				name->s++;
				name->len -= 2;
			}
			part->name.len = name->len;
			part->name.s = part->aor.s + part->aor.len;
			memcpy(part->name.s, name->s, name->len);
		}
	}
	if (start)
		part->ts = *start;
	else
		part->ts = time(NULL);

	sess->participants_no++;

	return 1;
}

#define SIPREC_BIN_POP(_type, _value) \
	do { \
		if (bin_pop_##_type(&packet, _value) < 0) { \
			LM_ERR("cannot pop '" #_value "' from bin packet!\n"); \
			goto error; \
			return; \
		} \
	} while (0)

void srec_loaded_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *params)
{
	str buf;
	struct src_sess *sess = NULL;
	struct srs_node *node = NULL;
	bin_packet_t packet;
	int version;
	time_t ts;
	str tmp, rtpproxy, media_ip, srs_uri, group, host;
	str aor, name, xml_val, *xml;
	siprec_uuid uuid;
	struct socket_info *si;
	int p, port, proto, c, label, medianum;
	int p_type;

	if (!dlg) {
		LM_ERR("null dialog - cannot fetch siprec info!\n");
		return;
	}

	if (srec_dlg.fetch_dlg_value(dlg, &srec_dlg_name, &buf, 0) < 0) {
		LM_DBG("cannot fetch siprec info from the dialog\n");
		return;
	}
	bin_init_buffer(&packet, buf.s, buf.len);

	if (get_bin_pkg_version(&packet) != SIPREC_SESSION_VERSION) {
		LM_ERR("invalid serialization version (%d != %d)\n",
			get_bin_pkg_version(&packet), SIPREC_SESSION_VERSION);
		return;
	}

	SIPREC_BIN_POP(str, &tmp);
	if (tmp.len != sizeof(ts)) {
		LM_ERR("invalid length for timestamp (%d != %d)\n", tmp.len,
				(int)sizeof(ts));
		return;
	}
	memcpy(&ts, tmp.s, tmp.len);
	SIPREC_BIN_POP(int, &version);
	SIPREC_BIN_POP(str, &rtpproxy);
	SIPREC_BIN_POP(str, &media_ip);
	SIPREC_BIN_POP(str, &srs_uri);
	SIPREC_BIN_POP(str, &group);
	SIPREC_BIN_POP(str, &tmp);

	if (tmp.len) {
		if (parse_phostport(tmp.s, tmp.len, &host.s, &host.len,
				&port, &proto) != 0) {
			LM_ERR("bad socket <%.*s>\n", tmp.len, tmp.s);
			goto error;
		}

		si = grep_sock_info(&host, (unsigned short)port,
				(unsigned short)proto);
		if (!si)
			LM_DBG("non-local socket <%.*s>\n", tmp.len, tmp.s);
	} else
		si = NULL;

	SIPREC_BIN_POP(str, &tmp);
	if (tmp.len != sizeof(siprec_uuid)) {
		LM_ERR("invalid length for uuid (%d != %d)\n", tmp.len,
				(int)sizeof(siprec_uuid));
		return;
	}
	memcpy(&uuid, tmp.s, tmp.len);

	sess = src_create_session((rtpproxy.len ? &rtpproxy : NULL),
			(media_ip.len ? &media_ip : NULL), (group.len ? &group : NULL),
			si, version, ts, NULL /* we do not replicate headers */, &uuid);
	if (!sess) {
		LM_ERR("cannot create a new siprec session!\n");
		return;
	}

	node = shm_malloc(sizeof(*node) + srs_uri.len);
	if (!node) {
		LM_ERR("cannot add srs node information!\n");
		goto error;
	}
	node->uri.s = (char *)(node + 1);
	node->uri.len = srs_uri.len;
	memcpy(node->uri.s, srs_uri.s, srs_uri.len);
	list_add(&node->list, &sess->srs);

	SIPREC_BIN_POP(str, &tmp);
	sess->b2b_key.s = shm_malloc(tmp.len);
	if (!sess->b2b_key.s) {
		LM_ERR("cannot allocate memory for b2b_key!\n");
		goto error;
	}
	memcpy(sess->b2b_key.s, tmp.s, tmp.len);
	sess->b2b_key.len = tmp.len;
	SIPREC_BIN_POP(str, &tmp);
	sess->b2b_fromtag.s = shm_malloc(tmp.len);
	if (!sess->b2b_fromtag.s) {
		LM_ERR("cannot allocate memory for b2b_fromtag!\n");
		goto error;
	}
	memcpy(sess->b2b_fromtag.s, tmp.s, tmp.len);
	sess->b2b_fromtag.len = tmp.len;
	SIPREC_BIN_POP(str, &tmp);
	sess->b2b_totag.s = shm_malloc(tmp.len);
	if (!sess->b2b_totag.s) {
		LM_ERR("cannot allocate memory for b2b_totag!\n");
		goto error;
	}
	memcpy(sess->b2b_totag.s, tmp.s, tmp.len);
	sess->b2b_totag.len = tmp.len;
	SIPREC_BIN_POP(str, &tmp);
	sess->b2b_callid.s = shm_malloc(tmp.len);
	if (!sess->b2b_callid.s) {
		LM_ERR("cannot allocate memory for b2b_callid!\n");
		goto error;
	}
	memcpy(sess->b2b_callid.s, tmp.s, tmp.len);
	sess->b2b_callid.len = tmp.len;

	SIPREC_BIN_POP(int, &p);
	for (; p > 0; p--) {
		SIPREC_BIN_POP(int, &p_type); /* actual xml val or nameaddr ? */
		if (p_type == 0) {
			SIPREC_BIN_POP(str, &xml_val);
			xml = &xml_val;
		} else {
			SIPREC_BIN_POP(str, &aor);
			SIPREC_BIN_POP(str, &name);
			xml = NULL;
		}
		SIPREC_BIN_POP(str, &tmp);
		if (tmp.len != sizeof(siprec_uuid)) {
			LM_ERR("invalid length for uuid (%d != %d)\n", tmp.len,
					(int)sizeof(siprec_uuid));
			goto error;
		}
		memcpy(&uuid, tmp.s, tmp.len);
		SIPREC_BIN_POP(str, &tmp);
		if (tmp.len != sizeof(ts)) {
			LM_ERR("invalid length for timestamp (%d != %d)\n", tmp.len,
					(int)sizeof(ts));
			return;
		}
		memcpy(&ts, tmp.s, tmp.len);
		if (src_add_participant(sess, &aor, &name, xml, &uuid, &ts) < 0) {
			LM_ERR("cannot add new participant!\n");
			goto error;
		}
		SIPREC_BIN_POP(int, &c);
		for (; c > 0; c--) {
			SIPREC_BIN_POP(int, &label);
			SIPREC_BIN_POP(int, &medianum);
			SIPREC_BIN_POP(str, &tmp);
			if (tmp.len != sizeof(siprec_uuid)) {
				LM_ERR("invalid length for uuid (%d != %d)\n", tmp.len,
						(int)sizeof(siprec_uuid));
				goto error;
			}
			memcpy(&uuid, tmp.s, tmp.len);
			SIPREC_BIN_POP(str, &tmp);
			if (srs_add_raw_sdp_stream(label, medianum, &tmp, &uuid,
					sess, &sess->participants[sess->participants_no - 1]) < 0) {
				LM_ERR("cannot add new media stream!\n");
				goto error;
			}
		}
	}

	/* restore b2b callbacks */
	if (srec_restore_callback(sess) < 0) {
		LM_ERR("cannot restore b2b callbacks!\n");
		return;
	}

	/* all good: continue with dialog support! */
	SIPREC_REF(sess);
	sess->dlg = dlg;

	if (srec_register_callbacks(sess) < 0) {
		LM_ERR("cannot register callback for terminating session\n");
		SIPREC_UNREF(sess);
		goto error;
	}

	return;
error:
	if (sess)
		src_free_session(sess);
}
#undef SIPREC_BIN_POP

static inline str *srec_serialize(void *field, int size)
{
	static str ret;
	ret.s = field;
	ret.len = size;
	return &ret;
}

#define SIPREC_SERIALIZE(_f) srec_serialize(&_f, sizeof(_f))

#define SIPREC_BIN_PUSH(_type, _value) \
	do { \
		if (bin_push_##_type(&packet, _value) < 0) { \
			LM_ERR("cannot push '" #_value "' in bin packet!\n"); \
			bin_free_packet(&packet); \
			return; \
		} \
	} while (0)

void srec_dlg_write_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *params)
{
	str name = str_init("siprec");
	str empty = str_init("");
	bin_packet_t packet;
	struct src_sess *ss;
	int p, c;
	str buffer;
	struct list_head *l;
	struct srs_sdp_stream *s;

	if (!params) {
		LM_ERR("no parameter specified to dlg callback!\n");
		return;
	}
	ss = *params->param;

	if (bin_init(&packet, &name, 0, SIPREC_SESSION_VERSION, 0) < 0) {
		LM_ERR("cannot initialize bin packet!\n");
		return;
	}

	SIPREC_BIN_PUSH(str, SIPREC_SERIALIZE(ss->ts));
	SIPREC_BIN_PUSH(int, ss->version);
	SIPREC_BIN_PUSH(str, &ss->rtpproxy);
	SIPREC_BIN_PUSH(str, &ss->media_ip);
	/* push only the first SRS - this is the one chosen */
	SIPREC_BIN_PUSH(str, &SIPREC_SRS(ss));
	SIPREC_BIN_PUSH(str, &ss->group);
	if (ss->socket)
		SIPREC_BIN_PUSH(str, &ss->socket->sock_str);
	else
		SIPREC_BIN_PUSH(str, &empty);
	SIPREC_BIN_PUSH(str, SIPREC_SERIALIZE(ss->uuid));
	SIPREC_BIN_PUSH(str, &ss->b2b_key);
	SIPREC_BIN_PUSH(str, &ss->b2b_fromtag);
	SIPREC_BIN_PUSH(str, &ss->b2b_totag);
	SIPREC_BIN_PUSH(str, &ss->b2b_callid);
	SIPREC_BIN_PUSH(int, ss->participants_no);

	for (p = 0; p < ss->participants_no; p++) {
		if (ss->participants[p].xml_val.s) {
			/* serialize actual xml val */
			SIPREC_BIN_PUSH(int, 0);
			SIPREC_BIN_PUSH(str, &ss->participants[p].xml_val);
		} else {
			/* serialize nameaddr */
			SIPREC_BIN_PUSH(int, 1);
			SIPREC_BIN_PUSH(str, &ss->participants[p].aor);
			SIPREC_BIN_PUSH(str, &ss->participants[p].name);
		}
		SIPREC_BIN_PUSH(str, SIPREC_SERIALIZE(ss->participants[p].uuid));
		SIPREC_BIN_PUSH(str, SIPREC_SERIALIZE(ss->participants[p].ts));
		/* count the number of sessions */
		c = 0;
		list_for_each(l, &ss->participants[p].streams)
			c++;
		SIPREC_BIN_PUSH(int, c);
		list_for_each(l, &ss->participants[p].streams) {
			s = list_entry(l, struct srs_sdp_stream, list);
			SIPREC_BIN_PUSH(int, s->label);
			SIPREC_BIN_PUSH(int, s->medianum);
			SIPREC_BIN_PUSH(str, SIPREC_SERIALIZE(s->uuid));
			SIPREC_BIN_PUSH(str, &s->body);
		}
	}
	bin_get_buffer(&packet, &buffer);
	bin_free_packet(&packet);

	if (srec_dlg.store_dlg_value(dlg, &srec_dlg_name, &buffer) < 0) {
		LM_DBG("ctx was not saved in dialog\n");
		return;
	}
}
#undef SIPREC_SERIALIZE
#undef SIPREC_BIN_PUSH
