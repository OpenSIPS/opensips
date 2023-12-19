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
#include "siprec_var.h"
#include "../../bin_interface.h"

struct tm_binds srec_tm;
struct dlg_binds srec_dlg;
static str srec_dlg_name = str_init("siprecX_ctx");

static struct src_sess *src_create_session(rtp_ctx rtp, str *m_ip, str *grp,
		const struct socket_info *si, int version, time_t ts, str *hdrs, siprec_uuid *uuid,
		str* group_custom_extension, str* session_custom_extension)
{
	struct src_sess *ss = shm_malloc(sizeof *ss + (m_ip ? m_ip->len : 0) +
			(grp ? grp->len : 0) + (hdrs ? hdrs->len : 0) +
			(group_custom_extension ? group_custom_extension->len : 0) +
			(session_custom_extension ? session_custom_extension->len : 0));
	if (!ss) {
		LM_ERR("not enough memory for creating siprec session!\n");
		return NULL;
	}
	memset(ss, 0, sizeof *ss);
	ss->socket = si;
	ss->rtp = rtp;

	if (m_ip) {
		ss->media.s = (char *)(ss + 1);
		memcpy(ss->media.s, m_ip->s, m_ip->len);
		ss->media.len = m_ip->len;
	} else {
		ss->media.s = NULL;
		ss->media.len = 0;
	}

	if (grp && grp->len) {
		ss->group.s = (char *)(ss + 1) + ss->media.len;
		memcpy(ss->group.s, grp->s, grp->len);
		ss->group.len = grp->len;
	}

	if (hdrs && hdrs->len) {
		ss->headers.s = (char *)(ss + 1) + ss->media.len +
			ss->group.len;
		memcpy(ss->headers.s, hdrs->s, hdrs->len);
		ss->headers.len = hdrs->len;
	}

	if (grp && grp->len && group_custom_extension && group_custom_extension->len) {
		ss->group_custom_extension.s = (char *)(ss + 1) + ss->media.len +
			ss->group.len + ss->headers.len;
		memcpy(ss->group_custom_extension.s, group_custom_extension->s, group_custom_extension->len);
		ss->group_custom_extension.len = group_custom_extension->len;
	}

	if (session_custom_extension && session_custom_extension->len) {
		ss->session_custom_extension.s = (char *)(ss + 1) + ss->media.len +
			ss->group.len + ss->headers.len + ss->group_custom_extension.len;
		memcpy(ss->session_custom_extension.s, session_custom_extension->s, session_custom_extension->len);
		ss->session_custom_extension.len = session_custom_extension->len;
	}

	memcpy(ss->uuid, uuid, sizeof(*uuid));
	ss->participants_no = 0;
	ss->ts = ts;

	INIT_LIST_HEAD(&ss->srs);

	lock_init(&ss->lock);
	ss->ref = 0;
#ifdef DBG_SIPREC_HIST
	ss->hist = sh_push(ss, srec_hist);
#endif

	return ss;
}

struct src_sess *src_new_session(str *srs, rtp_ctx rtp,
		struct srec_var *var)
{
	struct src_sess *sess;
	struct srs_node *node;
	char *p, *end;
	str s;

	siprec_uuid uuid;
	siprec_build_uuid(uuid);

	sess = src_create_session(rtp,
			(var && var->media.len)?&var->media:NULL,
			(var && var->group.len)?&var->group:NULL,
			(var?var->si:NULL), 0, time(NULL),
			(var && var->headers.len)?&var->headers:NULL,
			&uuid,
			(var && var->group_custom_extension.len)?&var->group_custom_extension:NULL,
			(var && var->session_custom_extension.len)?&var->session_custom_extension:NULL);

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

void src_free_session(struct src_sess *sess)
{
	int p;
	struct srs_node *node;

	/* extra check here! */
	if (sess->ref != 0) {
		srec_hlog(sess, SREC_DESTROY, "error destroying");
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
	if (sess->dlg)
		srec_dlg.dlg_ctx_put_ptr(sess->dlg, srec_dlg_idx, NULL);
	lock_destroy(&sess->lock);
#ifdef DBG_SIPREC_HIST
	srec_hlog(sess, SREC_DESTROY, "successful destroying");
	sh_flush(sess->hist);
	sh_unref(sess->hist);
	sess->hist = NULL;
#endif
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
		if (bin_pop_##_type(packet, _value) < 0) { \
			LM_ERR("cannot pop '" #_value "' from bin packet!\n"); \
			goto error; \
		} \
	} while (0)


static int srec_pop_sess(struct dlg_cell *dlg, bin_packet_t *packet)
{
	int version;
	time_t ts;
	str tmp, media_ip, srs_uri, group;
	str group_custom_extension, session_custom_extension;
	str aor, name, xml_val, *xml;
	siprec_uuid uuid;
	const struct socket_info *si;
	int p, c, label, medianum;
	rtp_ctx rtp;
	int p_type;
	int flags;
	str from_tag, to_tag;
	struct srs_node *node = NULL;
	struct src_sess *sess = NULL;

	/* first, double check if we've already done this */
	sess = (struct src_sess *)srec_dlg.dlg_ctx_get_ptr(dlg, srec_dlg_idx);
	if (sess) {
		LM_DBG("SIPREC session already popped\n");
		return 0;
	}

	/* retrieve the RTP information */
	rtp = srec_rtp.get_ctx_dlg(dlg);
	if (!rtp) {
		LM_DBG("no RTP Relay context not available!\n");
		return -1;
	}

	SIPREC_BIN_POP(str, &tmp);

	if (tmp.len != sizeof(ts)) {
		LM_ERR("invalid length for timestamp (%d != %d)\n", tmp.len,
				(int)sizeof(ts));
		return -1;
	}
	memcpy(&ts, tmp.s, tmp.len);
	SIPREC_BIN_POP(int, &version);
	SIPREC_BIN_POP(int, &flags);
	SIPREC_BIN_POP(str, &media_ip);
	SIPREC_BIN_POP(str, &srs_uri);
	SIPREC_BIN_POP(str, &group);

	SIPREC_BIN_POP(str, &group_custom_extension);
	if (group_custom_extension.s)
		LM_DBG("group custom extension: <%.*s>\n", group_custom_extension.len, group_custom_extension.s);

	SIPREC_BIN_POP(str, &session_custom_extension);
	if (group_custom_extension.s)
		LM_DBG("session custom extension: <%.*s>\n", session_custom_extension.len, session_custom_extension.s);

	SIPREC_BIN_POP(str, &tmp);

	if (tmp.len) {
		si = parse_sock_info(&tmp);
		if (!si)
			LM_DBG("non-local socket <%.*s>\n", tmp.len, tmp.s);
	} else
		si = NULL;

	SIPREC_BIN_POP(str, &tmp);
	if (tmp.len != sizeof(siprec_uuid)) {
		LM_ERR("invalid length for uuid (%d != %d)\n", tmp.len,
				(int)sizeof(siprec_uuid));
		return -1;
	}
	memcpy(&uuid, tmp.s, tmp.len);

	sess = src_create_session(rtp,
			(media_ip.len ? &media_ip : NULL), (group.len ? &group : NULL),
			si, version, ts, NULL /* we do not replicate headers */, &uuid,
			(group_custom_extension.len ? &group_custom_extension : NULL),
			(session_custom_extension.len ? &session_custom_extension : NULL));
	if (!sess) {
		LM_ERR("cannot create a new siprec session!\n");
		return -1;
	}
	sess->flags = flags;

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
	SIPREC_BIN_POP(str, &from_tag);
	SIPREC_BIN_POP(str, &to_tag);
	SIPREC_BIN_POP(str, &tmp);

	if (tmp.len) {
		sess->dlginfo = b2b_new_dlginfo(&tmp, &from_tag, &to_tag);
		if (!sess->dlginfo) {
			LM_ERR("could not create b2b dlginfo for %.*s/%.*s/%.*s!\n",
					tmp.len, tmp.s, from_tag.len, from_tag.s, to_tag.len, to_tag.s);
			goto error;
		}
	}

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
			goto error;
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
			if (srs_add_raw_sdp_stream(label, medianum, &uuid, sess,
					&sess->participants[sess->participants_no - 1]) < 0) {
				LM_ERR("cannot add new media stream!\n");
				goto error;
			}
		}
	}

	/* all good: continue with dialog support! */
	SIPREC_REF(sess);
	srec_hlog(sess, SREC_REF, "registered dlg");
	sess->dlg = dlg;

	/* restore b2b callbacks */
	if (srec_restore_callback(sess) < 0) {
		LM_ERR("cannot restore b2b callbacks!\n");
		goto error_unref;
	}

	srec_dlg.dlg_ctx_put_ptr(dlg, srec_dlg_idx, sess);

	if (srec_register_callbacks(sess) < 0) {
		LM_ERR("cannot register callback for terminating session\n");
		goto error_unref;
	}

	return 0;
error_unref:
	srec_hlog(sess, SREC_UNREF, "error registering dlg callbacks");
	SIPREC_UNREF(sess);
error:
	if (sess)
		src_free_session(sess);
	return -1;
}

void srec_loaded_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *params)
{
	int_str buf;
	int val_type;
	bin_packet_t packet;

	if (!dlg) {
		LM_ERR("null dialog - cannot fetch siprec info!\n");
		return;
	}

	if (srec_dlg.fetch_dlg_value(dlg, &srec_dlg_name, &val_type, &buf, 0) < 0) {
		LM_DBG("cannot fetch siprec info from the dialog\n");
		return;
	}

	bin_init_buffer(&packet, buf.s.s, buf.s.len);

	if (get_bin_pkg_version(&packet) != SIPREC_SESSION_VERSION) {
		LM_ERR("invalid serialization version (%d != %d)\n",
			get_bin_pkg_version(&packet), SIPREC_SESSION_VERSION);
		return;
	}

	if (srec_pop_sess(dlg, &packet) < 0)
		LM_ERR("failed to pop SIPREC session\n");
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
		if (bin_push_##_type(packet, _value) < 0) { \
			LM_ERR("cannot push '" #_value "' in bin packet!\n"); \
			return -1; \
		} \
	} while (0)

static int srec_push_sess(struct src_sess *ss, bin_packet_t *packet)
{
	str empty = str_init("");
	struct list_head *l;
	struct srs_sdp_stream *s;
	int p, c;

	SIPREC_BIN_PUSH(str, SIPREC_SERIALIZE(ss->ts));
	SIPREC_BIN_PUSH(int, ss->version);
	SIPREC_BIN_PUSH(int, ss->flags);
	SIPREC_BIN_PUSH(str, &ss->media);
	/* push only the first SRS - this is the one chosen */
	SIPREC_BIN_PUSH(str, &SIPREC_SRS(ss));
	SIPREC_BIN_PUSH(str, &ss->group);

	if (ss->group_custom_extension.s && ss->group_custom_extension.len)
		SIPREC_BIN_PUSH(str, &ss->group_custom_extension);
	else
		SIPREC_BIN_PUSH(str, &empty);
	if (ss->session_custom_extension.s && ss->session_custom_extension.len)
		SIPREC_BIN_PUSH(str, &ss->session_custom_extension);
	else
		SIPREC_BIN_PUSH(str, &empty);

	if (ss->socket)
		SIPREC_BIN_PUSH(str, &ss->socket->sock_str);
	else
		SIPREC_BIN_PUSH(str, &empty);
	SIPREC_BIN_PUSH(str, SIPREC_SERIALIZE(ss->uuid));
	SIPREC_BIN_PUSH(str, &ss->b2b_key);
	if (ss->dlginfo) {
		SIPREC_BIN_PUSH(str, &ss->dlginfo->fromtag);
		SIPREC_BIN_PUSH(str, &ss->dlginfo->totag);
		SIPREC_BIN_PUSH(str, &ss->dlginfo->callid);
	} else {
		SIPREC_BIN_PUSH(str, &empty);
		SIPREC_BIN_PUSH(str, &empty);
		SIPREC_BIN_PUSH(str, &empty);
	}
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
		}
	}
	return 0;
}

void srec_dlg_write_callback(struct dlg_cell *dlg, int type,
		struct dlg_cb_params *params)
{
	str name = str_init("siprec");
	bin_packet_t packet;
	struct src_sess *ss;
	int_str buffer;

	if (!params) {
		LM_ERR("no parameter specified to dlg callback!\n");
		return;
	}
	ss = *params->param;

	if (bin_init(&packet, &name, 0, SIPREC_SESSION_VERSION, 0) < 0) {
		LM_ERR("cannot initialize bin packet!\n");
		return;
	}
	if (srec_push_sess(ss, &packet) < 0) {
		LM_ERR("cannot push session in bin packet!\n");
		bin_free_packet(&packet);
		return;
	}

	bin_get_buffer(&packet, &buffer.s);
	bin_free_packet(&packet);

	if (srec_dlg.store_dlg_value(dlg, &srec_dlg_name, &buffer, DLG_VAL_TYPE_STR) < 0) {
		LM_DBG("ctx was not saved in dialog\n");
		return;
	}
}

static void src_event_trigger_create(struct src_sess *sess, bin_packet_t *store)
{
	if (srec_push_sess(sess, store) < 0)
		LM_WARN("could not create replicated session!\n");
}

void src_event_trigger(enum b2b_entity_type et, str *key,
		str *logic_key, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend)
{
	struct src_sess *sess = (struct src_sess *)param;

	switch (event_type) {
		case B2B_EVENT_CREATE:
			src_event_trigger_create(sess, store);
			break;
		default:
			/* nothing else for now */
			break;
	}
}

static void src_event_receive_create(str *key, bin_packet_t *packet)
{
	struct dlg_cell *dlg;
	/* search for the dialog based on the key */
	dlg = srec_dlg.get_dlg_by_callid(key, 0);
	if (!dlg) {
		LM_ERR("cannot find replicated dialog for callid  %.*s\n", key->len, key->s);
		return;
	}

	if (srec_pop_sess(dlg, packet) < 0)
		LM_ERR("failed to pop SIPREC session\n");
	srec_dlg.dlg_unref(dlg, 1);
}

void src_event_received(enum b2b_entity_type et, str *key,
		str *logic_key, void *param, enum b2b_event_type event_type,
		bin_packet_t *store, int backend)
{
	if (!store)
		return;

	switch (event_type) {
		case B2B_EVENT_CREATE:
			src_event_receive_create(logic_key, store);
			break;
		default:
			/* nothing else for now */
			break;
	}
}
#undef SIPREC_SERIALIZE
#undef SIPREC_BIN_PUSH
