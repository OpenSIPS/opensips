/*
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
 * History:
 * -------
 * 2013-04-10: Created (Liviu)
 */

#include "bin_interface.h"
#include "config.h"
#include "daemonize.h"
#include "pt.h"
#include "net/net_udp.h"

struct socket_info *bin;


static char *send_buffer;
static char *cpos;

static char *rcv_buf;
static char *rcv_end;

static struct packet_cb_list *reg_modules;
/**
 * bin_init - begins the construction of a new binary packet (header part):
 *
 * +-------------------+-----------------------------------------------------------------+
 * |    12-byte HEADER           |       BODY                max 65535 bytes             |
 * +-------------------+-----------------------------------------------------------------+
 * | PK_MARKER |PGK LEN| Version | LEN | MOD_NAME | CMD | LEN | FIELD | LEN | FIELD |....|
 * +-------------------+-----------------------------------------------------------------+
 *
 * @param: { LEN, MOD_NAME } + CMD
 */

short get_bin_pkg_version(void)
{
	return  *(short *)(rcv_buf + BIN_PACKET_MARKER_SIZE + PKG_LEN_FIELD_SIZE);
}


void set_len(char *send_buffer, char *cpos){
	unsigned short len = cpos - send_buffer, *px;
	px = (unsigned short *) (send_buffer + BIN_PACKET_MARKER_SIZE);
	*px = len;
}

int bin_init(str *mod_name, int cmd_type, short version)
{
	if (!send_buffer) {
		send_buffer = pkg_malloc(BUF_SIZE);
		if (!send_buffer) {
			LM_ERR("No more pkg memory!\n");
			return -1;
		}
	}

	/* binary packet header: marker + pkg_len */
	memcpy(send_buffer, BIN_PACKET_MARKER, BIN_PACKET_MARKER_SIZE);
	cpos = send_buffer + BIN_PACKET_MARKER_SIZE + PKG_LEN_FIELD_SIZE;

	
	/* bin version */
	memcpy(cpos, &version, sizeof(version));
	cpos += VERSION_FIELD_SIZE;

	/* module name */
	memcpy(cpos, &mod_name->len, LEN_FIELD_SIZE);
	cpos += LEN_FIELD_SIZE;
	memcpy(cpos, mod_name->s, mod_name->len);
	cpos += mod_name->len;

	memcpy(cpos, &cmd_type, sizeof(cmd_type));
	cpos += sizeof(cmd_type);
	set_len(send_buffer, cpos);

	return 0;
}

/*
 * copies the given string at the 'cpos' position in the buffer
 * allows null strings (NULL content or NULL param)
 *
 * @return:
 *		> 0: success, the size of the buffer
 *		< 0: internal buffer limit reached
 */
int bin_push_str(const str *info)
{
	if (!cpos || (cpos - send_buffer + LEN_FIELD_SIZE + (info ? info->len : 0))
	              > BUF_SIZE)
		return -1;

	if (!info || info->len == 0 || !info->s) {
		memset(cpos, 0, LEN_FIELD_SIZE);
		cpos += LEN_FIELD_SIZE;
		return (int)LEN_FIELD_SIZE;
	}

	memcpy(cpos, &info->len, LEN_FIELD_SIZE);
	cpos += LEN_FIELD_SIZE;
	memcpy(cpos, info->s, info->len);
	cpos += info->len;
	set_len(send_buffer, cpos);

	return (int)(cpos - send_buffer);
}

/*
 * adds a new integer value at the 'cpos' position in the buffer
 *
 * @return:
 *		> 0: success, the size of the buffer
 *		< 0: internal buffer limit reached
 */
int bin_push_int(int info)
{
	if (!cpos || (cpos + sizeof(info) - send_buffer) > BUF_SIZE)
		return -1;

	memcpy(cpos, &info, sizeof(info));
	cpos += sizeof(info);

	set_len(send_buffer, cpos);
	
	return (int)(cpos - send_buffer);
}

int bin_get_buffer(str *buffer)
{
	if (!buffer)
		return -1;

	buffer->s = send_buffer;
	buffer->len = bin_send_size;

	return 1;
}

/*
 * skips @count integers from the current position in the received binary packet
 *
 * @return:
 *		>= 0: success, number of skipped bytes
 *		<  0: error, buffer limit reached
 */
int bin_skip_int(int count)
{
	int i;
	char *in = cpos;

	for (i = 0; i < count; i++) {
		if (cpos + LEN_FIELD_SIZE > rcv_end) {
			LM_ERR("Receive binary packet buffer overflow");
			return -1;
		}

		cpos += LEN_FIELD_SIZE;
	}

	return (int)(cpos - in);
}

/*
 * skips @count strings from the current position in a received binary packet
 *
 * @return:
 *		>= 0: success, number of skipped bytes
 *		<  0: error, buffer limit reached
 */
int bin_skip_str(int count)
{
	int i, len;
	char *in = cpos;


	for (i = 0; i < count; i++) {
		if (cpos + LEN_FIELD_SIZE > rcv_end)
			goto error;

		memcpy(&len, cpos, LEN_FIELD_SIZE);
		cpos += LEN_FIELD_SIZE;

		if (cpos + len > rcv_end)
			goto error;

		cpos += len;
	}

	return (int)(cpos - in);

error:
	LM_ERR("Receive binary packet buffer overflow");
	return -1;
}

/*
 * pops an str from the current position in the buffer
 * @info:   pointer to store the result
 *
 * @return:
 *		0 (success): info retrieved
 *		1 (success): nothing returned, all data has been consumed!
 *		< 0: error
 *
 * Note: The pointer returned in @info str is only valid for the duration of
 *       the callback. Don't forget to copy the info into a safe buffer!
 */
int bin_pop_str(str *info)
{
	if (cpos == rcv_end)
		return 1;

	if (cpos + LEN_FIELD_SIZE > rcv_end)
		goto error;

	memcpy(&info->len, cpos, LEN_FIELD_SIZE);
	cpos += LEN_FIELD_SIZE;

	if (cpos + info->len > rcv_end)
		goto error;

	if (info->len == 0)
		info->s = NULL;
	else
		info->s = cpos;

	cpos += info->len;

	LM_DBG("Popped: '%.*s' [%d]\n", info->len, info->s, info->len);

	return 0;

error:
	LM_ERR("Receive binary packet buffer overflow");
	return -1;
}

/*
 * pops an integer value from the current position in the buffer
 * @info:   pointer to store the result
 *
 * @return:
 *		0 (success): info retrieved
 *		1 (success): nothing returned, all data has been consumed!
 *		< 0: error
 */
int bin_pop_int(void *info)
{
	if (cpos == rcv_end)
		return 1;


	if (cpos + sizeof(int) > rcv_end) {
		LM_ERR("Receive binary packet buffer overflow");
		return -1;
	}

	memcpy(info, cpos, sizeof(int));
	cpos += sizeof(int);

	return 0;
}

/**
 * bin_register_cb - registers a module handler for specific packets
 * @mod_name: used to classify the incoming packets
 * @cb:       the handler function, called once for each matched packet
 *
 * @return:   0 on success
 */
int bin_register_cb(char *mod_name, void (*cb)(int, struct receive_info *, void * atr), void *att)
{
	struct packet_cb_list *new_mod;

	new_mod = pkg_malloc(sizeof(*new_mod));
	if (!new_mod) {
		LM_ERR("No more pkg mem!\n");
		return -1;
	}
	memset(new_mod, 0, sizeof(*new_mod));

	new_mod->cbf = cb;
	new_mod->module.len = strlen(mod_name);
	new_mod->module.s = mod_name;
	new_mod->att = att;

	new_mod->next = reg_modules;
	reg_modules = new_mod;

	return 0;
}


/*
 * main binary packet UDP receiver loop
 */


void call_callbacks(char* buffer, struct receive_info *rcv){
	str name;
	struct packet_cb_list *p;

	rcv_buf = buffer;

	get_name(rcv_buf, name);
	rcv_end = rcv_buf + *(unsigned short*)(buffer + BIN_PACKET_MARKER_SIZE);

	cpos = name.s + name.len + CMD_FIELD_SIZE;

	/* packet will be now processed by a specific module */
	for (p = reg_modules; p; p = p->next) {
		if (p->module.len == name.len &&
		    memcmp(name.s, p->module.s, name.len) == 0) {

			LM_DBG("binary Packet CMD: %d. Module: %.*s\n",
					bin_rcv_type, name.len, name.s);

			p->cbf(bin_rcv_type, rcv,p->att);

			break;
		}
	}
}


/*
 * called in the OpenSIPS initialization phase by the main process.
 * forks the binary packet UDP receivers.
 *
 * @return: 0 on success
 */

