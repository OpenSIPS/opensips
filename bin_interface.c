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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * History:
 * -------
 * 2013-04-10: Created (Liviu)
 */

#include "bin_interface.h"
#include "udp_server.h"
#include "config.h"
#include "daemonize.h"
#include "pt.h"

struct socket_info *bin;

int bin_children = 1;

static int child_index;

static char *send_buffer;
static char *cpos;

static char rcv_buf[BUF_SIZE];
static char *rcv_end;

static struct packet_cb_list *reg_modules;

/**
 * bin_init - begins the construction of a new binary packet (header part):
 *
 * +-------------------+------------------------------------------------------+
 * |  8-byte HEADER    |                 BODY                max 65535 bytes  |
 * +-------------------+------------------------------------------------------+
 * | PK_MARKER |  CRC  | LEN | MOD_NAME | CMD | LEN | FIELD | LEN | FIELD |...|
 * +-------------------+------------------------------------------------------+
 *
 * @param: { LEN, MOD_NAME } + CMD
 */
int bin_init(str *mod_name, int cmd_type)
{
	if (!send_buffer) {
		send_buffer = pkg_malloc(BUF_SIZE);
		if (!send_buffer) {
			LM_ERR("No more pkg memory!\n");
			return -1;
		}
	}

	/* binary packet header: marker + crc */
	memcpy(send_buffer, BIN_PACKET_MARKER, BIN_PACKET_MARKER_SIZE);
	cpos = send_buffer + HEADER_SIZE;

	/* module name */
	memcpy(cpos, &mod_name->len, LEN_FIELD_SIZE);
	cpos += LEN_FIELD_SIZE;
	memcpy(cpos, mod_name->s, mod_name->len);
	cpos += mod_name->len;

	memcpy(cpos, &cmd_type, sizeof(cmd_type));
	cpos += sizeof(cmd_type);

	return 0;
}

/*
 * copies the given string at the 'cpos' position in the buffer
 * allows null strings (NULL content or NULL param)
 *
 * @return: 0 on success
 */
int bin_push_str(const str *info)
{
	if (!cpos || (cpos - send_buffer + LEN_FIELD_SIZE + (info ? info->len : 0))
	              > BUF_SIZE)
		return -1;

	if (!info || info->len == 0 || !info->s) {
		memset(cpos, 0, LEN_FIELD_SIZE);
		cpos += LEN_FIELD_SIZE;
		return 0;
	}

	memcpy(cpos, &info->len, LEN_FIELD_SIZE);
	cpos += LEN_FIELD_SIZE;
	memcpy(cpos, info->s, info->len);
	cpos += info->len;

	return 0;
}

/*
 * adds a new integer value at the 'cpos' position in the buffer
 *
 * @return: 0 on success
 */
int bin_push_int(int info)
{
	if (!cpos || (cpos + sizeof(info) - send_buffer) > BUF_SIZE)
		return -1;

	memcpy(cpos, &info, sizeof(info));
	cpos += sizeof(info);

	return 0;
}

/*
 * skips @count integers from the current position in the received binary packet
 *
 * @return: 0 on success
 */
int bin_skip_int(int count)
{
	int i;

	if (child_index == 0) {
		LM_ERR("Non bin processes cannot do pop operations!\n");
		return -2;
	}

	for (i = 0; i < count; i++) {
		if (cpos + LEN_FIELD_SIZE > rcv_end) {
			LM_ERR("Receive binary packet buffer overflow");
			return -1;
		}

		cpos += LEN_FIELD_SIZE;
	}

	return 0;
}

/*
 * skips @count strings from the current position in a received binary packet
 *
 * @return: 0 on success
 */
int bin_skip_str(int count)
{
	int i, len;

	if (child_index == 0) {
		LM_ERR("Non bin processes cannot do pop operations!\n");
		return -2;
	}

	for (i = 0; i < count; i++) {
		if (cpos + LEN_FIELD_SIZE > rcv_end)
			goto error;

		memcpy(&len, cpos, LEN_FIELD_SIZE);
		cpos += LEN_FIELD_SIZE;

		if (cpos + len > rcv_end)
			goto error;

		cpos += len;
	}

	return 0;

error:
	LM_ERR("Receive binary packet buffer overflow");
	return -1;
}

/*
 * pops an str from the current position in the buffer
 * @info:   pointer to store the result
 *
 * @return: 0 on success
 *
 * Note: The pointer returned in @info str is only valid for the duration of
 *       the callback. Don't forget to copy the info into a safe buffer!
 */
int bin_pop_str(str *info)
{
	if (child_index == 0) {
		LM_ERR("Non bin processes cannot do pop operations!\n");
		return -2;
	}

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
 * @return: 0 on success
 */
int bin_pop_int(void *info)
{
	if (child_index == 0) {
		LM_ERR("Non bin processes cannot do pop operations!\n");
		return -2;
	}

	if (cpos + sizeof(int) > rcv_end) {
		LM_ERR("Receive binary packet buffer overflow");
		return -1;
	}

	memcpy(info, cpos, sizeof(int));
	cpos += sizeof(int);

	return 0;
}

/**
 * bin_send - computes the checksum of the current packet and then
 * sends the packet over UDP to the @dest destination
 *
 * @return: number of bytes sent, or -1 on error
 */
int bin_send(union sockaddr_union *dest)
{
	int rc;
	str st;

	if (!dest)
		return 0;

	st.s = send_buffer + HEADER_SIZE;
	st.len = bin_send_size - HEADER_SIZE;

	/* compute a checksum of the binary packet content */
	crc32_uint(&st, (unsigned int *)(send_buffer + BIN_PACKET_MARKER_SIZE));

	LM_DBG("sending packet {'%.*s', %d}: %.*s [%d B] from socket %d\n",
	        *(int *)(send_buffer + HEADER_SIZE), send_buffer + HEADER_SIZE +
	        LEN_FIELD_SIZE, bin_send_type, bin_send_size, send_buffer, bin_send_size,
	        bin->socket);

	rc = udp_send(bin, send_buffer, bin_send_size, dest);
	if (rc == -1)
		LM_ERR("binary packet UDP send failed!\n");

	return rc;
}

/**
 * bin_register_cb - registers a module handler for specific packets
 * @mod_name: used to classify the incoming packets
 * @cb:       the handler function, called once for each matched packet
 *
 * @return:   0 on success
 */
int bin_register_cb(char *mod_name, void (*cb)(int))
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

	new_mod->next = reg_modules;
	reg_modules = new_mod;

	return 0;
}

static int has_valid_checksum(char *buf, int len)
{
	unsigned int crc, real_crc;
	str st;

	crc = *(unsigned int *)(buf + BIN_PACKET_MARKER_SIZE);

	st.s = buf + HEADER_SIZE;
	st.len = len - HEADER_SIZE;

	crc32_uint(&st, &real_crc);

	return crc == real_crc;
}

/*
 * main binary packet UDP receiver loop
 */
static void bin_receive_loop(void)
{
	int rcv_bytes;
	unsigned int from_len;
	union sockaddr_union* from;
	struct receive_info ri;
	struct packet_cb_list *p;
	str name;

	from = pkg_malloc(sizeof(*from));
	if (!from) {
		LM_ERR("No more pkg memory!\n");
		goto exit;
	}
	memset(from, 0, sizeof(*from));

	ri.bind_address = bind_address;
	ri.dst_port = bind_address->port_no;
	ri.dst_ip = bind_address->address;
	ri.proto = PROTO_UDP;
	ri.proto_reserved1 = ri.proto_reserved2 = 0;

	for (;;) {
		rcv_bytes = recvfrom(bind_address->socket, rcv_buf, BUF_SIZE,
							 0, &from->s, &from_len);
		if (rcv_bytes == -1) {
			if (errno == EAGAIN) {
				LM_DBG("packet with bad checksum received\n");
				continue;
			}

			LM_ERR("recvfrom: [%d] %s\n", errno, strerror(errno));
			if (errno == EINTR || errno == EWOULDBLOCK || errno == ECONNREFUSED)
				continue;
			else
				goto exit;
		}

		rcv_end = rcv_buf + rcv_bytes;

#ifndef NO_ZERO_CHECKS
		if (rcv_bytes < MIN_UDP_PACKET) {
			LM_DBG("probing packet received len = %d\n", rcv_bytes);
			continue;
		}
#endif

		if (!is_valid_bin_packet(rcv_buf)) {
			LM_WARN("Invalid binary packet header! First 10 bytes: %.*s\n",
					10, rcv_buf);
			continue;
		}

		if (!has_valid_checksum(rcv_buf, rcv_bytes)) {
			LM_WARN("binary packet checksum test failed!\n");
			continue;
		}

		get_name(rcv_buf, name);
		cpos = name.s + name.len + CMD_FIELD_SIZE;

		/* packet will be now processed by a specific module */
		for (p = reg_modules; p; p = p->next) {
			if (p->module.len == name.len &&
			    memcmp(name.s, p->module.s, name.len) == 0) {

				LM_DBG("binary Packet CMD: %d. Module: %.*s\n",
						bin_rcv_type, name.len, name.s);

				p->cbf(bin_rcv_type);

				break;
			}
		}
	}

exit:
	if (from)
		pkg_free(from);
}

/*
 * called in the OpenSIPS initialization phase by the main process.
 * forks the binary packet UDP receivers.
 *
 * @return: 0 on success
 */
int start_bin_receivers(void)
{
	pid_t pid;
	int i;

	if (udp_init(bin) != 0)
		return -1;

	for (i = 1; i <= bin_children; i++) {
		if ((pid = internal_fork("BIN receiver")) < 0) {
			LM_CRIT("Cannot fork binary packet receiver process!\n");
			return -1;
		}

		if (pid == 0) {
			LM_DBG("CHILD sock: %d\n", bin->socket);

			child_index = i;
			set_proc_attrs("BIN receiver %.*s ",
							bin->sock_str.len,
							bin->sock_str.s);
			bind_address = bin;

			if (init_child(PROC_BIN) < 0) {
				LM_ERR("init_child failed for BIN listener\n");
				if (send_status_code(-1) < 0)
					LM_ERR("failed to send status code\n");
				clean_write_pipeend();
				exit(-1);
			}

			bin_receive_loop();
			exit(-1);
		} else
			LM_DBG("PARENT sock: %d\n", bin->socket);
	}

	return 0;
}

