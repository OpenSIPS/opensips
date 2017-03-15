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

static int bin_realloc(bin_packet_t *packet, int size);

struct socket_info *bin;

static struct packet_cb_list *reg_modules;


short get_bin_pkg_version(bin_packet_t *packet)
{
	return  *(short *)(packet->buffer.s + BIN_PACKET_MARKER_SIZE + PKG_LEN_FIELD_SIZE);
}

void set_len(bin_packet_t *packet) {
	unsigned int *px;
	px = (unsigned int *) (packet->buffer.s + BIN_PACKET_MARKER_SIZE);
	*px = packet->buffer.len;
}

/**
 * bin_init - begins the construction of a new binary packet (header part):
 *
 * +-----------------------------+-------------------------------------------------------+
 * |    12-byte HEADER           |       BODY                max 65535 bytes             |
 * +-----------------------------+-------------------------------------------------------+
 * | PK_MARKER |PGK LEN| VERSION | LEN | MOD_NAME | CMD | LEN | FIELD | LEN | FIELD |....|
 * +-------------------+-----------------------------------------------------------------+
 *
 * @param: { LEN, MOD_NAME } + CMD + VERSION
 * @lentgh: initial size of the packet, if left 0, the defalut BUF_SIZE is used
 */
int bin_init(bin_packet_t *packet, str *mod_name, int cmd_type, short version, int length)
{
	if (length != 0 && length < MIN_BIN_PACKET_SIZE + mod_name->len) {
		LM_ERR("Length parameter has to be greater than:%lu\n", MIN_BIN_PACKET_SIZE + mod_name->len);
		return -1;
	}

	if (!length) 
		length = MAX_BUF_LEN;

	packet->buffer.s = pkg_malloc(length);
	if (!packet->buffer.s) {
		LM_ERR("No more pkg memory!\n");
		return -1;
	}
	packet->buffer.len = 0;
	packet->size = length;

	/* binary packet header: marker + pkg_len */
	memcpy(packet->buffer.s + packet->buffer.len, BIN_PACKET_MARKER, BIN_PACKET_MARKER_SIZE);
	packet->buffer.len += BIN_PACKET_MARKER_SIZE + PKG_LEN_FIELD_SIZE;

	
	/* bin version */
	memcpy(packet->buffer.s + packet->buffer.len, &version, sizeof(version));
	packet->buffer.len += VERSION_FIELD_SIZE;

	/* module name */
	memcpy(packet->buffer.s + packet->buffer.len, &mod_name->len, LEN_FIELD_SIZE);
	packet->buffer.len += LEN_FIELD_SIZE;
	memcpy(packet->buffer.s + packet->buffer.len, mod_name->s, mod_name->len);
	packet->buffer.len += mod_name->len;

	memcpy(packet->buffer.s + packet->buffer.len, &cmd_type, sizeof(cmd_type));
	packet->buffer.len += sizeof(cmd_type);
	set_len(packet);

	return 0;
}

/*
 * copies the given string at the end position in the packet
 * allows null strings (NULL content or NULL param)
 *
 * @return:
 *		> 0: success, the size of the packet
 *		< 0: internal buffer limit reached
 */
int bin_push_str(bin_packet_t *packet, const str *info)
{
	if (!packet->buffer.s || !packet->size) {
		LM_ERR("bin structure not initialize, call bin_init befere altering buffer\n");
		return -1;
	}

	if (packet->buffer.len  > packet->size - LEN_FIELD_SIZE - (info ? info->len : 0)) {
		if (!bin_realloc(packet, info->len))
			return -1;
	}

	if (!info || info->len == 0 || !info->s) {
		memset(packet->buffer.s + packet->buffer.len, 0, LEN_FIELD_SIZE);
		packet->buffer.len += LEN_FIELD_SIZE;
		return packet->buffer.len;
	}

	memcpy(packet->buffer.s + packet->buffer.len, &info->len, LEN_FIELD_SIZE);
	packet->buffer.len += LEN_FIELD_SIZE;
	memcpy(packet->buffer.s + packet->buffer.len, info->s, info->len);
	packet->buffer.len += info->len;
	set_len(packet);

	return packet->buffer.len;
}

/*
 * adds a new integer value at the end position in the packet          
 *
 * @return:
 *		> 0: success, the size of the packet
 *		< 0: internal buffer limit reached
 */
int bin_push_int(bin_packet_t *packet, int info)
{
	if (!packet->buffer.s  || !packet->size) {
		LM_ERR("bin structure not initialize, call bin_init befere altering buffer\n");
		return -1;
	}

	if (packet->buffer.len  > packet->size - sizeof(int)) {
		if (!bin_realloc(packet,  sizeof(int)))
			return -1;
	}


	memcpy(packet->buffer.s + packet->buffer.len, &info, sizeof(info));
	packet->buffer.len += sizeof(info);

	set_len(packet);
	
	return packet->buffer.len;
}

/*
 * removes @count intergers from the end of the packet
 *
 * @return:
 *		0: success
 *		< 0: error, no more integers in buffer
 */
int bin_remove_int_buffer_end(bin_packet_t *packet, int count) {
	if (!packet->buffer.s  || !packet->size || (int)(packet->buffer.len - count * sizeof(int)) < 0){
		LM_ERR("binary packet underflow\n");
		return -1;
	}

	packet->buffer.len -= count * sizeof(int);
	set_len(packet);

	return 0;
}

/*
 * skips @count integers in the end of the packet
 *
 * @return:
 *		0: success
 *		< 0: error, no more integers in buffer
 */
int bin_skip_int_packet_end(bin_packet_t *packet, int count)
{
	if (!packet->buffer.s  || !packet->size || (packet->buffer.len + count * sizeof(int)) > packet->size)
		return -1;

	packet->buffer.len += count * sizeof(int);
	set_len(packet);

	return 0;
}
/*
 * skips @count integers from the current position in the received binary packet
 *
 * @return:
 *             0: success
 *             <  0: error, buffer limit reached
 */
int bin_skip_int(bin_packet_t *packet, int count)
{
	if (packet->front_pointer - packet->buffer.s + count * sizeof(int) > packet->buffer.len){
		packet->front_pointer = packet->buffer.s + packet->buffer.len;
		LM_ERR("Buffer limit reached\n");
		return -1;
	}
	packet->front_pointer += count * sizeof(int);

	return 0;
}

/*
 * skips @count strings from the current position in a received binary packet
 *
 * @return:
 *		 0: success
 *		<  0: error, buffer limit reached
 */
int bin_skip_str(bin_packet_t *packet, int count)
{
	int i, len;

	for (i = 0; i < count; i++) {
		if (packet->front_pointer - packet->buffer.s + LEN_FIELD_SIZE > packet->buffer.len)
			goto error;

		len = 0;
		memcpy(&len, packet->front_pointer, LEN_FIELD_SIZE);
		packet->buffer.len += LEN_FIELD_SIZE;

		if (packet->front_pointer - packet->buffer.s + LEN_FIELD_SIZE > packet->buffer.len)
			goto error;

		packet->front_pointer += len;
	}

	return 0;

error:
	LM_ERR("Receive binary packet buffer overflow");
	return -1;
}

/*
 * pops an str from the current position in the packet
 * @info:   pointer to store the result
 *
 * @return:
 *		0 (success): info retrieved
 *      1 (success): nothing returned, all data has been consumed!
 *		< 0: error
 *
 * Note: The pointer returned in @info str is only valid for the duration of
 *       the callback. Don't forget to copy the info into a safe buffer!
 */
int bin_pop_str(bin_packet_t *packet, str *info)
{
	if (packet->front_pointer - packet->buffer.s == packet->buffer.len)
		return 1;

	if (packet->front_pointer - packet->buffer.s > packet->buffer.len)
		goto error;

	info->len = 0;
	memcpy(&info->len, packet->front_pointer, LEN_FIELD_SIZE);
	packet->front_pointer += LEN_FIELD_SIZE;

	if (packet->front_pointer - packet->buffer.s + info->len > packet->buffer.len)
		goto error;

	if (info->len == 0)
		info->s = NULL;
	else
		info->s = packet->front_pointer;

	packet->front_pointer += info->len;

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
int bin_pop_int(bin_packet_t *packet, void *info)
{
	if (packet->front_pointer - packet->buffer.s == packet->buffer.len)
		return 1;

	if (packet->front_pointer - packet->buffer.s > packet->buffer.len + sizeof(int)) {
		LM_ERR("Receive binary packet buffer overflow");
		return -1;
	}

	memcpy(info, packet->front_pointer, sizeof(int));
	packet->front_pointer += sizeof(int);

	return 0;
}

/*
 * pops an integer value from the end of the packet
 * @info:   pointer to store the result
 *
 * @return:
 *		0 (success): info retrieved
 *		1 (success): nothing returned, all data has been consumed!
 *		< 0: error
 */
int bin_pop_back_int(bin_packet_t *packet, void *info) {
	if (packet->buffer.len < sizeof(int) + HEADER_SIZE)
		return -1;

	memcpy(info, packet->buffer.s + packet->buffer.len - sizeof(int), sizeof(int));
	packet->buffer.len -= sizeof(int);

	return 0;
}

/**
 * bin_register_cb - registers a module handler for specific packets
 * @mod_name: used to classify the incoming packets
 * @cb:       the handler function, called once for each matched packet
 *
 * @return:   0 on success
 */
int bin_register_cb(char *mod_name, void (*cb)(bin_packet_t *, int, struct receive_info *, void * atr), void *att)
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
void call_callbacks(char* buffer, struct receive_info *rcv)
{
	struct packet_cb_list *p;
	unsigned int pkg_len;
	bin_packet_t packet;
	int packet_type;
	str mod_name;

	pkg_len = *(unsigned int*)(buffer + BIN_PACKET_MARKER_SIZE);
	//add extra size so a realloc wont trigger after small altering of the packet 
	packet.buffer.s = pkg_malloc(pkg_len + 50);
	packet.buffer.len = pkg_len;
	packet.size = pkg_len + 50;
	memcpy(packet.buffer.s, buffer, pkg_len);

	mod_name.len = *(unsigned short*)(buffer + HEADER_SIZE);
	mod_name.s = packet.buffer.s + HEADER_SIZE + LEN_FIELD_SIZE;

	packet.front_pointer = mod_name.s + mod_name.len + CMD_FIELD_SIZE;
	packet_type = *(int *)(mod_name.s + mod_name.len);

	/* packet will be now processed by a specific module */
	for (p = reg_modules; p; p = p->next) {
		if (p->module.len == mod_name.len &&
		    memcmp(mod_name.s, p->module.s, mod_name.len) == 0) {

			LM_DBG("binary Packet CMD: %d. Module: %.*s\n",
					packet_type, mod_name.len, mod_name.s);

			p->cbf(&packet, packet_type, rcv,p->att);

			break;
		}
	}

	bin_free_packet(&packet);
}

static int bin_realloc(bin_packet_t *packet, int size) {
	int required;

	if (size < 0 || packet->buffer.len > MAX_BUF_LEN - size){
		LM_ERR("cannot make the buffer bigger\n");
		return -1;
	}

	required = packet->buffer.len + size;

	if (required > MAX_BUF_LEN - required)
		packet->size = MAX_BUF_LEN;
	else
		packet->size = 2 * required;

	packet->buffer.s = pkg_realloc(packet->buffer.s, packet->size);

	if (!packet->buffer.s) {
		LM_ERR("pkg realloc failed\n");
		return -1;
	}

	return 0;
}

void bin_free_packet(bin_packet_t *packet) {
	if (packet->buffer.s) {
		pkg_free(packet->buffer.s);
		packet->buffer.s = NULL;
	} else {
		LM_INFO("atempting to free uninitialized binary packet\n");
	}
}

int bin_get_buffer(bin_packet_t *packet, str *buffer)
{
	if (!buffer)
		return -1;

	buffer->s = packet->buffer.s;
	buffer->len = packet->buffer.len;

	return 1;
}

int bin_reset_back_pointer(bin_packet_t *packet)
{
	int mod_len;
	if (!packet->buffer.s  || !packet->size)
		return -1;

	mod_len = *(unsigned short*)(packet->buffer.s + HEADER_SIZE);

	packet->buffer.len = HEADER_SIZE + LEN_FIELD_SIZE + CMD_FIELD_SIZE + mod_len;

	return 0;
}
