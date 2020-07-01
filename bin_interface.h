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

#ifndef __BINARY_INTERFACE__
#define __BINARY_INTERFACE__

#include "ip_addr.h"
#include "crc.h"
#include "net/proto_tcp/tcp_common_defs.h"

#define BIN_MAX_BUF_LEN TCP_BUF_SIZE
#define BIN_PACKET_MARKER      "P4CK"
#define BIN_PACKET_MARKER_SIZE 4
#define PKG_LEN_FIELD_SIZE     4
#define VERSION_FIELD_SIZE     2
#define LEN_FIELD_SIZE         (sizeof(unsigned short))
#define CMD_FIELD_SIZE         sizeof(int)
#define HEADER_SIZE \
			(BIN_PACKET_MARKER_SIZE + PKG_LEN_FIELD_SIZE + VERSION_FIELD_SIZE)
#define MIN_BIN_PACKET_SIZE \
			(HEADER_SIZE + LEN_FIELD_SIZE + 1 + CMD_FIELD_SIZE)
                                         /* ^ capability */

#define is_valid_bin_packet(_p) \
	(memcmp(_p, BIN_PACKET_MARKER, BIN_PACKET_MARKER_SIZE) == 0)

#define _ensure_bin_version(pkt, needed, pkt_desc) \
	do { \
		if (get_bin_pkg_version(pkt) != (needed)) { \
			if (pkt_desc && *pkt_desc) \
				LM_INFO("discarding %s, ver %d: need ver %d\n", \
				        pkt_desc, get_bin_pkg_version(pkt), (needed)); \
			else \
				LM_INFO("discarding packet type %d, ver %d: need ver %d\n", \
				        pkt->type, get_bin_pkg_version(pkt), (needed)); \
			return; \
		} \
	} while (0)
#define ensure_bin_version(pkt, needed) _ensure_bin_version(pkt, needed, "")

typedef struct bin_packet {
	str buffer;
	char *front_pointer;
	int size;
	int type;
	/* not populated by bin_interface */
	struct bin_packet *next;
	int src_id;
} bin_packet_t;

struct packet_cb_list {
	str capability;									 /* registered capability */
	void (*cbf)(bin_packet_t *, int packet_type,	 /* callback */
				struct receive_info *ri, void *att);
        void *att;

	struct packet_cb_list *next;
};

/* returns the version of the bin protocol from the given message */
static inline short get_bin_pkg_version(bin_packet_t *packet)
{
	return *(short *)(packet->buffer.s + BIN_PACKET_MARKER_SIZE
	                  + PKG_LEN_FIELD_SIZE);
}

/* overrides the version of the bin protocol from the given message */
static inline void set_bin_pkg_version(bin_packet_t *packet, short new_version)
{
	*(short *)(packet->buffer.s + BIN_PACKET_MARKER_SIZE
	           + PKG_LEN_FIELD_SIZE) = new_version;
}

/*
 * returns the capability from the message
 */
void bin_get_capability(bin_packet_t *packet, str *capability);


/**
	calls all the registered functions

	@buffer: buffer containing a complete bin message
	@rcv:    information about the sender of the message
 */
void call_callbacks(char* buffer, struct receive_info *rcv);
/*
 * registers a callback function to be triggered on a received
 * binary packet marked with the @cap capability
 */
int bin_register_cb(str *cap, void (*cb)(bin_packet_t *, int,
        struct receive_info *, void * atr), void *att, int att_len);


/**
 * first function called when building a binary packet
 *
 * @capability:   capability string
 * @packet_type:  capability specific identifier for this new packet
 *
 * @return: 0 on success
 */
int bin_init(bin_packet_t *packet, str *capability, int packet_type, short version,
				int length);

/**
 * function called to build a binary packet with a known buffer
 *
 * @packet: the packet that will be populated
 * @buffer: the buffer that will be attached to the packet
 * @length: the length of the buffer attached
 */
void bin_init_buffer(bin_packet_t *packet, char *buffer, int length);

/*
 * appends a buffer to a binary packet
 * @buf: buffer to be appended
 * @len: length of @buf
 *
 * @return:
 *		> 0: success, the size of the buffer
 *		< 0: internal buffer limit reached
 */
int bin_append_buffer(bin_packet_t *packet, str *buf);

/*
 * adds a new string value to the packet being currently built
 * @info: may also be NULL
 *
 * @return:
 *		> 0: success, the size of the buffer
 *		< 0: internal buffer limit reached
 */
int bin_push_str(bin_packet_t *packet, const str *info);

/*
 * adds a new integer value to the packet being currently built
 *
 * @return:
 *		> 0: success, the size of the buffer
 *		< 0: internal buffer limit reached
 */
int bin_push_int(bin_packet_t *packet, int info);

/*
 * removes an integer from the end of the packet
 *
 * @return:
 *		0: success
 *		< 0: error, no more integers in buffer
 */
int bin_remove_int_buffer_end(bin_packet_t *packet, int count);

/*
 * skips @count integers in the end of the packet
 *
 * @return:
 *		0: success
 *		< 0: error, no more integers in buffer
 */
int bin_skip_int_packet_end(bin_packet_t *packet, int count);

/*
 * pops a str structure from binary packet
 * @info:   pointer to store the result
 *
 * @return:
 *		0 (success): info retrieved
 *		1 (success): nothing returned, all data has been consumed!
 *		< 0: error
 *
 * Note: The pointer returned in @info is only valid for the duration of
 *       the callback. Don't forget to copy the data into a safe buffer!
 *
 * Note2: Information is retrieved in the same order it was stored
 */
int bin_pop_str(bin_packet_t *packet, str *info);

/*
 * pops an integer from the front of the packet
 * @info:   pointer to store the result
 *
 * @return:
 *		0 (success): info retrieved
 *		1 (success): nothing returned, all data has been consumed!
 *		< 0: error
 *
 * Note: Information is retrieved in the same order it was stored
 */
int bin_pop_int(bin_packet_t *packet, void *info);

/*
 * pops an integer from the end of binary packet
 * @info:   pointer to store the result
 *
 * @return:
 *		0 (success): info retrieved
 *		1 (success): nothing returned, all data has been consumed!
 *		< 0: error
 */
int bin_pop_back_int(bin_packet_t *packet, void *info);

/*
 * skips @count integers from a received binary packet
 *
 * @return:
 *		>= 0: success, number of skipped bytes
 *		<  0: error, buffer limit reached
 */
int bin_skip_int(bin_packet_t *packet, int count);

/*
 * skips @count strings from a received binary packet
 *
 * @return:
 *		>= 0: success, number of skipped bytes
 *		<  0: error, buffer limit reached
 */
int bin_skip_str(bin_packet_t *packet, int count);

/*
 * frees the memory used by the binary packet
 */
void bin_free_packet(bin_packet_t *packet);

/*
 * resets the packet, equivalent to calling bin_free_packet,
 * then reinitializing the packet
 */
int bin_reset_back_pointer(bin_packet_t *packet);
/*
 * returns the buffer with the data in the bin packet
*/
int bin_get_buffer(bin_packet_t *packet, str *buffer);

/*
 * returns the bin packet's buffer from the position where
 * the serialized content actually starts
*/
int bin_get_content_start(bin_packet_t *packet, str *buf);

/*
 * returns the bin packet's buffer from the position of the
 * next field to be consumed
*/
int bin_get_content_pos(bin_packet_t *packet, str *buf);

#endif /* __BINARY_INTERFACE__ */

