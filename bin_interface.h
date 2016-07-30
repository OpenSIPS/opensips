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

#define BIN_PACKET_MARKER      "P4CK"
#define BIN_PACKET_MARKER_SIZE 4
#define PKG_LEN_FIELD_SIZE     2
#define VERSION_FIELD_SIZE     2
#define LEN_FIELD_SIZE         sizeof(int)
#define CMD_FIELD_SIZE         sizeof(int)
#define HEADER_SIZE            (BIN_PACKET_MARKER_SIZE + PKG_LEN_FIELD_SIZE + VERSION_FIELD_SIZE)
#define MIN_BIN_PACKET_SIZE \
	(HEADER_SIZE + LEN_FIELD_SIZE + CMD_FIELD_SIZE + 2) /* e.g. >tm<.so */

#define bin_send_type \
	(*(int *)(send_buffer + HEADER_SIZE + LEN_FIELD_SIZE + \
	  *(int *)(send_buffer + HEADER_SIZE)))

#define bin_rcv_type \
	(*(int *)(rcv_buf + HEADER_SIZE + LEN_FIELD_SIZE + \
	  *(int *)(rcv_buf + HEADER_SIZE)))

#define bin_send_size ((int)(cpos - send_buffer))
#define bin_rcv_size  ((int)(rcv_end - rcv_buf))

#define is_valid_bin_packet(_p) \
	(memcmp(_p, BIN_PACKET_MARKER, BIN_PACKET_MARKER_SIZE) == 0)

#define get_name(_p, name) \
	do { \
		name.len = *(int *)(_p + HEADER_SIZE); \
		name.s = _p + HEADER_SIZE + LEN_FIELD_SIZE; \
	} while (0)

struct packet_cb_list {
	str module;							/* registered module */
	void (*cbf)(int packet_type,		/* module callback */
				struct receive_info *ri, void *att);
        void *att;

	struct packet_cb_list *next;
};


/**
	returns the version of the bin protocol from the received message
*/
short get_bin_pkg_version(void);

/**
	calls all the registered functions

	@buffer: buffer containing a complete bin message
	@rcv:    information about the sender of the message
 */
void call_callbacks(char* buffer, struct receive_info *rcv);
/*
 * registers a callback function to be triggered on a received
 * binary packet marked with the @mod_name module name
 */
int bin_register_cb(char *mod_name, void (*)(int packet_type, struct receive_info *ri, void * atr), void *att);


/**
 * first function called when building a binary packet
 *
 * @mod_name:  module specific string
 * @cmd_type:  module specific identifier for this new packet
 *
 * @return: 0 on success
 */
int bin_init(str *mod_name, int packet_type, short version);

/*
 * adds a new string value to the packet being currently built
 * @info: may also be NULL
 *
 * @return:
 *		> 0: success, the size of the buffer
 *		< 0: internal buffer limit reached
 */
int bin_push_str(const str *info);

/*
 * adds a new integer value to the packet being currently built
 *
 * @return:
 *		> 0: success, the size of the buffer
 *		< 0: internal buffer limit reached
 */
int bin_push_int(int info);

/* TODO - comment, lol */
int bin_get_buffer(str *buffer);

/*
 * pops a str structure from a received binary packet
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
int bin_pop_str(str *info);

/*
 * pops an integer from a received binary packet
 * @info:   pointer to store the result
 *
 * @return:
 *		0 (success): info retrieved
 *		1 (success): nothing returned, all data has been consumed!
 *		< 0: error
 *
 * Note: Information is retrieved in the same order it was stored
 */
int bin_pop_int(void *info);

/*
 * skips @count integers from a received binary packet
 *
 * @return:
 *		>= 0: success, number of skipped bytes
 *		<  0: error, buffer limit reached
 */
int bin_skip_int(int count);

/*
 * skips @count strings from a received binary packet
 *
 * @return:
 *		>= 0: success, number of skipped bytes
 *		<  0: error, buffer limit reached
 */
int bin_skip_str(int count);

#endif /* __BINARY_INTERFACE__ */

