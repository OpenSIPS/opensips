/*
 *
 * Copyright (C) 2026 Genesys Cloud Services, Inc.
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
 */

/**
 * @file thinfo_codec.h
 * @brief Compact binary codec for thinfo encoding and decoding
 * @author David Trihy <david.trihy@genesys.com>
 * @date 2026
 * 
 * This file provides a compact binary format for encoding and decoding thinfo param,
 * achieving significant size reduction compared to string representation.
 */
#ifndef _THINFO_CODEC_H
#define _THINFO_CODEC_H

#include <stdint.h>

#include "../../parser/msg_parser.h"
#include "../../socket_info.h"

/**
 * @def MAX_ENCODED_URI_SIZE
 * @brief Maximum size of an encoded URI in the compact binary format.
 * 
 * @section encoding_format ENCODING FORMAT
 * 
 * @subsection uri_properties 1. URI Properties (2 bytes, uint16_t) - Always present
 * Bit layout:
 * - Bits 0-2:   Scheme (sip, sips, tel, tels, urn:service, urn:nena:service)
 * - Bits 3-5:   Transport (udp, tcp, tls, sctp, ws, wss)
 * - Bits 6-7:   Domain type (IPv4, IPv6, FQDN)
 * - Bit 8:      HAS_USERNAME flag
 * - Bit 9:      HAS_PASSWORD flag
 * - Bit 10:     HAS_PORT flag
 * - Bit 11:     HAS_PARAMS flag (other params, not lr/transport and r2 if dual URI)
 * - Bit 12:     HAS_HEADERS flag
 * - Bit 13:     HAS_LR flag (lr or lr=on present)
 * - Bit 14:     IS_DUAL_URI flag
 * - Bit 15:     Reserved
 * 
 * @subsection username 2. Username (optional, if HAS_USERNAME set)
 * - Encoded Length: 1 byte length + variable data (2-256 bytes)
 *   - Length byte: uint8_t indicating username length
 *   - Data: username string (length specified by length byte)
 * 
 * @subsection password 3. Password (optional, if HAS_PASSWORD set)
 * - Encoded Length: 1 byte length + variable data (2-256 bytes)
 *   - Length byte: uint8_t indicating password length
 *   - Data: password string (length specified by length byte)
 * 
 * @subsection domain 4. Domain (variable size based on domain type)
 * - IPv4: 4 bytes (raw binary IP address)
 * - IPv6: 16 bytes (raw binary IP address)
 * - FQDN: 1 byte length + variable data (2-255 bytes)
 *   - Length byte: uint8_t indicating hostname length
 *   - Data: hostname string (length specified by length byte)
 * 
 * @subsection port 5. Port (optional, if HAS_PORT set)
 * - 2 bytes (uint16_t, network byte order)
 * 
 * @subsection params 6. Params (optional, if HAS_PARAMS set)
 * - Length: 1 byte (uint8_t)
 * - Data: variable length (0-255 bytes)
 * - @note lr and r2 params are encoded in flags, not here
 * 
 * @subsection headers 7. Headers (optional, if HAS_HEADERS set)
 * - Length: 1 byte (uint8_t)
 * - Data: variable length (0-255 bytes)
 * 
 * @subsection uri2_properties 8. Second URI Properties (optional, if IS_DUAL_URI set)
 * - 1 byte with scheme, transport, HAS_PORT, and HAS_R2 flags
 * 
 * @subsection uri2_port 9. Second URI Port (optional, if IS_DUAL_URI and URI2_HAS_PORT set)
 * - 2 bytes (uint16_t, network byte order)
 * 
 * @section examples ENCODING EXAMPLES
 * 
 * @par Best case scenario - single URI:
 * - Input URI: 40 bytes
 *   @code
 *   <sips:100.200.100.200;transport=tls;lr>
 *   @endcode
 * - Scheme, transport and lr param are encoded into the URI properties
 * - Largest IPv4 as a string (15 bytes) encoded into 4 byte octets
 * - No port needed to be encoded
 * - Params of transport and lr are already encoded so no params set
 * - Output: 6 byte binary representation of the URI
 *
 * @par Best case scenario - r2=on dual URI:
 * - Input URI: 96 bytes
 *   @code
 *   URI1: <sips:100.200.100.200;transport=tls;r2=on;lr>
 *   URI2: <sip:100.200.100.200;transport=tcp;r2=on;lr>
 *   @endcode
 * - Scheme, transport, lr and r2 param are encoded into the URI properties
 * - Largest IPv4 as a string (15 bytes) encoded into 4 byte octets
 * - No port needed to be encoded
 * - Params of transport, lr and r2 are already encoded so no params set
 * - Second URI properties encoded with HAS_R2 flag, no port so not encoded
 * - Output: 7 byte binary representation of the URI
 *
 * @note when using thinfo_encode_dual_uri it is up to the caller of the 
 * function to verify the host and params match before encoding.
 *
 * @par Worst case scenario:
 * - 1,277 bytes encoded size (extremely unlikely)
 * - Requires having the largest variable data possible: username, password, hostname, etc.
 * - In this scenario the input string will still be larger than the encoded string 
 *   but the savings are negligible at that point
 */
#define MAX_ENCODED_URI_SIZE ( \
    sizeof(uint16_t) +             /* uri_properties */ \
    sizeof(uint8_t)  + UINT8_MAX + /* username */ \
    sizeof(uint8_t)  + UINT8_MAX + /* password */ \
    sizeof(uint8_t)  + UINT8_MAX + /* domain */ \
    sizeof(uint16_t) +             /* port */ \
    sizeof(uint8_t)  + UINT8_MAX + /* params */ \
    sizeof(uint8_t)  + UINT8_MAX + /* headers */ \
    sizeof(uint8_t)  +             /* second associated uri flags */ \
    sizeof(uint16_t)               /* second associated uri port */ \
)

#define MAX_THINFO_BUFFER_SIZE 4096

/**
 * @struct thinfo_encoded_t
 * @brief Buffer structure for encoded thinfo data
 */
typedef struct {
    unsigned char buf[MAX_THINFO_BUFFER_SIZE];   /**< Buffer holding encoded binary data */
    uint16_t len;                                /**< Current length of encoded data */
    int pos;                                     /**< Current read/write position */
} thinfo_encoded_t;

/**
 * @brief Encode a single SIP URI into compact binary format
 * 
 * @param thinfo Pointer to the encoded buffer structure (updates len and pos on success)
 * @param uri Pointer to the parsed SIP URI to encode
 * @param param_count Number of parameters to skip during encoding
 * @param params_to_skip Array of parameter names to exclude from encoding
 * 
 * @return 0 on success, -1 on error
 */
int thinfo_encode_uri(thinfo_encoded_t *thinfo, struct sip_uri *uri, int param_count, str *params_to_skip);

/**
 * @brief Encode two related SIP URIs (dual URI encoding for r2 scenarios)
 * 
 * Dual encoding is more efficient when two URIs share functionally similar URIs.
 * The main areas they can differ in is scheme, port and transport.
 * This is an optimization if record_route() with dual recording routing is in the SIP message.
 * The caller must verify that the URIs are compatible for dual encoding.
 * 
 * @param thinfo Pointer to the encoded buffer structure (updates len and pos on success)
 * @param uri1 Pointer to the first parsed SIP URI
 * @param uri2 Pointer to the second parsed SIP URI
 * 
 * @return 0 on success, -1 on error
 */
int thinfo_encode_dual_uri(thinfo_encoded_t *thinfo, struct sip_uri *uri1, struct sip_uri *uri2);

/**
 * @brief Encode socket information into the buffer
 * 
 * @param thinfo Pointer to the encoded buffer structure (updates len and pos on success)
 * @param socket Pointer to the socket_info structure to encode
 * 
 * @return 0 on success, -1 on error
 */
int thinfo_encode_socket(thinfo_encoded_t *thinfo, const struct socket_info *socket);

/**
 * @brief Decode URIs from the encoded buffer into string representations
 * 
 * @param thinfo Pointer to the encoded buffer structure (updates pos on success)
 * @param decode_buf Character buffer to hold decoded URI strings
 * @param uri_count Number of URIs to decode
 * @param uris Array of str structures to receive decoded URI references
 * 
 * @return 0 on success, -1 on error
 */
int thinfo_decode_uris(thinfo_encoded_t *thinfo, char decode_buf[static MAX_ENCODED_URI_SIZE * 3], uint16_t uri_count, str uris[static uri_count]);

/**
 * @brief Decode socket information from the encoded buffer
 * 
 * @param thinfo Pointer to the encoded buffer structure (updates pos on success)
 * @param proto Pointer to receive the decoded protocol
 * @param ip Pointer to str structure to receive the decoded IP address
 * @param port Pointer to receive the decoded port number
 * 
 * @return 0 on success, -1 on error
 */
int thinfo_decode_socket(thinfo_encoded_t *thinfo, int *proto, str *ip, unsigned short *port);

/**
 * @brief Get the number of URIs encoded in the buffer
 * 
 * @param thinfo Pointer to the encoded buffer structure (read-only, does not modify)
 * 
 * @return Number of encoded URIs (uint8_t)
 */
uint8_t thinfo_get_uri_count(thinfo_encoded_t *thinfo);

/**
 * @brief Get the flags from the encoded buffer
 * 
 * @param thinfo Pointer to the encoded buffer structure (read-only, does not modify)
 * 
 * @return Flags value (uint16_t)
 */
uint16_t thinfo_get_flags(thinfo_encoded_t *thinfo);

/**
 * @brief Finalize the encoded buffer by writing header information
 * 
 * This should be called after all encoding operations are complete to write
 * the final flags and URI count to the buffer header.
 * 
 * @param thinfo Pointer to the encoded buffer structure (updates buf with header)
 * @param flags Flags value to write to the header
 * @param uri_count Number of URIs encoded in the buffer
 */
void thinfo_buffer_finalize(thinfo_encoded_t *thinfo, uint16_t flags, uint8_t uri_count);

/**
 * @brief Reset the encoded buffer to initial state
 * 
 * Clears the buffer and resets position and length counters.
 * 
 * @param thinfo Pointer to the encoded buffer structure (resets len and pos to 0)
 */
void thinfo_buffer_reset(thinfo_encoded_t *thinfo);

#endif