/*
 * SDP parser interface
 *
 * Copyright (C) 2008 SOMA Networks, INC.
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
 *
 * HISTORY:
 * --------
 * 2007-09-09 osas: ported and enhanced sdp parsing functions from nathelper module
 *
 */


#ifndef SDP_CLONER_H
#define SDP_CLONER_H

#include "sdp.h"


/**
 * Clone the given sdp_session_cell structure.
 */
sdp_session_cell_t * clone_sdp_session_cell(sdp_session_cell_t *session);
/**
 * Free all memory associated with the cloned sdp_session structure.
 *
 * Note: this will free up the parsed sdp structure (form SHM_MEM).
 */
void free_cloned_sdp_session(sdp_session_cell_t *_session);

/**
 * Clone the given sdp_info structure.
 *
 * Note: all cloned structer will be in SHM_MEM.
 */
sdp_info_t* clone_sdp_info(sdp_info_t* sdp_info);
/**
 * Free all memory associated with the cloned sdp_info structure.
 *
 * Note: this will free up the parsed sdp structure (form SHM_MEM).
 */
void free_cloned_sdp(sdp_info_t* sdp);

#endif /* SDP_H */
