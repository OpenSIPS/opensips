/*
 * Copyright (C) 2018 OpenSIPS Solutions
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
 */

#ifndef MMGEOIP_H
#define MMGEOIP_H

#include "../../str.h"

#define SHORT_FIELD_LAT   "lat"
#define SHORT_FIELD_LON   "lon"
#define SHORT_FIELD_CONT  "cont"
#define SHORT_FIELD_CC    "cc"
#define SHORT_FIELD_REG   "reg"
#define SHORT_FIELD_CITY  "city"
#define SHORT_FIELD_PC    "pc"
#define SHORT_FIELD_DMA   "dma"
#define SHORT_FIELD_AC    "ac"
#define SHORT_FIELD_TZ    "tz"
#define SHORT_FIELD_RN    "rn"

extern str MMG_city_db_path;

#endif  /* MMGEOIP_H */