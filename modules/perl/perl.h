/*
 * Perl module for OpenSIPS
 *
 * Copyright (C) 2006 Collax GmbH
 *                    (Bastian Friedrich <bastian.friedrich@collax.com>)
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
 */

#ifndef PERL_MOD_H
#define PERL_MOD_H

#include "../signaling/signaling.h"

/* lock_ops.h defines union semun, perl does not need to redefine it */
#ifdef USE_SYSV_SEM
# define HAS_UNION_SEMUN
#endif

#include <EXTERN.h>
#include <perl.h>

extern char *filename;
extern char *modpath;

extern PerlInterpreter *my_perl;

extern struct sig_binds sigb;

#define PERLCLASS_MESSAGE	"OpenSIPS::Message"
#define PERLCLASS_URI		"OpenSIPS::URI"

#endif /* PERL_MOD_H */
