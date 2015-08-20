#
# $Id$
#
# Perl module for OpenSIPS
#
# Copyright (C) 2006 Collax GmbH
#                    (Bastian Friedrich <bastian.friedrich@collax.com>)
#
# This file is part of opensips, a free SIP server.
#
# opensips is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version
#
# opensips is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
#

package OpenSIPS;
require Exporter;
require DynaLoader;

@ISA = qw(Exporter DynaLoader);
@EXPORT = qw ( t );
@EXPORT_OK = qw ( log );

use OpenSIPS::Message;
use OpenSIPS::Constants;
use OpenSIPS::Utils::Debug;

bootstrap OpenSIPS;


BEGIN {
	$SIG{'__DIE__'} = sub {
		OpenSIPS::Message::log(undef, L_ERR, "perl error: $_[0]\n");
        };
	$SIG{'__WARN__'} = sub {
		OpenSIPS::Message::log(undef, L_ERR, "perl warning: $_[0]\n");
        };
}

1;

