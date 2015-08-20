#
# $Id$
#
# Perl module for OpenSIPS
#
# Copyright (C) 2007 Collax GmbH
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

package OpenSIPS::VDB::Adapter::TableVersions;

use OpenSIPS;
use OpenSIPS::Constants;

sub version {
	my $table = shift;

	# FIXME We need to split table name again - possibly, this is a function only, so this one will not work
	my $v = $table->version();

	my @cols;
	my @row;

	push @cols, new OpenSIPS::VDB::Column(DB_INT, "table_version");
	push @row, new OpenSIPS::VDB::Value(DB_INT, $v);
	
	return new OpenSIPS::VDB::Result(\@cols, (bless \@row, OpenSIPS::Utils::Debug));
}

1;

