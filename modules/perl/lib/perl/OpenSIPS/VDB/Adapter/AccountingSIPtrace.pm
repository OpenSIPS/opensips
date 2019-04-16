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

=head1 OpenSIPS::VDB::Adapter::AccountingSIPtrace

This package is an Adapter for the acc and tracer modules, featuring
only an insert operation.

=cut

package OpenSIPS::VDB::Adapter::AccountingSIPtrace;

use OpenSIPS::VDB;
use OpenSIPS::VDB::VTab;
use OpenSIPS;
use OpenSIPS::Constants;
use Data::Dumper;

our @ISA = qw ( OpenSIPS::VDB );

sub insert {
	my $self = shift;
	my $vals = shift;

	my $vtab = $self->{vtabs}->{$self->{tablename}};
	return $vtab->call("insert", $vals);
}

1;
