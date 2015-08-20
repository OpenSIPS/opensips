/*
 * emergency module - basic support for emergency calls
 *
 * Copyright (C) 2014-2015 Robison Tesini & Evandro Villaron
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
 * --------
 *  2014-10-14 initial version (Villaron/Tesini)
 */


const char *MODEL = "<esrRequest xmlns=\"urn:nena:xml:ns:es:v2\" \n \
xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \n \
xsi:schemaLocation=\"urn:nena:xml:ns:es:v2 v2.xsd\"> \n \
<vpc> \n \
	<organizationName>%s</organizationName> \n \
	<hostId>%s</hostId> \n \
	<nenaId>%s</nenaId> \n \
	<contact>%s</contact> \n \
	<certUri>%s</certUri> \n \
</vpc> \n \
<source> \n \
	<organizationName>%s</organizationName> \n \
	<hostId>%s</hostId> \n \
	<nenaId>%s</nenaId> \n \
	<contact>%s</contact> \n \
	<certUri>%s</certUri> \n \
</source> \n \
<vsp> \n \
	<organizationName>%s</organizationName> \n \
	<hostId>%s</hostId> \n \
	<nenaId>%s</nenaId> \n \
	<contact>%s</contact> \n \
	<certUri>%s</certUri> \n \
</vsp> \n \
<callId>%s</callId> \n \
<callback>%s</callback> \n \
<lie> \n \
	%s \n \
</lie> \n \
<callOrigin>%s</callOrigin> \n \
<datetimestamp>%s</datetimestamp> \n \
<customer>7</customer> \n \
</esrRequest>";

