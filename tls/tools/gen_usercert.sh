#!/bin/bash
#
# $Id$
#
# Copyright (C) 2005 Voice Sistem SRL
#
# This file is part of openser, a free SIP server.
#
# openser is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# openser is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
#
# History:
# ---------
#  2005-10-06  first version (bogdan)
#

CA_DIR=rootCA

if [ -z $1 ]
then
	echo -e "ERROR: missing first parameter: no user specified"
	exit 1
fi

if [ -f $1.conf ]
then
	echo -e "\n***** Using config file $1.conf *****"
else
	echo -e "ERROR: missing first parameter: config file $1.conf not found"
	exit 1
fi

USER_DIR=$1
USER=$1


echo -e "\n***** Creating directory $USER_DIR *****"
mkdir -p $USER_DIR
if [ $? -ne 0 ] ; then
	echo "Failed to create user directory"
	exit 1
fi
rm -fr $USER_DIR/*


echo -e "\n***** Creating user certificate request *****"
openssl req  -config $USER.conf -out $USER_DIR/$USER-cert_req.pem -keyout $USER_DIR/$USER-privkey.pem -new -nodes
if [ $? -ne 0 ] ; then
	echo "Failed to generate certificate request"
	exit 1
fi


echo -e "\n******  Signing certificate request ******"
openssl ca -config request.conf -in $USER_DIR/$USER-cert_req.pem -out $USER_DIR/$USER-cert.pem
if [ $? -ne 0 ] ; then
	echo "Failed to generate certificate request"
	exit 1
fi

echo -e "\n***** Generating CA list *****"
cat $CA_DIR/cacert.pem >> $USER_DIR/$USER-calist.pem


echo -e "\n***** Private key is locate at $USER_DIR/$USER-privkey.pem "
echo -e "\n***** Certificate is locate at $USER_DIR/$USER-cert.pem "
echo -e "\n***** CA -List is locate at $USER_DIR/$USER-calist.pem "

echo -e "\n********   DONE   *********\n"

