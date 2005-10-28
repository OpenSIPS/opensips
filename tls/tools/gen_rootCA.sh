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


CA_PATH='./rootCA'

if [ -z $1 ]
then
	CA_CONF='ca.conf'
else
	CA_PATH=$1
fi

echo -e "\n***** Creating directory $CA_PATH and its sub-tree *****"
mkdir -p $CA_PATH
if [ $? -ne 0 ] ; then
	echo "Failed to create root directory"
	exit 1
fi
rm -fr $CA_PATH/*
mkdir $CA_PATH/private
mkdir $CA_PATH/certs
touch $CA_PATH/index.txt
echo 01 >$CA_PATH/serial


echo -e "\n***** Creating CA self-signed certificate *****"
( cd $CA_PATH; openssl req -config ../$CA_CONF -x509 -newkey rsa:2048 -days 365 -out ./cacert.pem -outform PEM )
if [ $? -ne 0 ] ; then
	echo "Failed to create self-signed certificate"
	exit 1
fi


echo -e "\n***** Protecting CA private key *****"
chmod 600 $CA_PATH/private/cakey.pem


echo -e "\n***** DONE  *****"
echo -e "\nPrivate key can be found in $CA_PATH/private/cakey.pem\n"
echo -e "\nCertificate can be found in $CA_PATH/cacert.pem\n"

