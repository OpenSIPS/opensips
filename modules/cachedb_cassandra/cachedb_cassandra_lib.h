/*
 * Copyright (C) 2011 OpenSIPS Solutions
 *
 * This file is part of opensips, a free SIP server.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * history:
 * ---------
 *  2011-12-xx  created (vlad-paiu)
 */

#include <string>
#include <vector>
#include <algorithm>
#include <sys/time.h>
#include <protocol/TBinaryProtocol.h>
#include <transport/TSocket.h>
#include <transport/TTransportUtils.h>
#include <boost/lexical_cast.hpp>
#include <boost/shared_ptr.hpp>
#include "Cassandra.h"

extern "C" {
/* give up on ut.h, don't need it anyway. Also give up on inline stuff */
#define ut_h
#define inline
#include "../../str.h"
#include "../../dprint.h"
#undef inline
}

using namespace std;
using namespace boost;
using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;
using namespace org::apache::cassandra;

class CassandraConnection {
private:

string keyspace;
string column_family;
string host;
int port;

int conn_to;
int snd_to;
int rcv_to;
ConsistencyLevel::type rd_level;
ConsistencyLevel::type wr_level;
/* actual connection to Cassandra */
CassandraClient* client;

protected:

/* generate a timestamp in ms. Thrift stuff :| */
long int make_cassandra_timestamp() const 
{
	struct timeval tv;
	long microseconds;

	gettimeofday(&tv, NULL);
	microseconds = (tv.tv_sec * 1000000) + tv.tv_usec;
	return microseconds;
}

public:

CassandraConnection(const string& keyspace, const string& column_family) : 
keyspace(keyspace),
column_family(column_family),
host(""),
port(0), 
client(NULL) 
{
}

virtual ~CassandraConnection() 
{
	cassandra_close();
}

int cassandra_open(const string& host, int port,
	int connection_timeout,int receive_timeout,int send_timeout,
	int read_cs_level,int write_cs_level) 
{

	/* save host & port */
	this->host = host;
	this->port = port;
	this->conn_to = connection_timeout;
	this->rcv_to = receive_timeout;
	this->snd_to = send_timeout;
	this->rd_level = (ConsistencyLevel::type)read_cs_level;
	this->wr_level = (ConsistencyLevel::type)write_cs_level;

	try {
		/* Create actual Thrift transport & protocol */
		boost::shared_ptr<TSocket> socket(new TSocket(host, port));
		boost::shared_ptr<TTransport> transport(new TFramedTransport(socket));
		boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));
		string version;

		/* Set all timeouts so we don't get stuck for too long */
		socket->setConnTimeout(connection_timeout);
		socket->setRecvTimeout(receive_timeout);
		socket->setSendTimeout(send_timeout);

		/* create CassandraClient object */
		if (!(client = new CassandraClient(protocol))) {
			LM_ERR("Failed to create CassandraClienta\n");
			return -1;
		}

		/* open actual transport connection */
		transport->open();
		if (!transport->isOpen()) {
			LM_ERR("Failed to open transport to Cassandra\n");
			return -1;
		}

		/* set Keyspace & get version for test purposes */
		client->set_keyspace(keyspace);
		client->describe_version(version);
		LM_DBG("Opened connection for KeySpace [%s]."
			" Cassandra version = [%s]\n", 
			keyspace.c_str(), version.c_str());

		return 0;
	} catch (InvalidRequestException &ire) {
		LM_ERR("ERROR1: %s\n", ire.why.c_str());
	} catch (TException &tx) {
		LM_ERR("ERROR2: %s\n", tx.what());
	} catch (std::exception &e) {
		LM_ERR("ERROR3: %s\n", e.what());
	}

	/* We failed. try & cleanup */
	cassandra_close();
	return -1;
}

void cassandra_close() 
{
	if (client) {
		try {
			delete client;
			LM_DBG("Cassandra connection closed\n");
		} catch (TException &tx) {
			LM_ERR("ERROR: %s\n", tx.what());
		} catch (std::exception &e) {
			LM_ERR("ERROR: %s\n", e.what());
		}

	client = NULL;
	}
}

int cassandra_reopen() 
{
	cassandra_close();
	return cassandra_open(host, port,conn_to,snd_to,rcv_to,rd_level,wr_level);
}

char* cassandra_simple_get(const string& attr)
{
	int retry=2;

	if (client == NULL && cassandra_reopen() != 0) {
		LM_ERR("No cassandra connection\n");
		return NULL;
	}

	do {
		try {
			ColumnPath cp;
			/* TODO - hard code this ? */
			string key = "1";
    			cp.__isset.column = true;
			cp.column = attr.c_str();
			cp.column_family = column_family.c_str();
			cp.super_column = "";
			ColumnOrSuperColumn sc;

    			client->get(sc, key, cp, rd_level);
			return (char *)sc.column.value.c_str();
		} catch (InvalidRequestException &ire) {
       			LM_ERR("ERROR1: %s\n", ire.why.c_str());
      		}
		catch (TException &tx) {
			LM_ERR("ERROR2: %s\n", tx.what());
		}
		catch (std::exception &e) {
 			LM_ERR("ERROR3: %s\n", e.what());
		}
	} while (retry-- && cassandra_reopen() == 0);
		
	LM_ERR("giving up on query\n");
	return NULL;
}

int cassandra_simple_insert(const string& name,const string& val, int expires)
{
	int retry=2;

	if (client == NULL && cassandra_reopen() != 0) {
		LM_ERR("No cassandra connection\n");
		return NULL;
	}

	do {
		try {
			/* TODO - hard code this ? */
			string key = "1";
    			ColumnParent cp;
			cp.column_family = column_family.c_str();
			Column c;
			c.name=name.c_str();
			c.value=val.c_str();
			c.__isset.value = true;
			c.timestamp=make_cassandra_timestamp();
			c.__isset.timestamp = true;
			if (expires > 0) {
				c.ttl=expires;
				c.__isset.ttl = true;
			}

			LM_DBG("inserting [%s] - [%s]\n",name.c_str(),val.c_str());
    			client->insert(key, cp,c,wr_level);
			return 0;
		} catch (InvalidRequestException &ire) {
       			LM_ERR("ERROR: %s\n", ire.why.c_str());
      		}
		catch (TException &tx) {
			LM_ERR("ERROR: %s\n", tx.what());
		}
		catch (std::exception &e) {
 			LM_ERR("ERROR: %s\n", e.what());
		}
	} while (retry-- && cassandra_reopen() == 0);
		
	LM_ERR("giving up on query\n");
	return -1;
}

int cassandra_simple_remove(const string& name)
{
	int retry=2;

	if (client == NULL && cassandra_reopen() != 0) {
		LM_ERR("No cassandra connection\n");
		return NULL;
	}

	do {
		try {
			/* TODO - hard code this ? */
			string key = "1";
    			ColumnPath cp;
			cp.column_family = column_family.c_str();
			cp.column=name.c_str();
			cp.__isset.column = true;

			LM_DBG("removing [%s]\n",name.c_str());
    			client->remove(key, cp,make_cassandra_timestamp(),wr_level);
			return 0;
		} catch (InvalidRequestException &ire) {
       			LM_ERR("ERROR: %s\n", ire.why.c_str());
      		}
		catch (TException &tx) {
			LM_ERR("ERROR: %s\n", tx.what());
		}
		catch (std::exception &e) {
 			LM_ERR("ERROR: %s\n", e.what());
		}
	} while (retry-- && cassandra_reopen() == 0);
		
	LM_ERR("giving up on query\n");
	return -1;
}
};
