#!/bin/bash

DBHOST=$1
DBUSER=$2
DBPASS=$3
DBNAME=$4

TMPFILE="/tmp/db_errors"

function run_query () {
	echo $1
	mysql -h$DBHOST -u$DBUSER -p$DBPASS $DBNAME -e "${2}" &>> $TMPFILE
}

if [ $# -ne 4 ];then
	echo "Usage : $0 hostname username password database"
	exit
fi

rm -f $TMPFILE

# ACC modifications

run_query "- Updating ACC table version" "UPDATE version SET table_version=6 WHERE table_name ='acc'"
run_query "- Adding new 'time' field in ACC table" "ALTER TABLE acc ADD COLUMN time DATETIME NOT NULL"
run_query "- Adding new 'duration' field in ACC table" "ALTER TABLE acc ADD COLUMN duration INT(11) UNSIGNED DEFAULT 0 NOT NULL"
run_query "- Adding new 'setuptime' field in ACC table" "ALTER TABLE acc ADD COLUMN setuptime INT(11) UNSIGNED DEFAULT 0 NOT NULL"
run_query "- Adding new 'created' field in ACC table" "ALTER TABLE acc ADD COLUMN created DATETIME NOT NULL"

# DROUTING modifications

run_query "- Updating DROUTING table version" "UPDATE version SET table_version=4 WHERE table_name ='dr_gateways'"
run_query "- Adding new 'probe_mode' field in DR_GATEWAYS table" "ALTER TABLE dr_gateways ADD COLUMN probe_mode INT(11) UNSIGNED DEFAULT 0 NOT NULL"
run_query "- Adding new 'attrs' field in DR_RULES table" "ALTER TABLE dr_rules ADD COLUMN attrs CHAR(255) DEFAULT NULL"
run_query "- Modifying 'groupid' field in DR_GROUPS table" "ALTER TABLE dr_groups MODIFY COLUMN groupid INT(11) UNSIGNED DEFAULT 0 NOT NULL"

# LOAD_BALANCER modifications

run_query "- Creating INDEX on dst_uri column in load_balancer table" "CREATE INDEX dsturi_idx ON load_balancer (dst_uri)"

# PRESENCE modifications

run_query "- Updating PRESENTITY table version" "UPDATE version SET table_version=5 WHERE table_name ='presentity'"
run_query "- Adding new 'extra_hdrs' field in PRESENTITY table" "ALTER TABLE acc ADD COLUMN extra_hdrs BLOB DEFAULT '' NOT NULL"
run_query "- Modifying 'contact' field in ACTIVE_WATCHERS table" "ALTER TABLE active_watchers MODIFY COLUMN contact CHAR(128) NOT NULL"

# PUA modifications
run_query "- Updating PUA table version" "UPDATE version SET table_version=8 WHERE table_name ='pua'"
run_query "- Modifying 'pres_id' field in PUA table" "ALTER TABLE pua MODIFY COLUMN pres_id CHAR(255) NOT NULL"
run_query "- Modifying 'etag' field in PUA table" "ALTER TABLE pua MODIFY COLUMN etag CHAR(64)"
run_query "- Modifying 'watcher_uri' field in PUA table" "ALTER TABLE pua MODIFY COLUMN watcher_uri CHAR(128)"
run_query "- Modifying 'to_uri' field in PUA table" "ALTER TABLE pua MODIFY COLUMN to_uri CHAR(64)"
run_query "- Modifying 'call_id' field in PUA table" "ALTER TABLE pua MODIFY COLUMN call_id CHAR(64)"
run_query "- Modifying 'to_tag' field in PUA table" "ALTER TABLE pua MODIFY COLUMN to_tag CHAR(64)"
run_query "- Modifying 'from_tag' field in PUA table" "ALTER TABLE pua MODIFY COLUMN from_tag CHAR(64)"
run_query "- Modifying 'cseq' field in PUA table" "ALTER TABLE pua MODIFY COLUMN cseq INT(11)"
run_query "- Modifying 'contact' field in PUA table" "ALTER TABLE pua MODIFY COLUMN contact CHAR(128)"
run_query "- Modifying 'remote_contact' field in PUA table" "ALTER TABLE pua MODIFY COLUMN remote_contact CHAR(128)"
run_query "- Modifying 'version' field in PUA table" "ALTER TABLE pua MODIFY COLUMN version INT(11)"
run_query "- Modifying 'extra_headers' field in PUA table" "ALTER TABLE pua MODIFY COLUMN extra_headers TEXT"

# RLS modifications
run_query "- Modifying 'content_type' field in RLS_PRESENTITY table" "ALTER TABLE rls_presentity MODIFY COLUMN content_type CHAR(255) NOT NULL"

# SIPTRACE modifications
run_query "- Modifying 'traced_user' field in SIP_TRACE table" "ALTER TABLE sip_trace MODIFY COLUMN traced_user CHAR(128) DEFAULT NULL"
run_query "- Modifying 'status' field in SIP_TRACE table" "ALTER TABLE sip_trace MODIFY COLUMN status CHAR(128) DEFAULT NULL"


if [ `cat $TMPFILE | grep -v Duplicate | wc -l` -ne 0 ]; then
	echo -e "\n\nErrors encountered in the update procedure :"
	cat $TMPFILE | grep -v Duplicate
fi
