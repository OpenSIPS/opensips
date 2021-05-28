#
# Copyright (C) 2019-2020 OpenSIPS Solutions
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

DROP PROCEDURE IF EXISTS `OSIPS_DB_MIGRATE_3_0_TO_3_1`;
DELIMITER $$
CREATE PROCEDURE `OSIPS_DB_MIGRATE_3_0_TO_3_1`(
	IN old_db CHAR(64), IN new_db CHAR(64))
BEGIN

# provisioning-data tables which have changed (data migration is best-effort!)
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'cc_agents');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'cc_calls');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'cc_flows');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'dr_carriers');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'dr_rules');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'load_balancer');

# temp-data tables which have changed (data migration is best-effort!)
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'b2b_entities');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'dialog');


# provisioning-data tables which can be copied 1:1
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'acc');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'address');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'cachedb');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'carrierfailureroute');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'carrierroute');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'cc_cdrs');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'closeddial');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'clusterer');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'cpl');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'dbaliases');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'dialplan');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'dispatcher');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'domain');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'domainpolicy');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'dr_gateways');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'dr_groups');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'dr_partitions');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'emergency_report');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'emergency_routing');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'emergency_service_provider');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'fraud_detection');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'freeswitch');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'globalblacklist');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'grp');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'imc_members');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'imc_rooms');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'missed_calls');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'presentity');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'pua');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 're_grp');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'registrant');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'rls_presentity');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'rls_watchers');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'route_tree');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'rtpengine');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'rtpproxy_sockets');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'silo');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'sip_trace');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'smpp');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'speed_dial');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'subscriber');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'tls_mgm');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'uri');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'userblacklist');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'usr_preferences');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'xcap');

# temp-data tables which can be copied 1:1
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'active_watchers');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'b2b_logic');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'b2b_sca');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'location');
CALL OSIPS_TB_COPY_3_0_TO_3_1(old_db, new_db, 'watchers');
END$$
DELIMITER ;
