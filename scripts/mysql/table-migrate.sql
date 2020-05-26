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

DROP PROCEDURE IF EXISTS `OSIPS_TB_COPY_3_0_TO_3_1`;
DELIMITER $$
CREATE PROCEDURE `OSIPS_TB_COPY_3_0_TO_3_1`(
	IN old_db CHAR(64), IN new_db CHAR(64), IN tb_name CHAR(64))
BEGIN
SET @c1 = (SELECT EXISTS(
       SELECT * FROM information_schema.tables
       WHERE table_schema = old_db
       AND table_name = tb_name
));
SET @c2 = (SELECT EXISTS(
       SELECT * FROM information_schema.tables
       WHERE table_schema = new_db
       AND table_name = tb_name
));
IF @c1 = 1 AND @c2 = 1 THEN
	IF tb_name = 'b2b_entities' THEN
		SET @Q = CONCAT(
		'INSERT INTO ', new_db, '.', tb_name, '
			(id, type, state, ruri, from_uri, to_uri, from_dname, to_dname, tag0,
				tag1, callid, cseq0, cseq1, contact0, contact1, route0, route1,
				sockinfo_srv, param, mod_name, storage, lm, lrc, lic, leg_cseq,
				leg_route, leg_tag, leg_contact, leg_sockinfo)
		SELECT
			id, type, state, ruri, from_uri, to_uri, from_dname, to_dname, tag0,
				tag1, callid, cseq0, cseq1, contact0, contact1, route0, route1,
				sockinfo_srv, param, "b2b_logic", NULL, lm, lrc, lic, leg_cseq,
				leg_route, leg_tag, leg_contact, leg_sockinfo
		FROM ', old_db, '.', tb_name);
	ELSEIF tb_name = 'cc_agents' THEN
		SET @Q = CONCAT(
		'INSERT INTO ', new_db, '.', tb_name, '
			(id, agentid, location, logstate, skills, wrapup_end_time)
		SELECT
			id, agentid, location, logstate, skills, last_call_end
		FROM ', old_db, '.', tb_name);
	ELSEIF tb_name = 'cc_calls' THEN
		SET @Q = CONCAT(
		'INSERT INTO ', new_db, '.', tb_name, '
		SELECT
			*, ""
		FROM ', old_db, '.', tb_name);
	ELSEIF tb_name = 'cc_flows' THEN
		SET @Q = CONCAT(
		'INSERT INTO ', new_db, '.', tb_name, '
			(id, flowid, priority, skill, prependcid, max_wrapup_time,
				dissuading_hangup, dissuading_onhold_th, dissuading_ewt_th,
				dissuading_qsize_th, message_welcome, message_queue,
				message_dissuading, message_flow_id)
		SELECT
			id, flowid, priority, skill, prependcid, 0,
				0, 0, 0, 0, message_welcome, message_queue,
				"", NULL
		FROM ', old_db, '.', tb_name);
	ELSEIF tb_name = 'dialog' THEN
		SET @Q = CONCAT(
		'INSERT INTO ', new_db, '.', tb_name, '
		SELECT
			*, NULL, NULL, NULL
		FROM ', old_db, '.', tb_name);
	ELSEIF tb_name = 'dr_carriers' THEN
		SET @Q = CONCAT(
		'INSERT INTO ', new_db, '.', tb_name, '
			(id, carrierid, gwlist, flags, sort_alg, state, attrs, description)
		SELECT
			id, carrierid, gwlist, flags, "N", state, attrs, description
		FROM ', old_db, '.', tb_name);
	ELSEIF tb_name = 'dr_rules' THEN
		SET @Q = CONCAT(
		'INSERT INTO ', new_db, '.', tb_name, '
			(ruleid, groupid, prefix, timerec, priority, routeid, gwlist,
				sort_alg, sort_profile, attrs, description)
		SELECT
			ruleid, groupid, prefix, timerec, priority, routeid, gwlist,
				"N", NULL, attrs, description
		FROM ', old_db, '.', tb_name);
	ELSEIF tb_name = 'load_balancer' THEN
		SET @Q = CONCAT(
		'INSERT INTO ', new_db, '.', tb_name, '
			(id, group_id, dst_uri, resources, probe_mode, attrs, description)
		SELECT
			id, group_id, dst_uri, resources, probe_mode, NULL, description
		FROM ', old_db, '.', tb_name);
	ELSE
		SET @Q = CONCAT('INSERT INTO ', new_db, '.', tb_name,
						' SELECT * FROM ', old_db, '.', tb_name);
	END IF;

	PREPARE stmt FROM @Q;
	EXECUTE stmt;
	DEALLOCATE PREPARE stmt;
END IF;
END$$
DELIMITER ;
