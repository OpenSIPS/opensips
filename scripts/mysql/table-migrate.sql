#
# Copyright (C) 2020-2022 OpenSIPS Solutions
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

DROP PROCEDURE IF EXISTS `OSIPS_TB_COPY_3_2_TO_3_3`;
DELIMITER $$
CREATE PROCEDURE `OSIPS_TB_COPY_3_2_TO_3_3`(
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
	IF tb_name = 'cc_agents' THEN
		SET @Q = CONCAT('INSERT INTO ', new_db, '.', tb_name, '
			(id, agentid, location, logstate, msrp_location,
				msrp_max_sessions, skills, wrapup_end_time, wrapup_time)
			SELECT
			id, agentid, location, logstate, NULL,
				4, skills, wrapup_end_time, wrapup_time
			FROM ', old_db, '.', tb_name);
	ELSEIF tb_name = 'cc_calls' THEN
		SET @Q = CONCAT('INSERT INTO ', new_db, '.', tb_name, '
			(id, state, media, ig_cback, no_rej, setup_time, eta,
				last_start, recv_time, caller_dn, caller_un,
				b2buaid, flow, agent, script_param)
			SELECT
			id, state, 0, ig_cback, no_rej, setup_time, eta,
				last_start, recv_time, caller_dn, caller_un,
				b2buaid, flow, agent, script_param
			FROM ', old_db, '.', tb_name);
	ELSEIF tb_name = 'cc_cdrs' THEN
		SET @Q = CONCAT('INSERT INTO ', new_db, '.', tb_name,
			' SELECT *, 0 FROM ', old_db, '.', tb_name);
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
