CREATE TABLE IF NOT EXISTS `report_capture` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `micro_ts` bigint(18) NOT NULL DEFAULT '0',
  `correlation_id` varchar(256) NOT NULL DEFAULT '',
  `source_ip` varchar(60) NOT NULL DEFAULT '',
  `source_port` int(10) NOT NULL DEFAULT 0,
  `destination_ip` varchar(60) NOT NULL DEFAULT '',
  `destination_port` int(10) NOT NULL DEFAULT 0,
  `proto` int(5) NOT NULL DEFAULT 0,
  `family` int(1) DEFAULT NULL,
  `type` int(2) NOT NULL DEFAULT 0,
  `node` varchar(125) NOT NULL DEFAULT '',
  `msg` varchar(1500) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`,`date`),
  KEY `date` (`date`),
  KEY `correlationid` (`correlation_id`(255))
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=8;
