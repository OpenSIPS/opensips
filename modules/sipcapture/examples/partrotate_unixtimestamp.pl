#!/usr/bin/perl
#
# partrotate_unixtimestamp - perl script for mySQL partition rotation
#
# Copyright (C) 2011 Alexandr Dubovikov (QSC AG) (alexandr.dubovikov@gmail.com)
#
# This file is part of webhomer, a free capture server.
#
# partrotate_unixtimestamp is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version
#
# partrotate_unixtimestamp is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

use DBI;

$version = "0.2.1";
$mysql_table = "sip_capture";
$mysql_dbname = "homer_db";
$mysql_user = "mysql_login";
$mysql_password = "mysql_password";
$mysql_host = "localhost";
$maxparts = 6; #6 days
$newparts = 2; #new partitions for 2 days. Anyway, start this script daily!
@stepsvalues = (86400, 3600, 1800, 900); 
$partstep = 0; # 0 - Day, 1 - Hour, 2 - 30 Minutes, 3 - 15 Minutes 

#Check it
$partstep=0 if(!defined $stepsvalues[$partstep]);
#Mystep
$mystep = $stepsvalues[$partstep];
#Coof
$coof=int(86400/$mystep);

#How much partitions
$maxparts*=$coof;
$newparts*=$coof;

my $db = DBI->connect("DBI:mysql:$mysql_dbname:$mysql_host:3306", $mysql_user, $mysql_password);

#$db->{PrintError} = 0;

my $sth = $db->do("
CREATE TABLE IF NOT EXISTS `".$mysql_table."` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `date` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `micro_ts` bigint(18) NOT NULL DEFAULT '0',
  `method` varchar(50) NOT NULL DEFAULT '',
  `reply_reason` varchar(100) NOT NULL,
  `ruri` varchar(200) NOT NULL DEFAULT '',
  `ruri_user` varchar(100) NOT NULL DEFAULT '',
  `from_user` varchar(100) NOT NULL DEFAULT '',
  `from_tag` varchar(64) NOT NULL DEFAULT '',
  `to_user` varchar(100) NOT NULL DEFAULT '',
  `to_tag` varchar(64) NOT NULL,
  `pid_user` varchar(100) NOT NULL DEFAULT '',
  `contact_user` varchar(120) NOT NULL,
  `auth_user` varchar(120) NOT NULL,
  `callid` varchar(100) NOT NULL DEFAULT '',
  `callid_aleg` varchar(100) NOT NULL DEFAULT '',
  `via_1` varchar(256) NOT NULL,
  `via_1_branch` varchar(80) NOT NULL,
  `cseq` varchar(25) NOT NULL,
  `diversion` varchar(256) NOT NULL,
  `reason` varchar(200) NOT NULL,
  `content_type` varchar(256) NOT NULL,
  `authorization` varchar(256) NOT NULL,
  `user_agent` varchar(256) NOT NULL,
  `source_ip` varchar(50) NOT NULL DEFAULT '',
  `source_port` int(10) NOT NULL,
  `destination_ip` varchar(50) NOT NULL DEFAULT '',
  `destination_port` int(10) NOT NULL,
  `contact_ip` varchar(60) NOT NULL,
  `contact_port` int(10) NOT NULL,
  `originator_ip` varchar(60) NOT NULL DEFAULT '',
  `originator_port` int(10) NOT NULL,
  `proto` int(5) NOT NULL,
  `family` int(1) DEFAULT NULL,
  `rtp_stat` varchar(256) NOT NULL,
  `type` int(2) NOT NULL,
  `node` varchar(125) NOT NULL,
  `msg` text NOT NULL,
  PRIMARY KEY (`id`,`date`),
  KEY `ruri_user` (`ruri_user`),
  KEY `from_user` (`from_user`),
  KEY `to_user` (`to_user`),
  KEY `pid_user` (`pid_user`),
  KEY `auth_user` (`auth_user`),
  KEY `callid_aleg` (`callid_aleg`),
  KEY `date` (`date`),
  KEY `callid` (`callid`),
  KEY `method` (`method`),
  KEY `source_ip` (`source_ip`),
  KEY `destination_ip` (`destination_ip`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1
PARTITION BY RANGE ( UNIX_TIMESTAMP(`date`)) (PARTITION pmax VALUES LESS THAN MAXVALUE ENGINE = MyISAM);
");


my $query = "SELECT UNIX_TIMESTAMP(CURDATE() - INTERVAL 1 DAY)";
$sth = $db->prepare($query);
$sth->execute();
my ($curtstamp) = $sth->fetchrow_array();
$curtstamp+=0; 

my $query = "SELECT COUNT(*) FROM INFORMATION_SCHEMA.PARTITIONS"
            ."\n WHERE TABLE_NAME='".$mysql_table."' AND TABLE_SCHEMA='".$mysql_dbname."'";
$sth = $db->prepare($query);
$sth->execute();
my ($partcount) = $sth->fetchrow_array();

while($partcount > $maxparts ) {

    $query = "SELECT PARTITION_NAME, MIN(PARTITION_DESCRIPTION)"
             ."\n FROM INFORMATION_SCHEMA.PARTITIONS WHERE TABLE_NAME='".$mysql_table."'"
             ."\n AND TABLE_SCHEMA='".$mysql_dbname."';";

    $sth = $db->prepare($query);
    $sth->execute();
    my ($minpart,$todaytstamp) = $sth->fetchrow_array();
    $todaytstamp+=0;
    
    #Dont' delete the partition for the current day or for future. Bad idea!
    if($curtstamp <= $todaytstamp) {    
          $partcount = 0;
          next;
    }
           
    #Delete
    $query = "ALTER TABLE ".$mysql_table." DROP PARTITION ".$minpart;
    $db->do($query);
    if (!$db->{Executed}) {
           print "Couldn't drop partition: $minpart\n";
           break;
    }
    
    #decrease partcount
    $partcount--;
}

# < condition
$curtstamp+=(86400);

#Create new partitions 
for(my $i=0; $i<$newparts; $i++) {

    $oldstamp = $curtstamp;
    $curtstamp+=$mystep;
    
    ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($oldstamp);

    my $newpartname = sprintf("p%04d%02d%02d%02d",($year+=1900),(++$mon),$mday,$hour);    
    
    $query = "SELECT COUNT(*) "
             ."\n FROM INFORMATION_SCHEMA.PARTITIONS WHERE TABLE_NAME='".$mysql_table."'"
             ."\n AND TABLE_SCHEMA='".$mysql_dbname."' AND PARTITION_NAME='".$newpartname."'"
             ."\n AND PARTITION_DESCRIPTION = '".$curtstamp."'";
             
    $sth = $db->prepare($query);
    $sth->execute();
    my ($exist) = $sth->fetchrow_array();
    $exist+=0;
    
    if(!$exist) {

	# Fix MAXVALUE. Thanks Dorn B. <djbinter@gmail.com> for report and fix.
        $query = "ALTER TABLE ".$mysql_table." REORGANIZE PARTITION pmax INTO (PARTITION ".$newpartname
                                ."\n VALUES LESS THAN (".$curtstamp.") ENGINE = MyISAM, PARTITION pmax VALUES LESS THAN MAXVALUE ENGINE = MyISAM)";  

        $db->do($query);
                    
        if (!$db->{Executed}) {
             print "Couldn't add partition: $newpartname\n";
        }
    }    
}
