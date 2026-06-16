---
title: "Generating Config Files"
description: "Generating OpenSIPS config files is accomplished by using the menuconfig tool. Because the graphical interface is ncurses based, please make sure to first in..."
---

Generating OpenSIPS config files is accomplished by using the menuconfig tool. Because the graphical interface is ncurses based, please make sure to first install the ncurses development library ( typically libncurses5-dev ). 

## Using the Menuconfig Tool

The menuconfig can be ran either directly from the OpenSIPS sources, or post installation, from the installation path :

* From sources, you can run

```bash
make menuconfig
```

* After installation, you can run menuconfig directly from the installation path, by running

```text
[install_path]/sbin/osipsconfig
```

Once in the menuconfig tool, navigate to the 'Generate OpenSIPS Script' option, and then choose your desired script type.
Once you have chosen you script type, you will be able to go to configure the various available options for that script ( described below ). Enabling certain options per script is done by using the spacebar key. Once you have configured your desired options, you can hit the 'q' key to go to the previous menu, and hit 'Save Changes'. Then, you can generate the OpenSIPS script with your configurations. At the end, the graphical tool will give you the path for your newly generated config file ( eg : Config generated : /usr/local/etc/opensips/opensips_residential_2013-5-21_12:39:48.cfg )

 ![menuconfig snapshot](/images/docs/tutorials/menuconfig_snapshot.png)

## Types of Configs

So far, the OpenSIPS 3.5 menuconfig automated script generator supports 3 types of scripts. Here are the types of scripts, along with the available options per script :

* Residential Script

  * ENABLE_TCP : OpenSIPS will listen on TCP for SIP requests
  * ENABLE_TLS : OpenSIPS will listen on TCP for SIP requests
  * USE_ALIASES : OpenSIPS will allow the use of Aliases for SIP users
  * USE_AUTH : OpenSIPS will authenticate Register & Invite requests
  * USE_DBACC : OpenSIPS will save ACC entries in DB for all calls
  * USE_DBUSRLOC : OpenSIPS will persistently store User Location entries in the DB
  * USE_DIALOG : OpenSIPS will keep track of active dialogs
  * USE_MULTIDOMAIN : OpenSIPS will handle multiple domains for subscribers
  * USE_NAT : OpenSIPS will try to cope with NAT by fixing SIP msgs and engaging RTPProxy
  * USE_PRESENCE : OpenSIPS will act as a Presence server
  * USE_DIALPLAN : OpenSIPS will use dialplan for transformation of local numbers
  * VM_DIVERSION : OpenSIPS will redirect to VM calls not reaching the subscribers 
  * HAVE_INBOUND_PSTN : OpenSIPS will accept calls from PSTN gateways (with static IP authentication)
  * HAVE_OUTBOUND_PSTN : OpenSIPS will send numerical dials to PSTN gateways (with static IP definition)
  * USE_DR_PSTN : OpenSIPS will use Dynamic Routing Support ( LCR ) for PSTN interconnection

* Trunking Script

  * ENABLE_TCP : OpenSIPS will listen on TCP for SIP requests
  * ENABLE_TLS : OpenSIPS will listen on TCP for SIP requests
  * USE_DBACC : OpenSIPS will save ACC entries in DB for all calls
  * USE_DIALPLAN : OpenSIPS will use dialplan for transformation of local numbers
  * USE_DIALOG : OpenSIPS will keep track of active dialogs
  * DO_CALL_LIMITATION : OpenSIPS will limit the number of parallel calls per trunk

* Load-Balancer Script

  * ENABLE_TCP : OpenSIPS will listen on TCP for SIP requests
  * ENABLE_TLS : OpenSIPS will listen on TCP for SIP requests
  * USE_DBACC : OpenSIPS will save ACC entries in DB for all calls
  * USE_DISPATCHER : OpenSIPS will use DISPATCHER instead of Load-Balancer for distributing the traffic
  * DISABLE_PINGING : OpenSIPS will not ping at all the destinations (otherwise it will ping when detected as failed)

## Post-Generation Script editing

After generating your OpenSIPS script with the menuconfig tool, you need to open the script with your favorite editor, and go through all the '# CUSTOMIZE ME' comments in the script. Those comments mark the places where user attention is needed, and usually refer to customizing the OpenSIPS listening address or setting the proper database URL.

Upon making the appropriate '# CUSTOMIZE ME' changes, you can save your script
and take it for a test drive.
