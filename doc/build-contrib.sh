#!/bin/bash
# scan the git log, apply exceptions and generate the proper project
# commmit statistics since September 2001
#
# Copyright (C) 2018 OpenSIPS Solutions
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA

### global OpenSIPS commit stats, self-generated on each "rebuild-proj-stats"
__PROJ_COMMITS=17783
__PROJ_LINES_ADD=2184345
__PROJ_LINES_DEL=1089621
__LAST_REBUILD_SHA=b6ef99633e17d0fac08b98364389678f8ae3a3d2

TMP_FILE=/var/tmp/.opensips-build-contrib.tmp

# be more verbose
DEBUG=${DEBUG-}

# display author emails in the resulting HTML
SHOW_AUTHOR_EMAIL=${SHOW_AUTHOR_EMAIL-}

# process all arguments (modules) supplied to build-contrib.sh in parallel
PARALLEL_BUILD=${PARALLEL_BUILD-yes}

# formatting settings
TABLE_SIZE_COMMITS=${TABLE_SIZE_COMMITS:-10}
TABLE_SIZE_ACTIVITY=${TABLE_SIZE_ACTIVITY:-10}

# Update the display name of an author, create a name-only referencing shortcut
# or link multiple emails of an author under a single identity
declare -A author_aliases
author_aliases=(
  ["AgalyaR <agalya.job@gmail.com>"]="Agalya Ramachandran <agalya.job@gmail.com>"
  ["Alessio Garzi <agarzi@clouditalia.com>"]="Alessio Garzi <gun101@email.it>"
  ["Anca Vamanu"]="Anca Vamanu <anca@opensips.org>"
  ["Andreas Granig <andreas.granig@inode.info>"]="Andreas Granig <agranig@linguin.org>"
  ["Andreas Heise"]="Andreas Heise <aheise@gmx.de>"
  ["Andrei Pelinescu-Onciul"]="Andrei Pelinescu-Onciul <andrei@iptel.org>"
  ["Bogdan Andrei IANCU <bogdan@opensips.org>"]="Bogdan-Andrei Iancu <bogdan@opensips.org>"
  ["Bogdan-Andrei Iancu <bogdan@voice-system.ro>"]="Bogdan-Andrei Iancu <bogdan@opensips.org>"
  ["Bogdan Iancu <bogdan@opensips.org>"]="Bogdan-Andrei Iancu <bogdan@opensips.org>"
  ["Carsten Bock"]="Carsten Bock <lists@bock.info>"
  ["Cerghit Ionel <ionel.cerghit@gmail.com>"]="Ionel Cerghit <ionel.cerghit@gmail.com>"
  ["Christian Schlatter <USERNAME@DOMAIN.COM>"]="Christian Schlatter <cs@unc.edu>"
  ["Christophe Sollet"]="Christophe Sollet <csollet-git@keyyo.com>"
  ["Daniel-Constantin Mierla <daniel@opensips.org>"]="Daniel-Constantin Mierla <miconda@gmail.com>"
  ["Daniel-Constantin Mierla <daniel@voice-system.ro>"]="Daniel-Constantin Mierla <miconda@gmail.com>"
  ["davesidwell <davesidwell@users.noreply.github.com>"]="Dave Sidwell <davesidwell@users.noreply.github.com>"
  ["Eric Tamme <eric@uphreak.com>"]="Eric Tamme <eric.tamme@onsip.com>"
  ["Fabian Gast <fgast+git@only640k.net>"]="Fabian Gast <fabian.gast@nfon.com>"
  ["Henning Westerholt"]="Henning Westerholt <henning.westerholt@1und1.de>"
  ["Ionut Ionita <ionutrazvan.ionita@gmail.com>"]="Ionut Ionita <ionutionita@opensips.org>"
  ["Ionut Ionita <ionut.ionita@cti.pub.ro>"]="Ionut Ionita <ionutionita@opensips.org>"
  ["Jan Janak"]="Jan Janak <jan@iptel.org>"
  ["Jarrod Baumann <jarrod@unixc.org>"]="Jarrod Baumann <j@rrod.org>"
  ["John Riordan"]="John Riordan <john@junctionnetworks.com>"
  ["Juha Heinanen"]="Juha Heinanen <jh@tutpro.com>"
  ["Kobi Eshun"]="Kobi Eshun <kobi@sightspeed.com>"
  ["Maxim Sobolev <sobomax@sippysoft.com>"]="Maksym Sobolyev <sobomax@sippysoft.com>"
  ["NAME <USERNAME@DOMAIN.COM>"]="Anonymous"
  ["Norm Brandinger <n.brandinger@gmail.com>"]="Norman Brandinger <n.brandinger@gmail.com>"
  ["Norman Brandinger"]="Norman Brandinger <n.brandinger@gmail.com>"
  ["Nick Altmann <nikbyte@users.noreply.github.com>"]="Nick Altmann <nick.altmann@gmail.com>"
  ["Nick Altmann <nick@altmann.pro>"]="Nick Altmann <nick.altmann@gmail.com>"
  ["Ovidiu Sas <osas@t40>"]="Ovidiu Sas <osas@voipembedded.com>"
  ["Oliver Mulelid-Tynes"]="Oliver Severin Mulelid-Tynes <olivermt@users.noreply.github.com>"
  ["Oliver Severin Mulelid-Tynes"]="Oliver Severin Mulelid-Tynes <olivermt@users.noreply.github.com>"
  ["Parantido De Rica <Parantido@users.noreply.github.com>"]="Parantido Julius De Rica <parantido@techfusion.it>"
  ["Peter Lemenkov"]="Peter Lemenkov <lemenkov@gmail.com>"
  ["pasandev <pasandev@ymail.com>"]="Pasan Meemaduma <pasandev@ymail.com>"
  ["Ryan Bullock"]="Ryan Bullock <rrb3942@gmail.com>"
  ["Răzvan Crainea <razvan@opensips.org>"]="Razvan Crainea <razvan@opensips.org>"
  ["Răzvan Crainea <razvan.crainea@gmail.com>"]="Razvan Crainea <razvan@opensips.org>"
  ["Răzvan Crainea <razvancrainea@users.noreply.github.com>"]="Razvan Crainea <razvan@opensips.org>"
  ["Rob Gagnon <rgagnon@vcentos7.telepointglobal.com>"]="Rob Gagnon <rgagnon24@gmail.com>"
  ["Sergey KHripchenko <shripchenko@intermedia.net>"]="Sergey Khripchenko <shripchenko@intermedia.net>"
  ["shripchenko <shripchenko@intermedia.net>"]="Sergey Khripchenko <shripchenko@intermedia.net>"
  ["rgagnon24 <rgagnon24@gmail.com>"]="Rob Gagnon <rgagnon24@gmail.com>"
  ["Saúl Ibarra Corretgé <saul@ag-projects.com>"]="Saúl Ibarra Corretgé <saghul@gmail.com>"
  ["Stéphane Alnet"]="Stéphane Alnet <stephane@shimaore.net>"
  ["Vladut Paiu <vladpaiu@opensips.org>"]="Vlad Paiu <vladpaiu@opensips.org>"
  ["Walter Doekes"]="Walter Doekes <walter+github@wjd.nu>"
  ["boris_t <boris@talovikov.ru>"]="Boris Talovikov <boris@talovikov.ru>"
  ["csollet <csollet-git@keyyo.com>"]="Christophe Sollet <csollet-git@keyyo.com>"
  ["ionutrazvanionita <ionutionita@opensips.org>"]="Ionut Ionita <ionutionita@opensips.org>"
  ["liviuchircu <liviu@opensips.org>"]="Liviu Chircu <liviu@opensips.org>"
  ["root <evillaron@gmail.com>"]="Evandro Villaron <evillaron@gmail.com>"
  ["root <root@localhost.localdomain>"]="Robison Tesini <rtesini@gmail.com>"
  ["root <root@vlad-pc.(none)>"]="Vlad Paiu <vladpaiu@opensips.org>"
  ["root <root@dell02.xipx.local>"]="Chad Attermann <chad@broadmind.com>"
  ["root <root@opensips.org>"]="Bogdan-Andrei Iancu <bogdan@opensips.org>"
  ["rvlad-patrascu <vladp@opensips.org>"]="Vlad Patrascu <vladp@opensips.org>"
  ["rvlad-patrascu <rvlad.patrascu@gmail.com>"]="Vlad Patrascu <vladp@opensips.org>"
  ["Vlad Pătrașcu <vladp@opensips.org>"]="Vlad Patrascu <vladp@opensips.org>"
  ["tallicamike <mtiganus@gmail.com>"]="Mihai Tiganus <mtiganus@gmail.com>"
)

# Associate a GitHub handle with an author or an author alias (same effect).

# ProTip: there is no need to include the email if the "name <email>" token is
# already present in "author_aliases" above (either LHS or RHS works)
declare -A github_handles
github_handles=(
  ["Agalya Ramachandran"]="AgalyaR"
  ["Alessio Garzi"]="Ozzyboshi"
  ["Alexandr Dubovikov <voip@start4.info>"]="adubovikov"
  ["Alexey Vasilyev <alexei.vasilyev@gmail.com>"]="vasilevalex"
  ["Andrei Datcu <datcuandrei@gmail.com>"]="andrei-datcu"
  ["Andrey Vorobiev <andrey.o.vorobiev@gmail.com>"]="andrey-vorobiev"
  ["Andriy Pylypenko <bamby@sippysoft.com>"]="bambyster"
  ["Aron Podrigal <aronp@guaranteedplus.com>"]="ar45"
  ["Björn Esser <besser82@fedoraproject.org>"]="besser82"
  ["Bogdan-Andrei Iancu"]="bogdan-iancu"
  ["Callum Guy <callum.guy@x-on.co.uk>"]="spacetourist"
  ["Chad Attermann"]="attermann"
  ["Christophe Sollet"]="csollet"
  ["Damien Sandras <dsandras@beip.be>"]="dsandras"
  ["Daniel-Constantin Mierla"]="miconda"
  ["Dan Pascu <dan@ag-projects.com>"]="danpascu"
  ["Dave Sidwell"]="davesidwell"
  ["Di-Shi Sun <di-shi@transnexus.com>"]="di-shi"
  ["Dusan Klinec <dusan.klinec@gmail.com>"]="ph4r05"
  ["Eric Tamme"]="etamme"
  ["Eseanu Marius Cristian <eseanu.cristian@gmail.com>"]="eseanucristian"
  ["Evandro Villaron"]="evillaron"
  ["Ezequiel Lovelle <ezequiellovelle@gmail.com>"]="lovelle"
  ["Fabian Gast"]="fgast"
  ["Federico Edorna <fedorna@anura.com.ar>"]="fedorna"
  ["Gohar Ahmed <gahmed@saevolgo.ca>"]="goharahmed"
  ["Henning Westerholt"]="henningw"
  ["Ionel Cerghit"]="ionel-cerghit"
  ["Ionut Ionita"]="ionutrazvanionita"
  ["Italo Rossi <italorossib@gmail.com>"]="italorossi"
  ["jamesabravo"]="jamesabravo"
  ["Jan Janak"]="janakj"
  ["Jarrod Baumann"]="jarrodb"
  ["Jasper Hafkenscheid <hafkensite@users.noreply.github.com>"]="hafkensite"
  ["Jeremy Martinez <jmarti70@harris.com>"]="JeremyMartinez51"
  ["Jiri Kuthan <jiri@iptel.org>"]="jiriatipteldotorg"
  ["John Kiniston <johnk@simplybits.com>"]="SB-JohnK"
  ["Juha Heinanen"]="juha-h"
  ["Kobi Eshun <kobi@sightspeed.com>"]="ekobi"
  ["Liviu Chircu"]="liviuchircu"
  ["Maksym Sobolyev"]="sobomax"
  ["Mihai Tiganus"]="tallicamike"
  ["Nick Altmann"]="nikbyte"
  ["Norman Brandinger"]="NormB"
  ["Oliver Mulelid-Tynes"]="olivermt"
  ["Ovidiu Sas"]="ovidiusas"
  ["Parantido Julius De Rica"]="Parantido"
  ["Pasan Meemaduma"]="pasanmdev"
  ["Peter Lemenkov"]="lemenkov"
  ["Razvan Crainea"]="razvancrainea"
  ["Rob Gagnon"]="rgagnon24"
  ["Robison Tesini"]="rtesini"
  ["Ryan Bullock"]="rrb3942"
  ["Saúl Ibarra Corretgé"]="saghul"
  ["Sergey Khripchenko"]="shripchenko"
  ["Stefan Pologov"]="sisoftrg"
  ["Stéphane Alnet"]="shimaore"
  ["Victor Ciurel <victor.ciurel@gmail.com>"]="victor-ciurel"
  ["Vlad Paiu"]="vladpaiu"
  ["Vlad Patrascu"]="rvlad-patrascu"
  ["Walter Doekes"]="wdoekes"
  ["Zero King <l2dy@icloud.com>"]="l2dy"
)

# Commits which have been done on behalf of the original authors
#  (ideally, PRs will for-always solve this problem,
#   and we won't ever have to edit this array)
#
# (in some cases, the committer may have also added their own minor tweaks on
# top of the provided patch, so fully re-attributing the commit to the original
# author is still not completely fair.  If you have a "split credits" idea and
# want to put more time into this, I will happily review your PR!)
declare -A fix_authors
fix_authors=(
  # global, "across multiple modules" changes (will get properly counted for each module)
  ["0de42c5b2b9f35a983f59c925a10ccf08a544ca6"]="Edson Gellert Schubert <4lists@gmail.com>"
  ["7ef17c650772b635ede8bbb7ac061c49abce584a"]="Edson Gellert Schubert <4lists@gmail.com>"
  ["9394da66657f23d11bc35396bec4ae8e108a92ad"]="UnixDev"
  ["c8c8263bbce3449c6ed140e832eb4b971dc7be77"]="Andreas Granig"
  ["cd6142cb65c0104e49f27812ef14c1c89cf8cca7"]="John Riordan"
  ["7740840eec2be4c786537c905374f5568561b878"]="Walter Doekes"
  ["14a626b000d1788c5cb1649b12f708712d11d8d9"]="Ancuta Onofrei <ancuta@voice-system.ro>"
  ["c4c6ac5947eab0d9e5dec05529aefce3c61c3ff6"]="Norman Brandinger"
  ["e65227a9c8f3c8fac0564ae8d0bba71617e034e0"]="Vallimamod Abdullah"
  ["6097c7bba18be247cdf9c72327e6bb89c7751f59"]="Walter Doekes"
  ["4db2b711486eef5a330806095d11bb4f191ab9be"]="Walter Doekes"
  ["40f53d8f4043427258e5c2eb338739e3b43f139b"]="Angel Marin"
  ["fe1e5ce3e4113da6f6645419236dfef958edaeaa"]="Stanislaw Pitucha"
  ["401d799e64ec71f6774e3a70dde8d86aef667915"]="Stanislaw Pitucha"
  ["13637069128558a04d3bf70bfb28f045ce3a97c3"]="Iouri Kharon <yjh@styx.cabel.net>"
  ["42f9066ebf4b1c459be35b2597eda4a5937a8866"]="Andreas Heise"
  ["2b1f7934628e99db96be759dc81eb3b8204b2174"]="Jeffrey Magder <jmagder@somanetworks.com>"
  ["e0fe570fe75c78d0573aa5185ae8986dba0c91da"]="Shlomi Gutman <shlomi@voicenter.com>"
  ["5346d6f2118818f51512c777fb5ee7b089c8e2fb"]="Phil D'Amore"
  ["ee0221187d8f3d57b63e3cbd615c448a5a508667"]="Marcus Hunger <hunger@sipgate.de>"
  ["45e4b0bc8b1d4198f72859d02c3ccb5f9c2cadd2"]="Marcus Hunger <hunger@sipgate.de>"
  ["0ddde446698a62566fa94d9da74549f3acd5a9ae"]="Juha Heinanen"
  ["baa5e19b90931b3d84813e4c585c4361e9fd69ca"]="Klaus Darilion"

  # aaa_radius
  ["2296c4953ce85b9cffab3a74e2c98ce3186c96db"]="Boris Ratner"
  ["77cc5af653240f7b5b2355e100082434a5dcb2ed"]="Boris Ratner"
  ["46124d967074e981afa46a200c278529cdf731cb"]="Matt Lehner"
  ["5e138604958a7b8d5c0ccb01ed8a24010e338a39"]="Авдиенко Михаил"
  ["9870f06530ba72145733bace69f15f2e802c9a3c"]="Alex Massover"

  # acc
  ["77d77188b35de71c06e5cf3c4787166888e5ff80"]="Ryan Bullock"
  ["95dc05f3ba606f80ffc1b767b8e4d47ad667584b"]="Ryan Bullock"
  ["829eaa2e409a2398842f72fe40829ef8ba3f6939"]="Alex Massover"
  ["ce4ba967cbc5c186e63993ae51181b85517a1157"]="Ovidiu Sas"
  ["eb2854457a428b3de08142a8e7c8bf0825785c3b"]="Ovidiu Sas"
  ["bdb07d33492551a2893fc1d49d453c1658b2e04b"]="Peter Nixon"

  # alias_db
  ["7c308080e1c0f9edb07a19afde45534abd681b37"]="Vladimir Romanov"

  # auth
  ["26599d25cbc140373a5c24759dce688235e57589"]="Anatoly Pidruchny"

  # auth_db
  ["dbf3497f4d09a6b1158a536d6843f8402704fd6b"]="Richard Revels"
  ["13e9a5cbe14050e622a3ef65cd34b72260a74f01"]="Kennard White"
  ["26599d25cbc140373a5c24759dce688235e57589"]="Anatoly Pidruchny"

  # avpops
  ["37eba4b6d38f379a227040397c569f0d0fe99c9c"]="Kennard White"
  ["d129377f64f13e85ea0baf6d215092b4b4776f6e"]="Norman Brandinger"
  ["b9247c08af07662c6e712179dc57bcc5f16794aa"]="Kobi Eshun"
  ["bbbaaeca433fc5d03eca587d0a33f53d7720bec5"]="Olle E. Johansson"
  ["80eee1a046ea1da637a2c8b55d3aa22cb6f16d82"]="Andrei Pelinescu-Onciul"

  # b2b_entities
  ["ec7b4e54bf7f09fb6ff56e8f8497563cf13719e8"]="@DMOsipov"
  ["cdd3c519fcbdadf351ab76bf2efbc75d35ba2803"]="Ryan Bullock"
  ["4135804ae488d8c574611298488540b5e868dd4d"]="Nick Altmann"
  ["65df3af5781c21ba8a41f23983e060badf7d9b48"]="Stéphane Alnet"
  ["ee8ca9e979e87506d6eb9260a26a7a2fee45e026"]="Henk Hesselink"
  ["fe1e5ce3e4113da6f6645419236dfef958edaeaa"]="Stanislaw Pitucha"

  # b2b_logic
  ["5a3b6ac30c4b9dd68e3ebc5cbe83e31eb1175b77"]="Nick Altmann"
  ["4135804ae488d8c574611298488540b5e868dd4d"]="Nick Altmann"
  ["1a45f19c7911bae211a83883874e6408842afceb"]="Nick Altmann"
  ["4822b9c83a7da4191eb9c67ae5e739598f2fbee8"]="Nick Altmann"
  ["28135f150c6d5268bf1d99ff6be68e9eb8f78e00"]="Nick Altmann"
  ["099adbe9f944afcd3cfc16ea1a470ea25e76860e"]="Nick Altmann"
  ["2c35387a83353a6d3e7a1cdc1ee1853c167e44b4"]="Ovidiu Sas"
  ["2e15877aab36ce18d71d06700dd7578c7831fa69"]="Ovidiu Sas"

  # benchmark
  ["6409da30683a081671eddaba08bdfcc5f5aaee00"]="David Sanders"
  ["db65db5b74d24731394027cda7ceed94efb76d7b"]="David Sanders"
  ["daaeafc070c62ce5fd21db07358573a9005442df"]="Stanislaw Pitucha"
  ["737f38461ca5478841d455d7114aff63e65fa4a7"]="Stanislaw Pitucha"
  ["567edd786e8a71ba831ce596603e1cba62dbeed8"]="Stanislaw Pitucha"

  # cachedb_mongodb
  ["18045793ada31f8f9f36d2b68b36e566456687dd"]="@jalung"

  # cachedb_redis
  ["e6847255b104518d53c1d04716a3520872053dd7"]="Ezequiel Lovelle"

  # call_control
  ["4a4c9535f8b08b88d242e83c0bccce1298eb9dc8"]="Mauro Davi"

  # carrierroute
  ["84041cb08d95061da268d303342946b3e6f29f96"]="Jonas Appel <jonas.appel@schlund.de>"
  ["fb3e4e46d9f884aa4d2371e4b767c728305f27c1"]="Henning Westerholt"
  ["38ecf98329ecfddfd3dbc3c8a4879139e8e602ac"]="Henning Westerholt"
  ["7817142c27a5a59bb2403dd4b6390231b8c35881"]="Sergio Gutierrez"
  ["d99f65c970fa3198477a30cdb3e84a10faf049cd"]="Henning Westerholt"
  ["81660a52292d1bd7c5d998a14ce7949cf6b8d744"]="Hardy Kahl <hardy.kahl@1und1.de>"
  ["deb8125173f975c7f03519e40df3ca5606f5771d"]="Hardy Kahl <hardy.kahl@1und1.de>"
  ["7290013a0d30210840c23c5ea266645b586ab28b"]="Hardy Kahl <hardy.kahl@1und1.de>"
  ["992e8826987ec398be637ddcb0ad4324f1f6bd13"]="Bob Atkins"
  ["3bdc5208ea7503205fc0b353ce37f537383ccad3"]="Carsten Bock"

  # db_berkeley
  ["cf8c99620c843cf8dfca76dc3dbc2c5928c968a1"]="William Quan"
  ["2b52b8d594680488f77e9d511c7bf9937797a42d"]="Jan Janak"

  # db_mysql
  ["46b2af2bb646a52fc7072247876cb96e0da0c71a"]="Norman Brandinger"

  # db_oracle
  ["e67fb5b8fb4b16e77b9d7c3e2da2c81b74f24635"]="Peter Lemenkov"
  ["5c2b21794d6cbe597cc123fdbb75874ee3ab1d8c"]="Peter Lemenkov"
  ["85d55c5225b8c60e16d171298c56aac696a3b05e"]="Peter Lemenkov"
  ["b0c03645f34a81851d53ee8b0a02ef83a1144f57"]="Peter Lemenkov"

  # db_postgres
  ["9e6730ec4d2e876f6b2372f1b5fb5703112079fc"]="Ruslan Bukin"
  ["2d80fcf1cfed82680a016fe723da03a303f73aff"]="Norman Brandinger"

  # db_text
  ["e8c8262d23b26bdb45b8074c6e518825ea0ca6de"]="Henning Westerholt"
  ["9391890a8123bc5c7fef594163e0179d334d5bde"]="Chris Heiser"

  # db_unixodbc
  ["659d79da476ef7eed6d39a3bc8f5ec995930afe7"]="Marco Lorrai <marco.lorrai@abbeynet.it>"
  ["09134cc7343b21ac9c7e06d8d202dc55be1433b0"]="Alex Massover"
  ["a3eca3ca69531a6bd00dca2f921c32262a17fae3"]="Carsten Bock"

  # dialog
  ["b200e11cf0308ab12c9562c552d69b1a78c52576"]="Nick Altmann"
  ["0468b6afabd2c343910c151411607ee29961921b"]="Ryan Bullock"
  ["70c7f34692e3b6652e412da3f6de1328c0cfcde0"]="Walter Doekes"
  ["477997f42f00321cd43310c29c56361bec6c95b0"]="Alex Massover"
  ["fd0634ff51108722f97731e4c5bf709067d79667"]="John Riordan"
  ["9cc90e6bd51ab940788fc77e23e3420dbae36228"]="John Riordan"
  ["25faec5c54950288aa49f412f043caaa559fbd39"]="John Riordan"
  ["afa190d872003e9c259c8e4424040fa9b55835f3"]="Hugues Mitonneau"
  ["c264a11b0c29060b4658ea40428c41ec9d731a5b"]="Hugues Mitonneau"
  ["1ae905901b94d8be0c44f9cb5e73ad81def63721"]="Richard Revels"
  ["26fe61533a2a4144c6a985ddf399daefebd8b855"]="Hugues Mitonneau"
  ["7937df2a9a3ed5961b34a5e43210b262f71116c0"]="Alex Hermann"
  ["c008a1b0d1695abc184762b08bff4520bdd1b546"]="Henning Westerholt"
  ["8e9ce5dc3e29a132ff1dbf58a51a44e09be097f4"]="Carsten Bock"
  ["b1fa1bf71de29cc35e9476ee06bdea687db98070"]="Carsten Bock"
  ["4685d0c026f6523d5563f1235dc1b41f02839ca3"]="Ovidiu Sas"
  ["76a86f7c9f9d61efa83163f09d879961090db4a1"]="Carsten Bock"
  ["937e6a88db9f41b93f57f805097c5513fca3a11f"]="Jerome Martin"
  ["08fe6e2f97ae48a47d8d4041b540ad464f68bb4b"]="Jerome Martin"
  ["aaed9b11cfd138e64f7152b2f1bb9d5e868ff271"]="Tavis Paquette <tavis@galaxytelecom.net>" # 3x
  ["cb5322df66ecd2baff2ea501b49ca111dc89a000"]="Michel Bensoussan <michel@extricom.com>" # 2x
  ["0359f75caa06cb58b09e96e1322573c13aea81dd"]="Eliot Gable <egable@broadvox.net>" # 2x
  ["b2b4305dd5217696d41dfbccc9477d0f2408f777"]="Andy Pyles"
  ["8be8f9df614c327a48e88356b3eb8c30774a84dc"]="Ron Winacott <ronw@somanetworks.com>"

  # dialplan
  ["0a7ef1191c25b81d52898dc78bdb87b7be0b1958"]="Rudy Pedraza"
  ["67c04b2ded9ff89ee3f39def4769d735044edb74"]="Sergio Gutierrez"
  ["e10369ed4237fdb66a85e162db3b84dd8ab89d44"]="Paul Wise"
  ["69b37814c291ff02b9528f041b4ae0b569a6adec"]="Henning Westerholt"

  # dispatcher
  ["83ec071d880400bb5c29ad6ab1df1a625f2b2020"]="Nick Altmann"
  ["d1887831d1488d7ab96c76e3cc207095a35052bf"]="Walter Doekes"
  ["fbda02ff646e321874fba85232e230c454e37c89"]="Stanislaw Pitucha"
  ["820f0750fbd772cc8ac7a732203c69c511ab335d"]="Kevin McAllister" # really?
  ["3f93ea0590cbb9c313ed00172b6d38ff68ef9d6f"]="Carsten Bock"
  ["0de42c5b2b9f35a983f59c925a10ccf08a544ca6"]="Konstantin Bokarius"
  ["897bfced489fd078b12c1c6f53f83d6e6d7d9780"]="Carsten Bock"
  ["50e5eaed15c8ce97770f27401908c8e94369cabb"]="Carsten Bock"
  ["8154621da217f1f36f3064c0fa4dc14e57014288"]="Federico Cabiddu"
  ["42e1a8a845af64d6cce226bb8278425ce9e1508a"]="Carsten Bock"

  # domain
  ["6a6a595095d8983561b1b36357f4d47ccb13bf81"]="Juha Heinanen"
  ["f62684327c13f29f273ac8a97e0041f79d97621c"]="@coxx"

  # drouting
  ["64da0da6fb2406eed788fa69522545dbddfeeb19"]="Nick Altmann"
  ["23f8ae3bd60018a0acbe68bc16c37c27bb661e01"]="Matt Lehner"

  # emergency
  ["e1bbbe5ea4b87b6c127a1200e50d56f2ff0947d4"]="Evandro Villaron"

  # enum
  ["2bbf6364bf30a2aaaef3259ede8bf90c44036d8c"]="Juha Heinanen"
  ["f089ca434dc5416d0a86ad663aab1fbe879b9eae"]="Greg Fausak <lgfausak@gmail.com>"
  ["85b05c11d3390bb00e6cc096d329eeb24571f774"]="Klaus Darilion"

  # event_xmlrpc
  ["0a69df1a113bd288aad2952ace55c42a8dfe1214"]="Ryan Bullock"

  # exec
  ["66c27dd0a37a2a083990c77e85b4f0574a0ff4b0"]="Dror Wald"

  # gflags
  ["5a2468d1c38a8459cee1c0e923ebfd1c3972d77c"]="Richard Revels"

  # identity
  ["3cbf9b62a88738da14a367a64896308b5878e622"]="Alexander Christ"

  # jabber
  ["e9f3bbf62c7adabad87a209653885a12eba6a596"]="Peter Lemenkov"

  # json
  ["596271ae13bb28669a4d907885c0303165b708fb"]="Nick Altmann"

  # ldap
  ["faea9a5e2025b5f10d147888fcf380a6cb1ebe64"]="Christian Schlatter"

  # load_balancer
  ["df5956eb76347611ec50a98e64a3c6c138ea94b6"]="James Van Vleet"

  # lua
  ["b95f0d139e7e2b74c258582cb6b9b727c95f7ca2"]="Arnaud Chong + Eric Gouyer"

  # mediaproxy
  ["08c743ac8e90dcb04cd58daae5e28ef4ea6ecc1f"]="Sergio Gutierrez"

  # mi_datagram
  ["6cf68d21fbee033eebb17966bb8aa74f037f70d7"]="Ancuta Onofrei <ancuta@voice-system.ro>"

  # mi_fifo
  ["dccde2318d302463cc0e3439b0ff3d8c4a5a9d25"]="Jerome Martin"

  # mmgeoip
  ["8ecf19894a61acbfce0b5f3dc36b3bf6ce925118"]="Kobi Eshun"

  # msilo
  ["fe1e5ce3e4113da6f6645419236dfef958edaeaa"]="Stanislaw Pitucha"
  ["7b371e11fda16ae247d1068e1d1ce4ba25406f61"]="Aron Rosenberg"
  ["d9c5d5ed9e7c4a14889d60394f8bcd5c21899aef"]="Juha Heinanen"
  ["f81018ef34d1afe789c015b801bfec0b5142c2b0"]="Andrea Giordana"

  # nathelper
  ["d8a8c377163ad466238bb3f621b49de622966b58"]="John Riordan"
  ["a3eb777997fd62f66f0e7b1f6eabe9bfe472845d"]="Emmanuel Buu"
  ["53358d7798d88db9e843d7ffb557aa9cc5cc2a5f"]="Christophe Sollet"
  ["8d105420558f2b204142b9b9312264c2ea31507b"]="Carsten Bock"
  ["fde24edbe45f98961de48fabde64b0e5fd201726"]="Ancuta Onofrei <ancuta@voice-system.ro>"
  ["e306d9832e85455d56b38276e2d4fe0bdeb50ab4"]="Ancuta Onofrei <ancuta@voice-system.ro>"
  ["22f8a8c7f336d6ee7cdbbd03d16f8f1ea13adbf2"]="Jeremie Le Hen"
  ["a2b31ed575d436b94cec2e2a732b2a13ac08250f"]="Laurent Schweizer <laurent.schweizer@gmail.com>"
  ["c20047dbd0657d7ef3d84d3dd35f9fe0c1557da9"]="Bayan Towfiq <bayan@towfiq.com>"
  ["201e8120c654ff7f175ab9a43ea08978b6680e8b"]="Andrei Pelinescu-Onciul"

  # nat_traversal
  ["ffb830f588bd57239474f8d6ef786b2e1a92b51a"]="Stéphane Alnet"

  # perl
  ["743879030d9174f12b187ae3095628b016317d71"]="Boris Ratner"
  ["0ad2cfad20f4f16717f9c2e5e56632fd1acbec34"]="Julien Blache"

  # permissions
  ["97973e49590ef69e8ec86f2fa929d08a1a3d5ef7"]="Saúl Ibarra Corretgé"

  # pike
  ["78e97babb5511cde3b37846e5ea7c61613d4e784"]="Andrei Pelinescu-Onciul"

  # presence
  ["3c8f45538412e1544fa4fb551d1d5804995074aa"]="Walter Doekes"
  ["ec31054f89e769e68bec060cec8a63788afcb238"]="Walter Doekes"
  ["25914e36b19ac167d57156037c4aa178b8781598"]="Ovidiu Sas"
  ["e28be091719ec84f0afd0f90a24e5d1f82d76e56"]="Kennard White"
  ["8fc84e33d370898ca7b576324ee036dfa24b1c9d"]="Vasil Kolev"
  ["23017aa50be8ec71d23d6e79df53c8b644defece"]="Kobi Eshun"
  ["b478c4d8e5b12cbad21079cf7e2194699ccf05ae"]="Klaus Darilion"
  ["8800e14409aaf4b27557f4325b40edb578b268bf"]="Kobi Eshun"
  ["79dfdd2f11323ce1a1da311b4f56b415a2f6fcf1"]="Denis Bilenko <denis@ag-projects.com>"
  ["a143ee8d8c7113994a66429c9f1ab1255a0ce5a5"]="Stanislaw Pitucha"
  ["f7159bb5a483bb535f9c892faf7a5be78922b75c"]="Benny Prijono"

  # presence_xml
  ["09717cf71cb28e9cb7b7747b170c45bb49d540df"]="Kennard White"

  # proto_smpp
  ["09b42266130943905938566752bf2e7855c13355"]="Victor Ciurel <victor.ciurel@gmail.com>"

  # pua
  ["2fb5fb43c22513ca50f2d84135339c7f7dd6b7a8"]="Alex Hermann"
  ["1639775961bdedec0a89269330324297f675d54a"]="Denis Bilenko <denis@ag-projects.com>"
  ["02258a0c8ef1050019f3852ad4251f32183de6be"]="Denis Bilenko <denis@ag-projects.com>"

  # pua_dialoginfo
  ["6d213ecdd514c76c4c2a5cddca3959c2bda6e619"]="Vallimamod Abdullah"

  # ratelimit
  ["684b452b8137200902d037f76b7a345d82bb1986"]="Stanislaw Pitucha"
  ["d31fa0623948c7db2b3c93b844a8048f46ec1b82"]="Arnaud Boussus"
  ["964397d5a9ecd0773aceed8652d20e477b719b09"]="Sergio Gutierrez"

  # regex
  ["8ae90ece51d3ebf014fa87793234462a9faeee7c"]="Marius Zbihlei <mariuszbi@gmail.com>"

  # registrar
  ["c2a0e7e7164d2fc7bba79351dcf126af4f2e79c2"]="@jalung"
  ["e5cb9805bcae7b9fb0d5391e3c5cc0f54eb65107"]="Nick Altmann"
  ["54e027adfa486cfcf993828512b2e273aeb163c2"]="Tolga Tarhan"
  ["03b5a2a19d9ace2ba7877c943d41b7bdc506bf9c"]="Nick Altmann"
  ["313208b7e0fa47801637a99bbc6868c0cf4bbe12"]="Ruslan Bukin"
  ["94143b0943a2219fa245bc4978f529927b66ad59"]="Kobi Eshun"
  ["32d0696642d14c0f100baf46b9a6ed2efc5a3b97"]="Carsten Bock"
  ["7c0b5a2759dddb6a162de001582aaa3d7f3551ed"]="Andreas Granig"
  ["f93722815873572e90d5c038df7a57964bd06522"]="Dmitry Semyonov"

  # rr
  ["ec83f6af09176aef1e09aaa969067b87e175e915"]="Ovidiu Sas"

  # rtpproxy
  ["1e5a965fc10f3fb7016d929d661e11c6484a2e62"]="Maxim Sobolev"
  ["d4b0b7e31fa9dd602751c372ca3557536982e540"]="Ryan Bullock"
  ["643ac134a0b8f0cf4e6f24215dce1356f68ad792"]="Peter Lemenkov"
  ["7d6e628a49f4c0348ab84cda9f4baffcbb5f0701"]="Peter Lemenkov"
  ["35d7cbe54d601b2d08d767a1385439c5b63e70a4"]="Walter Doekes"
  ["fbade8479291ea91d73b5dde5aa990d39dd7054d"]="Christophe Sollet"

  # sipmsgops
  ["3b37b827746459a538fb86507414d4a26481a946"]="Jarrod Baumann"
  ["bcc2fe8a63f03e48bce665bd140bf45114711281"]="Boris Ratner"
  ["e3d7a468db8794330b9297c70c98e290c0e1535a"]="Nick Altmann"
  ["75c1e8f10ca29eaef3044d3aaad7751fe8b3cbe7"]="Peter Lemenkov"
  ["9df587143764ec86958244a29ddfbceeed323d66"]="Walter Doekes"

  # siptrace
  ["3d39c0b6fcc2ae698dd7ee7f3cd2646f07fcd4af"]="Sergio Gutierrez"

  # sl
  ["86a3afd75396c3ce3e748c8d1e316115c9503317"]="Andreas Heise"

  # snmpstats
  ["ac87253a439ac390c3433b34a6e9cb3e6e50ad6c"]="Sergio Gutierrez"
  ["237bb3d33158722e240fe5ffc2b42d735643b15b"]="Anca Vamanu"
  ["8e6edeaf362d17af67fba1f87e3ad6369e5fa2b8"]="Ovidiu Sas"
  ["3f42350b554c293cc8a46cf55f3e59e1d258dbd4"]="Ovidiu Sas"

  # sst
  ["1f14961143343b80e682f8436b353921b7309fb1"]="Christophe Sollet"
  ["034e61d1fed5c2e7ef3917f7e827a562486a0bf7"]="Ron Winacott <ronw@somanetworks.com>"

  # stir_shaken
  ["70905f4803a68b583cb0bff235493bf58dd32832"]="John Burke <john@voxtelesys.net>"

  # textops
  ["ad7f17082aef12211d85d2f1ec0694c4ff21bbef"]="Christophe Sollet"
  ["ca2a72ee03ce7886a3e47af78da72a8967100db5"]="Hugues Mitonneau"
  ["cf883b8921664ac38aa3ea4b1a61c4db8d99e9e9"]="Andreas Granig"
  ["f214c9d3329b66649c79d5f73714324b4c0ede93"]="Marc Haisenko <haisenko@comdasys.com>"

  # tm
  ["1e2275aeb9df0b7406b0eea3d34229e7fbf44df0"]="Christophe Sollet"
  ["b78774d0074a3e24c53854537a829c94b9281599"]="Saúl Ibarra Corretgé"
  ["076d4e559d2cab8f790920adf2cd9cf68023e1d2"]="Anonymous"
  ["04697ee81923ca1a663fdc36c5afc04eff6b544b"]="Mark Dalby"
  ["428c1118a63845da5494e99568ce20bf83d9608e"]="Ovidiu Sas"
  ["b63e314d87816e7cfa0b65d5bd6eb3007102b25f"]="Christophe Sollet"
  ["87b5a216c842ebfd3e51f24b3377ae3219acc562"]="Marcus Hunger <hunger@sipgate.de>"
  ["0b0529ceabacacde96c856a5c25ffcb78ca58d3e"]="Marcus Hunger <hunger@sipgate.de>"
  ["28f22ad32259f27e285bb7cc45384fe755fe6878"]="Elias Baixas <elias.baixas@voztele.com>"
  ["1bae4b932a5b59302d10daac518906a812eef97e"]="Jeffrey Magder <jmagder@somanetworks.com>"
  ["57cdee3e9b1c6c763e2c663129421d26eab28f89"]="Juha Heinanen"
  ["ce2c9565ee35964066052302ce2ccce95e043b97"]="Juha Heinanen"
  ["964531fd56eef000f4f11558c1cba94ae2ac10f3"]="Daniel Hsueh <dhsueh@somanetworks.com>"
  ["f176f04b8e2158c9afdcb50cf72499a3360d35c5"]="Ingo Wolfsberger <iwolfsberger@gmx.net>"
  ["4e75ee84ca601eb33747a2fbe544d210c4249d1b"]="Andrei Pelinescu-Onciul"
  ["0f0f44c4d48e0ce60ac226efde221a44702969e7"]="Maksym Sobolyev <sobomax@sippysoft.com>"
  ["2f43c7326f5b87b6db41b244415070efdcbfdccb"]="Jan Janak <jan@iptel.org>"

  # uac
  ["d53ed37767b4b02e26ea68c49dfcac960ac193ab"]="Andreas Heise"
  ["a4c4924c60b9d29f126c5a283c1b901b6c30afa4"]="Andreas Heise"

  # userblacklist
  ["c3448532a15113ff930df13a6c2ef33fd85d8420"]="Ruslan Bukin"
  ["55ce032dcdbe6253f973a3e0dca834ab3bce4751"]="Hardy Kahl <hardy.kahl@1und1.de>"

  # usrloc
  ["de0e58a5952df7c482e78920b5ee67e5bfd0635e"]="@jalung"
  ["f434101fbe7f704f10cd55c24cc3d624b9e44771"]="Iouri Kharon <yjh@styx.cabel.net>"
  ["41d3799f1cbd36ea04135e9b322c0f60de64cba7"]="Matthew M. Boedicker <matthewm@boedicker.org>"
  ["fe11b2a681da77ddc5ddf02ffa9453d5d87879e2"]="Jeffrey Magder <jmagder@somanetworks.com>"
  ["b8ffcb70fbb66f9f873692d611a20402f53459ee"]="Klaus Darilion"

  # xcap_client
  ["eae1d5a75118f919e4d0f707a8272e5301552a42"]="Romanov Vladimir <VRomanov@yota.ru>"
)

# Commits which should be ignored: merge commits, auto-generated
# files, copy-pasted libraries, etc.
declare -A skip_commits
skip_commits=(
  ["d88a1e2f6df5e591dd4162e2fa2e6e08d93e1c96"]=1 # 13 Jun 2005, initial import
  ["a5b72648f928547d87c06c269b3118ae97b97aa4"]=1 # 13 Jun 2005, cherry-pick
  ["33b4d7c82f186e66311c9f215b76d55324f45adc"]=1 # 15 Jun 2005, cherry-pick
  ["251cc10f454050dba8f31653ee3e4c4cda87a74a"]=1 # 15 Jun 2005, cherry-pick
  ["b1ff52999c48688ae228e76ffa64e64f75d57b0d"]=1 # 16 Jun 2005, merge w/ SER
  ["d41d30a8af8b79f00947dfc9600699f62b210d4d"]=1 # 16 Jun 2005, merge w/ SER
  ["d55ce8ffc86dd433f4860d5867d03d484312d954"]=1 # 16 Jun 2005, merge w/ SER
  ["442a83e55bb475637e75fc904f998e6d585bd437"]=1 # 16 Jun 2005, merge w/ SER
  ["8fe24ec1990a1c468fcf8490228c2fcd42a15121"]=1 # Jan 2017, import FS ESL
)

# "git log" cannot properly follow an entire directory throughout all its
# historical renames, so we use this array in order to solve the problem
#
# [<new_dir>]=<old_dir>   provision such an entry for each rename
#                         (if a -> b -> c, then you need 2 entries)
declare -A mod_renames
mod_renames=(
  [db_mysql]=mysql
  [db_postgres]=postgres
  [db_text]=dbtext
  [db_flatstore]=flatstore
  [db_unixodbc]=unixodbc
  [db_perlvdb]=perlvdb
  [cpl_c]=cpl-c
  [auth_aaa]=auth_radius
  [cachedb_local]=localcache
  [uac_registrant]=registrant
  [tracer]=siptrace
  [stir_shaken]=stir
  [mi_http]=mi_json:1540473075:  # old_module:new_module_since:old_module_until
  [mi_html]=mi_http::1540473075
  [event_stream]=event_jsonrpc
)

mk_git_handle() {
  if [[ "$1" =~ ^@ ]]; then
    echo "<ulink url=\"https://github.com/$(echo "$1" | tr -d '@')\">$1</ulink>"
  elif [ -n "${github_handles["$1"]}" ]; then
    echo " (<ulink url=\"https://github.com/${github_handles["$1"]}\">@${github_handles["$1"]}</ulink>)"
  fi
}

normalize_arrays() {
  # enrich the "author_aliases" array with all name-only variants
  for author in "${!author_aliases[@]}"; do
    auth_name=$(grep -oE "^[^<]*" <<< "$author" | sed 's/\s\+$//g')
    [[ ! "$auth_name" =~ ^(root|NAME)$ ]] && \
      author_aliases["$auth_name"]=${author_aliases["$author"]}

    auth_name_rhs=$(grep -oE "^[^<]*" <<< "${author_aliases["$author"]}" | sed 's/\s\+$//g')
    [[ ! "$auth_name_rhs" =~ ^(root|NAME)$ ]] && \
      author_aliases["$auth_name_rhs"]=${author_aliases["$author"]}
  done

  # normalize the "github_handles" array (include aliases)
  for author in "${!github_handles[@]}"; do
    [ -n "${author_aliases[$author]}" ] && \
      github_handles["${author_aliases[$author]}"]="${github_handles[$author]}"
  done

  if [ -n "$DEBUG" ]; then
    for author in "${!author_aliases[@]}"; do
      echo "$author: ${author_aliases["$author"]}"
    done | sort
  fi
}

rebuild_proj_commit_stats() {
  __PROJ_COMMITS=0
  __PROJ_LINES_ADD=0
  __PROJ_LINES_DEL=0

  echo "Summing up all OpenSIPS commits! :-O"

  for sha in $(git log --reverse --format=%H); do
    [ -n "${skip_commits[$sha]}" ] && continue

    lines=($(git show $sha --format= --numstat \
         | awk '{a+=$1; r+=$2}END{print a" "r}'))
    [ -z "${lines[0]}" ] && continue

    __PROJ_COMMITS=$((__PROJ_COMMITS + 1))
    __PROJ_LINES_ADD=$(($__PROJ_LINES_ADD + ${lines[0]}))
    __PROJ_LINES_DEL=$(($__PROJ_LINES_DEL + ${lines[1]}))
    echo -en "\rProcessing commit #$__PROJ_COMMITS"
  done

  sed -i "s/^__PROJ_COMMITS.*/__PROJ_COMMITS=$__PROJ_COMMITS/" $0
  sed -i "s/^__PROJ_LINES_ADD=.*/__PROJ_LINES_ADD=$__PROJ_LINES_ADD/" $0
  sed -i "s/^__PROJ_LINES_DEL=.*/__PROJ_LINES_DEL=$__PROJ_LINES_DEL/" $0
  sed -i "s/^__LAST_REBUILD_SHA=.*/__LAST_REBUILD_SHA=$(git log -1 --format=%H)/" $0
}

count_dir_changes() {
  for sha in $(git log --reverse --format=%H $2 modules/$1); do
    [ -n "${skip_commits[$sha]}" ] && continue

    show="$(git log $sha -b --no-walk --find-renames --format="$(echo -e "%an <%ae>")" --numstat | grep -vE "modules/.*(README|contributors\.xml|\.html|\.sw[po])")"

    # grab the overrided author or just the commit author
    if [ -n "${fix_authors[$sha]}" ]; then
      author=${fix_authors[$sha]}
    else
      author=$(echo "$show" | head -1)
    fi

    # convert any author aliases
    [ -n "${author_aliases[$author]}" ] && author="${author_aliases[$author]}"

    commit_date=$(git show --format=%aD --no-patch $sha | awk '{print $2","$3","$4}')

    added="$(echo "$show" | grep -E "modules/$1" | awk '{s+=$1}END{print s}')"
    deleted="$(echo "$show" | grep -E "modules/$1" | awk '{s+=$2}END{print s}')"
    [ -z "$added" -a -z "$deleted" ] && continue

    echo "$1: $sha - ${commit_date//,/ } - $author - ${added:-0}++ ${deleted:-0}--"

    commits["$author"]=$((${commits["$author"]:-0} + 1))
    add["$author"]=$((${add["$author"]:-0} + ${added:-0}))
    del["$author"]=$((${del["$author"]:-0} + ${deleted:-0}))

    [ -z "${first_commit["$author"]}" ] && first_commit["$author"]="$commit_date"
    last_commit["$author"]="$commit_date"
  done
}

_count_module_changes() {
  if [ -n "${mod_renames[$1]}" ]; then
    IFS=':'; local arr=(${mod_renames[$1]})
    local old_mod="${arr[0]}"; local since="${arr[1]}"; local until="${arr[2]}"
    unset IFS

    # this trick helps deal with the mi_html->mi_http, mi_http->mi_json rename
    [ -z "$3" -o -z "$since" ] && \
        _count_module_changes "$old_mod" "$2" "recurse" "$until"
  fi

  if [ -n "$4" ]; then
    time_cond="--until $4"
  elif [ -z "$3" -a -n "$since" ]; then
    time_cond="--since $since"
  else
    time_cond=
  fi

  mkdir -p modules/$1$2
  count_dir_changes "$1$2" "$time_cond"
  if [ "$3" == "recurse" -a -z "$time_cond" ]; then
    rm -r modules/$1
  fi
}

count_module_changes() { _count_module_changes "$1" ""; }
count_module_doc_changes() { _count_module_changes "$1" "/doc"; }

# $1 - module name, e.g.: "tm", "cachedb_mongodb"
gen_module_contributors() {
unset score
unset commits
unset add
unset del
unset first_commit
unset last_commit

declare -A score
declare -A commits
declare -A add
declare -A del
declare -A first_commit
declare -A last_commit

tmp_file=$(mktemp $TMP_FILE.XXXXXXXXXXX)

count_module_changes $1

for i in "${!commits[@]}"; do
  score[$i]=$(python -c "from math import ceil; print(int(${commits[$i]} + ceil(${add[$i]} / ($__PROJ_LINES_ADD/float($__PROJ_COMMITS))) + ceil(${del[$i]} / ($__PROJ_LINES_DEL/float($__PROJ_COMMITS)))))")
done

declare -A sorted_scores

(
  export LC_ALL=C
  for i in "${!score[@]}"; do
    echo "$i,${score[$i]},${commits[$i]},${add[$i]},${del[$i]},${first_commit[$i]},${last_commit[$i]}"
  done | sort -t, -k2nr -k3nr -k4nr -k5nr -k1 >$tmp_file
)

#######  Generate table #1 (by commit statistics)

cat <<EOF >modules/$1/doc/contributors.xml
<!-- THIS IS AN AUTO-GENERATED FILE -->
<chapter id="contributors" xreflabel="contributors">
    <title>&contributors;</title>

<section id="contrib_commit_statistics" xreflabel="contrib_commit_statistics">
	<title>By Commit Statistics</title>

	<table frame='all'><title>Top contributors by DevScore<superscript>(1)</superscript>, authored commits<superscript>(2)</superscript> and lines added/removed<superscript>(3)</superscript></title>
	<tgroup cols='6' align='left' colsep='1' rowsep='1'>
	<thead>
	<row>
	    <entry align="center"></entry>
	    <entry align="center">Name</entry>
	    <entry align="center">DevScore</entry>
	    <entry align="center">Commits</entry>
	    <entry align="center">Lines ++</entry>
	    <entry align="center">Lines --</entry>
	</row>
	</thead>
	<tbody>
EOF

mk_author_xml_str() {
  author="$1"
  gh=$(mk_git_handle "$author")
  [[ "$author" =~ ^@ ]] && author=

  if [ -n "$SHOW_AUTHOR_EMAIL" ]; then
    echo "$(echo "$author" | sed 's/</\&lt;/g; s/>/\&gt;/g')$gh"
  else
    echo "$(echo "$author" | grep -oE "^[^<]*" | sed 's/\s\+$//')$gh"
  fi
}

index=1
side_authors=
while read line; do
  author_str=$(mk_author_xml_str "$(echo $line | awk -F'[,]' '{print $1}')")

  if [ $index -gt $TABLE_SIZE_COMMITS ]; then
    side_authors+="$author_str, "
    continue
  fi

  cat <<EOF >>modules/$1/doc/contributors.xml
	<row>
		<entry>$index. </entry>
		<entry>$author_str</entry>
		<entry align="center">$(echo $line | awk -F, '{print $2}')</entry>
		<entry align="center">$(echo $line | awk -F, '{print $3}')</entry>
		<entry align="center">$(echo $line | awk -F, '{print $4}')</entry>
		<entry align="center">$(echo $line | awk -F, '{print $5}')</entry>
	</row>
EOF
  index=$(($index+1))
done < $tmp_file

if [ -n "$side_authors" ]; then
  side_authors_para="<para><emphasis role='bold'>All remaining contributors</emphasis>: ${side_authors::-2}.</para>"
else
  side_authors_para=
fi

cat <<EOF >>modules/$1/doc/contributors.xml
	</tbody>
	</tgroup>
	</table>
	$side_authors_para
	<para>
	    <emphasis>(1) DevScore = author_commits + author_lines_added / (project_lines_added / project_commits) + author_lines_deleted / (project_lines_deleted / project_commits)</emphasis>
	</para>
	<para>
	    <emphasis>(2) including any documentation-related commits, excluding merge commits. Regarding imported patches/code, we do our best to count the work on behalf of the proper owner, as per the "fix_authors" and "mod_renames" arrays in opensips/doc/build-contrib.sh. If you identify any patches/commits which do not get properly attributed to you, please <ulink url="https://github.com/OpenSIPS/opensips/pulls"><citetitle>submit a pull request</citetitle></ulink></emphasis> which extends "fix_authors" and/or "mod_renames".
	</para>
	<para>
	    <emphasis>(3) ignoring whitespace edits, renamed files and auto-generated files</emphasis>
	</para>
</section>

EOF

####### Generate table #2 (by commit activity)
cat <<EOF >>modules/$1/doc/contributors.xml
<section id="contrib_commit_activity" xreflabel="contrib_commit_activity">
	<title>By Commit Activity</title>

	<table frame='all'><title>Most recently active contributors<superscript>(1)</superscript> to this module</title>
	<tgroup cols='3' align='left' colsep='1' rowsep='1'>
	<thead>
	<row>
	    <entry align="center"></entry>
	    <entry align="center">Name</entry>
	    <entry align="center">Commit Activity</entry>
	</row>
	</thead>
	<tbody>
EOF

(
  export LC_ALL=C
  for i in "${!score[@]}"; do
    echo "$i,${first_commit[$i]},${last_commit[$i]}"
  done | sort -s -t, -k7.1,7.4nr -k6.1,6.3fMr -k5nr -k4.1,4.4n -k3.1,3.3fM -k2n -k1 >$tmp_file
)

index=1
side_authors=
while read line; do
  author_str=$(mk_author_xml_str "$(echo $line | awk -F'[,]' '{print $1}')")

  if [ $index -gt $TABLE_SIZE_ACTIVITY ]; then
    side_authors+="$author_str, "
    continue
  fi

  cat <<EOF >>modules/$1/doc/contributors.xml
	<row>
		<entry>$index. </entry>
		<entry>$author_str</entry>
		<entry align="center">$(echo $line | awk -F, '{print $3" "$4" - "$6" "$7}')</entry>
	</row>
EOF
  index=$(($index+1))
done < $tmp_file

if [ -n "$side_authors" ]; then
  side_authors_para="<para><emphasis role='bold'>All remaining contributors</emphasis>: ${side_authors::-2}.</para>"
else
  side_authors_para=
fi

cat <<EOF >>modules/$1/doc/contributors.xml
	</tbody>
	</tgroup>
	</table>
	$side_authors_para
	<para>
	    <emphasis>(1) including any documentation-related commits, excluding merge commits</emphasis>
	</para>
</section>

</chapter>
EOF

####### Generate "documentation authors" list

unset first_commit
unset last_commit
declare -A first_commit
declare -A last_commit

count_module_doc_changes $1

(
  export LC_ALL=C
  for i in "${!first_commit[@]}"; do
    echo "$i,${first_commit[$i]},${last_commit[$i]}"
  done | sort -s -t, -k7.1,7.4nr -k6.1,6.3fMr -k5nr -k4.1,4.4n -k3.1,3.3fM -k2n -k1 >$tmp_file
)

doc_authors=
while read line; do
  doc_authors+="$(mk_author_xml_str "$(echo $line | awk -F'[,]' '{print $1}')"), "
done < $tmp_file

if [ -n "$doc_authors" ]; then
  doc_authors_para="<para><emphasis role='bold'>Last edited by:</emphasis> ${doc_authors::-2}.</para>"
else
  doc_authors_para=
fi

cat <<EOF >>modules/$1/doc/contributors.xml
<chapter id="documentation" xreflabel="documentation">
	<title>Documentation</title>
<section id="documentation_contributors" xreflabel="documentation_contributors">
	<title>Contributors</title>
	$doc_authors_para
</section>

</chapter>
EOF

rm $tmp_file
}

graceful_exit() {
  set +e
  # stop all jobs
  if [ -n "$PARALLEL_BUILD" ]; then
    for pid in ${pids[@]}; do
      killall -q $pid
      wait $pid
    done
  fi

  rm $TMP_FILE*
  exit 1
}

###############################################################################

set -e

if [ ! -r .git ]; then
  echo "Please run this script from the root opensips directory!"
  exit 1
fi

if [ $# -eq 0 ]; then
  echo "Usage: $0 (<module>[, <module>[, ...]] | rebuild-proj-stats)"
  echo "For best results, please run with git 2.7.4+"
  exit 0
fi

normalize_arrays

# if not already done, graft the entire git history of the SER project
if [[ ! $(git log --reverse --format=%H | head -1) =~ ^f06ade ]]; then
  remote=$(git remote -v | grep -i "OpenSIPS/opensips.git.*fetch" | awk '{print $1}')
  git fetch ${remote:-origin} 'refs/replace/*:refs/replace/*'
fi

if [[ "$1" =~ rebuild-proj-stats ]]; then
  rebuild_proj_commit_stats
  exit 0
fi

trap graceful_exit INT TERM

pids=()
while [ -n "$1" ]; do
  mod="$(basename $1)"

  if [ -n "$PARALLEL_BUILD" ]; then
    gen_module_contributors "$mod" &
    pids+=($!)
    echo -en "\rForked job #${#pids[@]}"
  else
    gen_module_contributors "$mod"

    if [ -n "$DEBUG" ]; then
      make modules-docbook-html modules=modules/$mod
      xdg-open "file://$(pwd)/modules/$mod/doc/$mod.html#contributors"
    fi
  fi

  shift
done

if [ -n "$PARALLEL_BUILD" ]; then
  for pid in ${pids[@]}; do
    wait $pid
  done
fi

if [ -n "$DEBUG" ]; then
  echo "Total: $__PROJ_COMMITS commits. $__PROJ_LINES_ADD++, ${__PROJ_LINES_DEL}--"
fi
