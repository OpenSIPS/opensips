/*
 * clusterer_controller - module exports, parameters, init and destroy
 *
 * Copyright (C) 2026 Yury Kirsanov
 *                          VoIPLine Telecom
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#include "cl_ctr.h"
#include "cl_ctr_stats.h"
#include "cl_ctr_events.h"

static int mod_init(void);
static int cl_ctr_child_init(int rank);
static void mod_destroy(void);

cl_ctr_cluster_t  cl_ctr_clusters[CL_CTR_MAX_CLUSTERS];
int           cl_ctr_cluster_count = 0;

/* Raw "cluster" strings collected during modparam parsing */
static char *cl_ctr_cluster_strs[CL_CTR_MAX_CLUSTERS];
static int   cl_ctr_cluster_str_count = 0;

/* =========================================================================
 * Module parameters
 * ========================================================================= */

/* Global modparams - apply to all clusters unless overridden per-cluster */
char *my_ip             = NULL;  /* explicit IP, or NULL for auto-detect */
static char *my_interface      = NULL;  /* explicit interface name, or NULL      */
int   query_time        = 5;
char *password          = CL_CTR_DEFAULT_PASSWORD; /* default; falls back per cluster */
static char *on_config_mismatch_s = NULL;              /* raw modparam string   */
int   on_config_mismatch   = CL_CTR_CFGMISMATCH_REJECT; /* resolved; default reject */

/* Resolved at mod_init time - always valid after cl_ctr_resolve_local_identity() */
static char my_ip_buf[INET_ADDRSTRLEN];
/* which of the three resolution paths produced my_ip - reported through
 * clctr_api.get_my_ip() so a consumer can show it without guessing */
const char *my_ip_src = "unresolved";
char my_interface_buf[IF_NAMESIZE];


/* Local node identity - populated at mod_init by scanning the config file */
uint16_t my_node_id                              = 0;
/* This process's incarnation (see CL_CTR_INC_SZ) - set once in mod_init and
 * inherited across fork, so the worker and mod_destroy's GOODBYE agree. */
uint64_t cl_ctr_incarnation                      = 0;

/* clusterer integration - loaded at mod_init if clusterer use_controller=1 */
clusterer_ctrl_binds_t clctl;
struct clusterer_binds cl_api;
int cl_api_loaded = 0;
int                    clctl_loaded  = 0;
int                    manage_shtags = 1;
int                    consumer_retries = CL_CTR_CONSUMER_RETRIES_DEFAULT;
int                    consumer_retry_ms = CL_CTR_CONSUMER_RETRY_MS_DEFAULT;
/*
 * enable_reliable_send - kill switch for the consumer ARQ (ACK + retransmit).
 *
 * ON by default, which it was NOT when it was first added hours earlier: the
 * flag then could not work on a channel carrying concurrent messages, and
 * failed silently when it did not. A retransmit reuses its original seq, and
 * the receiver's anti-replay guard was a bare high-water mark, so once any
 * later message had been accepted the repair copy was rejected as
 * out-of-order AND re-ACKed - which stopped the sender retransmitting and left
 * it believing it had delivered. Measured on the cross-node cache pull channel
 * under 40% reply loss: plain 61.2% delivered, RELIABLE 49.4%, at two to three
 * times the packets, with not one retransmitted payload ever delivered.
 *
 * The replay window (cl_ctr_replay_t) removes that: a seq below the mark whose
 * bit is clear was never delivered, so its retransmit is accepted, while a seq
 * whose bit is set is a true duplicate and is re-ACKed without being delivered
 * twice. The flag now does what it says on any channel.
 *
 * The switch survives the fix rather than being deleted with it, because ARQ
 * still has a cost the operator may not want on a given fleet: a reliable
 * broadcast draws one ACK per member, so on a large cluster a single message
 * becomes an event. Turning this off degrades every reliable send to a plain
 * one - lossy, but cheap and never silent about it.
 */
int                    enable_reliable_send = 1;
/* master_stickiness (global default; per-cluster override via "cluster" string):
 *   1 (default) = the master is "sticky": a live master keeps the role and is
 *                 NOT displaced when a higher-IP node joins.  The highest-IP
 *                 non-master is designated BACKUP and takes over only when the
 *                 master fails.  A higher-IP joiner just replaces the backup.
 *                 Result: fewer master handovers.
 *   0           = not sticky - pure highest-IP election, so a higher-IP node
 *                 takes over as master as soon as it appears (more handovers). */
int                    master_stickiness = 1;
/* release_tag_when_isolated: 1 = a master that hears fewer than half of its
 * last stable membership for a whole election window gives up the active
 * sharing tag until it hears a majority again (cl_ctr_isolation_round()).
 * Off by default - availability first. */
int                    release_tag_when_isolated = 0;
static int      consumer_rate_limit = CL_CTR_CONSUMER_RATE_DEFAULT;
static char     my_bin_sockets[CL_CTR_MAX_BIN_SOCKETS][CL_CTR_MAX_BIN_SOCK_LEN];
static int      my_bin_count                            = 0;


/**
 * cl_ctr_add_cluster_param() - collect "cluster" modparam strings.
 * Actual parsing happens in mod_init() after all params are set.
 */
static int cl_ctr_add_cluster_param(modparam_t type, void *val)
{
    if (cl_ctr_cluster_str_count >= CL_CTR_MAX_CLUSTERS) {
	LM_ERR("clusterer_controller: too many clusters (max %d)\n",
	       CL_CTR_MAX_CLUSTERS);
	return -1;
    }
    {
	size_t _len = strlen((char *)val) + 1;
	cl_ctr_cluster_strs[cl_ctr_cluster_str_count] = pkg_malloc(_len);
	if (!cl_ctr_cluster_strs[cl_ctr_cluster_str_count]) {
	    LM_ERR("clusterer_controller: pkg_malloc failed\n");
	    return -1;
	}
	memcpy(cl_ctr_cluster_strs[cl_ctr_cluster_str_count], (char *)val, _len);
    }
    cl_ctr_cluster_str_count++;
    return 0;
}

static const param_export_t params[] = {
    {"cluster",    STR_PARAM | USE_FUNC_PARAM, (void *)cl_ctr_add_cluster_param},
    {"my_ip",      STR_PARAM, &my_ip},
    {"interface",  STR_PARAM, &my_interface},
    {"query_time", INT_PARAM, &query_time},
    {"password",      STR_PARAM, &password},
    {"consumer_rate_limit", INT_PARAM, &consumer_rate_limit},
    {"consumer_retries",    INT_PARAM, &consumer_retries},
    {"consumer_retry_ms",   INT_PARAM, &consumer_retry_ms},
    {"enable_reliable_send", INT_PARAM, &enable_reliable_send},
    {"manage_shtags", INT_PARAM, &manage_shtags},
    {"master_stickiness", INT_PARAM, &master_stickiness},
    {"release_tag_when_isolated", INT_PARAM, &release_tag_when_isolated},
    {"on_config_mismatch", STR_PARAM, &on_config_mismatch_s},
    {0, 0, 0}
};

/* =========================================================================
 * Extra-process export  (layout from mi_fifo.c)
 * ========================================================================= */

static proc_export_t procs[] = {
    /* NEEDS_SCRIPT because a message arriving for the script's channel
     * raises an event here, and an event route is script: without it the
     * route structures are not set up in this process and running one
     * crashes. */
    {"clusterer_controller worker", 0, 0, cl_ctr_worker, 1,
        PROC_FLAG_INITCHILD | PROC_FLAG_HAS_IPC | PROC_FLAG_NEEDS_SCRIPT},
    {0, 0, 0, 0, 0, 0}
};

/* =========================================================================
 * Module dependency
 * ========================================================================= */

static const dep_export_t deps = {
    {
	/* proto_bin must load before us so its listeners are registered */
	{ MOD_TYPE_DEFAULT, "proto_bin",  DEP_ABORT },
		{ MOD_TYPE_DEFAULT, "clusterer", DEP_ABORT },
	{ MOD_TYPE_NULL, NULL, 0 },
    },
    { { NULL, NULL } },
};

/* =========================================================================
 * module_exports
 * ========================================================================= */

struct module_exports exports = {
    "clusterer_controller",
    MOD_TYPE_DEFAULT,
    MODULE_VERSION,
    DEFAULT_DLFLAGS,
    0,
    &deps,
    cl_ctr_cmds,          /* cmds - per-peer lookup functions */
    0,                /* acmds   */
    params,
    0,                /* stats   */
    mi_cmds,
    cl_ctr_mod_vars,      /* pvs - read-only $cl_ctr_* variables */
    0,                /* transforms */
    procs,
    0,                /* pre_init_f */
    mod_init,
    0,                /* response_f */
    mod_destroy,
    cl_ctr_child_init,    /* child_init_f */
    0                 /* reload_confirm_f */
};
/* =========================================================================
 * Lifecycle
 * ========================================================================= */

/**
 * cl_ctr_resolve_local_identity() - determine my_ip and my_interface_buf.
 *
 * Three modes depending on which modparams were provided:
 *
 *   Mode 1 - ip= only:
 *     Walk getifaddrs() to find the interface that owns the given IP.
 *     Fails if no interface owns it.
 *
 *   Mode 2 - interface= only:
 *     Walk getifaddrs() to find the interface and take its first IPv4 address.
 *     Warns if the interface has multiple IPv4 addresses; uses the first one
 *     (the kernel's enumeration order matches `ip addr show`).
 *
 *   Mode 3 - neither:
 *     Connect a throw-away UDP socket to the multicast group (no data sent).
 *     getsockname() returns the source IP the kernel would select.
 *     Reverse-look up the interface name via getifaddrs().
 *
 * On success: my_ip points to a valid dotted-decimal IPv4 string and
 *             my_interface_buf holds the interface name (may be empty if the
 *             reverse lookup failed in mode 3 - non-fatal).
 */
/**
 * cl_ctr_parse_cluster_str() - parse one "cluster" modparam string into cl.
 *
 * Format: "id=N,multicast=A.B.C.D:PORT[,password=STRING][,bin_socket=bin:IP:PORT]"
 * - id= required, positive integer
 * - multicast= required, IPv4:port
 * - password= optional, falls back to global password modparam
 * - bin_socket= optional, BIN socket for this cluster; falls back to
 *   first discovered socket (or only socket if one exists)
 */
static int cl_ctr_parse_cluster_str(const char *str, cl_ctr_cluster_t *cl)
{
    char        buf[2048];
    char       *p, *tok, *key, *val, *colon;
    struct in_addr addr;
    unsigned char  first_octet;
    int         has_id = 0, has_mcast = 0;

    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Defaults */
    cl->multicast_port = 3333;
    strncpy(cl->password, password, sizeof(cl->password) - 1);
    cl->password[sizeof(cl->password) - 1] = '\0';
    cl->manage_shtags = -1; /* sentinel: inherit global default in mod_init */
    cl->consumer_retries = -1;
    cl->consumer_retry_ms = -1;
    cl->consumer_rate = -1;
    cl->master_stickiness = -1; /* sentinel: inherit global default in mod_init */

    for (tok = strtok_r(buf, ",", &p); tok; tok = strtok_r(NULL, ",", &p)) {
	while (*tok == ' ' || *tok == '\t') tok++;
	key = tok;
	val = strchr(tok, '=');
	if (!val) continue;
	*val++ = '\0';

	if (strcmp(key, "id") == 0) {
	    cl->cluster_id = atoi(val);
	    if (cl->cluster_id <= 0 || cl->cluster_id > 65535) {
		LM_ERR("clusterer_controller: cluster id must be 1..65535 "
		       "(carried as a 2-byte field on the wire)\n");
		return -1;
	    }
	    has_id = 1;

	} else if (strcmp(key, "multicast") == 0) {
	    colon = strrchr(val, ':');
	    if (colon) {
		*colon = '\0';
		cl->multicast_port = atoi(colon + 1);
		if (cl->multicast_port <= 0 || cl->multicast_port > 65535) {
		    LM_ERR("clusterer_controller: invalid port in cluster '%s'\n", str);
		    return -1;
		}
	    }
	    strncpy(cl->multicast_address, val, INET_ADDRSTRLEN - 1);
	    cl->multicast_address[INET_ADDRSTRLEN - 1] = '\0';
	    if (inet_aton(cl->multicast_address, &addr) == 0) {
		LM_ERR("clusterer_controller: invalid multicast address '%s'\n", val);
		return -1;
	    }
	    first_octet = (unsigned char)((ntohl(addr.s_addr) >> 24) & 0xFF);
	    if (first_octet < 224 || first_octet > 239) {
		LM_ERR("clusterer_controller: '%s' is not a multicast address\n", val);
		return -1;
	    }
	    has_mcast = 1;

	} else if (strcmp(key, "password") == 0) {
	    strncpy(cl->password, val, sizeof(cl->password) - 1);
	    cl->password[sizeof(cl->password) - 1] = '\0';

	} else if (strcmp(key, "bin_socket") == 0) {
	    if (strlen(val) >= CL_CTR_MAX_BIN_SOCK_LEN) {
		LM_ERR("clusterer_controller: bin_socket value too long\n");
		return -1;
	    }
	    strncpy(cl->bin_socket, val, CL_CTR_MAX_BIN_SOCK_LEN - 1);
	    cl->bin_socket[CL_CTR_MAX_BIN_SOCK_LEN - 1] = '\0';

	} else if (strcmp(key, "consumer_retries") == 0) {
	    cl->consumer_retries = atoi(val);
	    if (cl->consumer_retries < 0 || cl->consumer_retries > 10) {
		LM_ERR("clusterer_controller: consumer_retries must be 0..10 "
		       "in '%s'\n", str);
		return -1;
	    }

	} else if (strcmp(key, "consumer_retry_ms") == 0) {
	    cl->consumer_retry_ms = atoi(val);
	    if (cl->consumer_retry_ms < 5 || cl->consumer_retry_ms > 5000) {
		LM_ERR("clusterer_controller: consumer_retry_ms must be "
		       "5..5000 in '%s'\n", str);
		return -1;
	    }

	} else if (strcmp(key, "consumer_rate_limit") == 0) {
	    cl->consumer_rate = atoi(val);
	    if (cl->consumer_rate < 1) {
		LM_ERR("clusterer_controller: consumer_rate_limit must be "
		       "positive in '%s'\n", str);
		return -1;
	    }

	} else if (strcmp(key, "manage_shtags") == 0) {
	    cl->manage_shtags = atoi(val) ? 1 : 0;

	} else if (strcmp(key, "master_stickiness") == 0) {
	    cl->master_stickiness = atoi(val) ? 1 : 0;

	} else if (strcmp(key, "uuid") == 0) {
	    if (cl_ctr_cid_parse_pin(val, cl->cid_pin) < 0) {
		LM_ERR("clusterer_controller: empty uuid= in '%s'\n", str);
		return -1;
	    }
	    cl->cid_pinned = 1;
	}
    }

    if (!has_id) {
	LM_ERR("clusterer_controller: cluster string missing id= in '%s'\n", str);
	return -1;
    }
    if (!has_mcast) {
	LM_ERR("clusterer_controller: cluster string missing multicast= in '%s'\n", str);
	return -1;
    }
    return 0;
}

static int cl_ctr_resolve_local_identity(void)
{
    struct ifaddrs *ifap = NULL, *ifa;
    int             found = 0;

    if (getifaddrs(&ifap) < 0) {
	LM_ERR("clusterer_controller: getifaddrs() failed: %s\n",
	       strerror(errno));
	return -1;
    }

    if (my_ip && *my_ip) {
	/* ---- Mode 1: ip= explicitly provided - find owning interface ---- */
	struct in_addr target;

	if (inet_aton(my_ip, &target) == 0) {
	    LM_ERR("clusterer_controller: cannot parse 'my_ip' '%s'\n", my_ip);
	    freeifaddrs(ifap);
	    return -1;
	}
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
		continue;
	    if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr
	            == target.s_addr) {
		strncpy(my_interface_buf, ifa->ifa_name, IF_NAMESIZE - 1);
		my_interface_buf[IF_NAMESIZE - 1] = '\0';
		found = 1;
		break;
	    }
	}
	if (!found) {
	    LM_ERR("clusterer_controller: no local interface owns IP '%s'\n",
	           my_ip);
	    freeifaddrs(ifap);
	    return -1;
	}
	my_ip_src = "my_ip modparam (explicit)";
	LM_INFO("clusterer_controller: using IP %s on interface %s\n",
	        my_ip, my_interface_buf);

    } else if (my_interface && *my_interface) {
	/* ---- Mode 2: interface= provided - derive IP from it ---- */
	int addr_count = 0;

	strncpy(my_interface_buf, my_interface, IF_NAMESIZE - 1);
	my_interface_buf[IF_NAMESIZE - 1] = '\0';

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
		continue;
	    if (strcmp(ifa->ifa_name, my_interface) != 0)
		continue;
	    addr_count++;
	    if (addr_count == 1) {
		struct in_addr a =
		    ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
		inet_ntop(AF_INET, &a, my_ip_buf, sizeof(my_ip_buf));
		my_ip = my_ip_buf;
		found = 1;
	    }
	}
	if (!found) {
	    LM_ERR("clusterer_controller: interface '%s' not found or "
	           "has no IPv4 address\n", my_interface);
	    freeifaddrs(ifap);
	    return -1;
	}
	if (addr_count > 1)
	    LM_WARN("clusterer_controller: interface '%s' has %d IPv4 "
	            "addresses, using %s (first returned by kernel) - "
	            "use 'my_ip' modparam to override\n",
	            my_interface, addr_count, my_ip);
	else
	    LM_INFO("clusterer_controller: using IP %s on interface %s\n",
	            my_ip, my_interface_buf);
	my_ip_src = "interface modparam (IPv4 of that interface)";

    } else {
	/* ---- Mode 3: neither - auto-detect via kernel routing table ---- */
	struct sockaddr_in dest, local;
	socklen_t          local_len = sizeof(local);
	int                probe;

	memset(&dest, 0, sizeof(dest));
	dest.sin_family      = AF_INET;
	dest.sin_port        = htons((uint16_t)cl_ctr_clusters[0].multicast_port);
	dest.sin_addr.s_addr = inet_addr(cl_ctr_clusters[0].multicast_address);

	probe = socket(AF_INET, SOCK_DGRAM, 0);
	if (probe < 0) {
	    LM_ERR("clusterer_controller: auto-detect socket: %s\n",
	           strerror(errno));
	    freeifaddrs(ifap);
	    return -1;
	}
	if (connect(probe, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
	    LM_ERR("clusterer_controller: auto-detect connect: %s\n",
	           strerror(errno));
	    close(probe);
	    freeifaddrs(ifap);
	    return -1;
	}
	memset(&local, 0, sizeof(local));
	if (getsockname(probe, (struct sockaddr *)&local, &local_len) < 0) {
	    LM_ERR("clusterer_controller: auto-detect getsockname: %s\n",
	           strerror(errno));
	    close(probe);
	    freeifaddrs(ifap);
	    return -1;
	}
	close(probe);

	inet_ntop(AF_INET, &local.sin_addr, my_ip_buf, sizeof(my_ip_buf));
	my_ip = my_ip_buf;
	my_ip_src = "auto-detected via default route to the multicast group";

	/* Reverse-look up the interface name */
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
	    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
		continue;
	    if (((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr
	            == local.sin_addr.s_addr) {
		strncpy(my_interface_buf, ifa->ifa_name, IF_NAMESIZE - 1);
		my_interface_buf[IF_NAMESIZE - 1] = '\0';
		found = 1;
		break;
	    }
	}
	if (found) {
	    LM_INFO("clusterer_controller: auto-detected IP %s on "
	            "interface %s\n", my_ip, my_interface_buf);
	} else {
	    /* Fatal, where it used to warn and continue.  The interface name is
	     * the only route to the MTU, and the MTU is what admission to the
	     * cluster is decided on - a node that cannot name its own interface
	     * cannot know whether it belongs, and would previously have run on
	     * the compile-time default as if it did.  Both explicit modes
	     * (my_ip, interface) always yield a name, so this is only reachable
	     * from auto-detection, and naming either one is the fix. */
	    LM_ERR("clusterer_controller: auto-detected IP %s but no interface "
	           "owns it, so its MTU cannot be read - and the cluster admits "
	           "only nodes whose MTU matches. Set the 'interface' modparam "
	           "(or 'my_ip') so the link is unambiguous\n", my_ip);
	    freeifaddrs(ifap);
	    return -1;
	}
    }

    freeifaddrs(ifap);
    return 0;
}

/**
 * cl_ctr_discover_bin_sockets() - enumerate BIN listeners via proto_bin.
 *
 * Walks the protos[PROTO_BIN].listeners list and collects every
 * entry with proto == PROTO_BIN.  proto_bin must be loaded before this
 * module so the listeners are already registered when mod_init() runs.
 *
 * Populates my_bin_sockets[] and my_bin_count.
 * Returns 0 on success, -1 if no BIN sockets are found.
 */
static int cl_ctr_discover_bin_sockets(void)
{
    struct socket_info_full *sif;
    struct socket_info *si;
    char                buf[CL_CTR_MAX_BIN_SOCK_LEN];
    int                 len;

    /* On devel, protos[].listeners is a list of socket_info_full (next/prev),
     * each embedding the socket_info as its first member. */
    for (sif = protos[PROTO_BIN].listeners; sif; sif = sif->next) {
	si = &sif->socket_info;
	/* all entries here are PROTO_BIN by construction */
	if (si->proto != PROTO_BIN)
	    continue;
	/* Reject wildcard - clusterer needs an explicit IP to set send_sock.
	 * Use socket=bin:IP:PORT instead of socket=bin:*:PORT.             */
	if (si->address_str.len == 0
	    || (si->address_str.len == 1 && si->address_str.s[0] == '*')
	    || (si->address_str.len == 7
	        && memcmp(si->address_str.s, "0.0.0.0", 7) == 0)) {
	    LM_ERR("clusterer_controller: wildcard BIN socket "
	           "(bin:*:%u) is not allowed - use an explicit IP "
	           "(e.g. socket=bin:%s:%u)\n",
	           si->port_no, my_ip ? my_ip : "YOUR_IP", si->port_no);
	    return -1;
	}
	if (my_bin_count >= CL_CTR_MAX_BIN_SOCKETS) {
	    LM_WARN("clusterer_controller: more than %d BIN sockets, "
	            "ignoring the rest\n", CL_CTR_MAX_BIN_SOCKETS);
	    break;
	}
	len = snprintf(buf, sizeof(buf), "bin:%.*s:%u",
	               si->address_str.len, si->address_str.s,
	               si->port_no);
	if (len <= 0 || len >= CL_CTR_MAX_BIN_SOCK_LEN) {
	    LM_WARN("clusterer_controller: BIN socket name too long, "
	            "skipping\n");
	    continue;
	}
	memcpy(my_bin_sockets[my_bin_count], buf, len + 1);
	LM_INFO("clusterer_controller: found BIN socket: %s\n", buf);
	my_bin_count++;
    }

    if (my_bin_count == 0) {
	LM_ERR("clusterer_controller: no BIN sockets found - "
	       "is proto_bin loaded and socket=bin: configured?\n");
	return -1;
    }

    return 0;
}

static int mod_init(void)
{
    struct in_addr addr;
    int            i, j;
    /* the script's messaging channel and its two events; done here so the
     * reserved name is claimed before any consumer module registers */
    if (cl_ctr_script_init() < 0) {
        LM_ERR("clusterer_controller: cannot set up script messaging\n");
        return -1;
    }
    if (cl_ctr_events_init() < 0)
        return -1;


    LM_INFO("clusterer_controller: initialising\n");

    if (sodium_init() < 0) {
	LM_ERR("clusterer_controller: sodium_init() failed\n");
	return -1;
    }

    /* This process's incarnation: wall-clock start time in microseconds, so
     * every restart numbers above the one before it (see CL_CTR_INC_SZ).  A
     * clock stepped back across a restart would make the new life look older
     * than the last; the master's NODE_ASSIGN, sent when it re-admits us,
     * carries the incarnation it admitted and peers take it from there. */
    {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	cl_ctr_incarnation = (uint64_t)ts.tv_sec * 1000000ULL
	                     + (uint64_t)ts.tv_nsec / 1000ULL;
	if (cl_ctr_incarnation == 0)
	    cl_ctr_incarnation = 1;     /* 0 means "not seen yet" to peers */
    }

    /* Resolve the on_config_mismatch policy string. */
    if (on_config_mismatch_s) {
	if (strcasecmp(on_config_mismatch_s, "warn") == 0)
	    on_config_mismatch = CL_CTR_CFGMISMATCH_WARN;
	else if (strcasecmp(on_config_mismatch_s, "reject") == 0)
	    on_config_mismatch = CL_CTR_CFGMISMATCH_REJECT;
	else if (strcasecmp(on_config_mismatch_s, "adopt") == 0)
	    on_config_mismatch = CL_CTR_CFGMISMATCH_ADOPT;
	else {
	    LM_ERR("clusterer_controller: invalid on_config_mismatch '%s' "
	           "(expected warn|reject|adopt)\n", on_config_mismatch_s);
	    return -1;
	}
    }

    /* ---- Require at least one cluster ---------------------------------- */

    if (cl_ctr_cluster_str_count == 0) {
	LM_ERR("clusterer_controller: no 'cluster' modparam defined\n");
	return -1;
    }

    /* ---- Global param validation --------------------------------------- */

    if (query_time < 1) {
	LM_WARN("clusterer_controller: 'query_time' %d below min, clamping to 1s\n",
	        query_time);
	query_time = 1;
    } else if (query_time > 60) {
	LM_WARN("clusterer_controller: 'query_time' %d exceeds max, clamping to 60s\n",
	        query_time);
	query_time = 60;
    }

    /* ---- Parse and validate all cluster strings ------------------------ */

    for (i = 0; i < cl_ctr_cluster_str_count; i++) {
	cl_ctr_cluster_t *cl = &cl_ctr_clusters[i];
	if (cl_ctr_parse_cluster_str(cl_ctr_cluster_strs[i], cl) < 0)
	    return -1;
	/* Resolve the multicast destination once, in the main process, so both
	 * the forked workers (via fork) and mod_destroy's GOODBYE path (main
	 * process) can send without rebuilding it. */
	memset(&cl->mcast_dest, 0, sizeof(cl->mcast_dest));
	cl->mcast_dest.sin_family      = AF_INET;
	cl->mcast_dest.sin_port        = htons((uint16_t)cl->multicast_port);
	cl->mcast_dest.sin_addr.s_addr = inet_addr(cl->multicast_address);
	cl_ctr_cluster_count++;
	pkg_free(cl_ctr_cluster_strs[i]);
	cl_ctr_cluster_strs[i] = NULL;
    }

    /* Validate cluster_id / (multicast,port) uniqueness.  Every local controller
     * socket binds INADDR_ANY:multicast_port, so a unicast to my_ip:port is
     * demultiplexed by port alone - if two local clusters share a port (distinct
     * groups), a unicast can land on the wrong cluster's socket.  That is now
     * recovered at the receiver by the packet's cleartext cluster_id (see
     * cl_ctr_maybe_forward()), so shared ports stay fully unicast; we only note
     * it. */
    for (i = 0; i < cl_ctr_cluster_count; i++) {
	for (j = i + 1; j < cl_ctr_cluster_count; j++) {
	    if (cl_ctr_clusters[i].cluster_id == cl_ctr_clusters[j].cluster_id) {
		LM_ERR("clusterer_controller: duplicate cluster_id %d\n",
		       cl_ctr_clusters[i].cluster_id);
		return -1;
	    }
	    if (cl_ctr_clusters[i].multicast_port != cl_ctr_clusters[j].multicast_port)
		continue;
	    if (strcmp(cl_ctr_clusters[i].multicast_address,
	               cl_ctr_clusters[j].multicast_address) == 0) {
		LM_ERR("clusterer_controller: duplicate multicast %s:%d\n",
		       cl_ctr_clusters[i].multicast_address,
		       cl_ctr_clusters[i].multicast_port);
		return -1;
	    }
	    /* same port, different group: unicast is demuxed by port alone and
	     * routed to the right cluster by cluster_id at the receiver */
	    LM_INFO("clusterer_controller: clusters %d and %d share multicast "
	            "port %d - unicast is routed by cluster_id\n",
	            cl_ctr_clusters[i].cluster_id, cl_ctr_clusters[j].cluster_id,
	            cl_ctr_clusters[i].multicast_port);
	}
    }

    /* ---- Discover BIN sockets from opensips config file --------------- */
    /* Called after cl_ctr_resolve_local_identity() so my_ip is available for  */
    /* wildcard substitution (bin:*:PORT -> bin:my_ip:PORT).               */

    /* ---- Resolve local identity using first cluster for Mode 3 probe --- */

    if (cl_ctr_resolve_local_identity() < 0)
	return -1;

    /* Derive max consumer payload from the interface MTU so jumbo-frame
     * links (e.g. MTU 9000) are not capped at the 1500-byte default.
     * Overhead per consumer datagram:
     *   IP(20) + UDP(8) + wire_hdr(28) + plain_hdr(5) +
     *   consumer_hdr(3) + max_chan(31) + poly1305_tag(16) = 111 bytes. */
    {
	int _probe_mtu = cl_ctr_read_iface_mtu();
	if (_probe_mtu <= 0) {
	    /* No modparam can supply this: the MTU is detected, never
	     * configured, precisely so it cannot disagree with the kernel.
	     * Without it this node cannot know whether it may join, and a node
	     * that cannot participate must not serve SIP. */
	    LM_ERR("clusterer_controller: cannot read the MTU of %s (%s) - the "
	           "cluster admits only nodes whose MTU matches, so this node "
	           "cannot establish whether it belongs and will not start\n",
	           my_interface_buf[0] ? my_interface_buf : "(no interface)",
	           my_interface_buf[0] ? strerror(errno) : "interface unresolved");
	    return -1;
	}
	cc_mtu = cc_mtu_now = _probe_mtu;
    }
    if (my_interface_buf[0] != '\0') {
	struct ifreq _mtu_ifr;
	int _mtu_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (_mtu_sock >= 0) {
	    memset(&_mtu_ifr, 0, sizeof(_mtu_ifr));
	    memcpy(_mtu_ifr.ifr_name, my_interface_buf, strnlen(my_interface_buf, IF_NAMESIZE - 1));
	    if (ioctl(_mtu_sock, SIOCGIFMTU, &_mtu_ifr) == 0) {
		int _mtu = _mtu_ifr.ifr_mtu;
		int _overhead = 20 + 8 + CL_CTR_WIRE_HDR_SZ + CL_CTR_PLAIN_HDR_SZ
		                + CL_CTR_CONSUMER_HDR_SZ + CLCTR_MAX_CHAN_LEN + CL_CTR_TAG_SZ;
		cc_max_payload = _mtu - _overhead;
		/* Do NOT pad this back up to CLCTR_MAX_PAYLOAD when the link is
		 * smaller than that. It used to, and the effect was that any
		 * interface under ~1435 MTU - a VPN, a GRE/IPIP tunnel, PPPoE,
		 * the usual 1400/1420/1436 - reported a bound ABOVE what the
		 * path carries, which is the exact inverse of why the MTU is
		 * consulted at all. Every full-size consumer datagram then IP
		 * fragments, and a fragmented datagram is lost entirely if any
		 * one fragment is, so the padding manufactured precisely the
		 * losses the retransmit machinery then has to repair.
		 *
		 * Honour the link and say so instead: the compile-time constant
		 * stays what a consumer sizes a buffer with, but it stops being
		 * a promise the network cannot keep. */
		if (cc_max_payload < CLCTR_MAX_PAYLOAD)
		    LM_WARN("clusterer_controller: interface %s has MTU %d, so a "
		            "consumer datagram carries at most %d bytes - below "
		            "the %d that CLCTR_MAX_PAYLOAD leads consumers to "
		            "expect. Sends above %d will be refused on this "
		            "link. Raise the MTU, or keep consumer payloads "
		            "under it; the bound is deliberately NOT padded up "
		            "to the constant, because that only fragments and a "
		            "lost fragment loses the whole message.\n",
		            my_interface_buf, _mtu, cc_max_payload,
		            (int)CLCTR_MAX_PAYLOAD, cc_max_payload);
		/* However large the MTU claims to be, one datagram still has
		 * to fit a UDP payload. Loopback reports 65536, which lands a
		 * byte past what sendto() accepts. */
		if (cc_max_payload > CL_CTR_UDP_PAYLOAD_MAX - CL_CTR_PKT_OVERHEAD)
		    cc_max_payload = CL_CTR_UDP_PAYLOAD_MAX - CL_CTR_PKT_OVERHEAD;
		if (cc_max_payload <= 0) {
		    LM_ERR("clusterer_controller: interface %s has MTU %d, which "
		           "cannot carry even the %d bytes of per-datagram "
		           "overhead - the cluster plane cannot run on it\n",
		           my_interface_buf, _mtu, _overhead);
		    return -1;
		}
		LM_INFO("clusterer_controller: interface %s MTU=%d, "
		        "max consumer payload=%d bytes - every cluster member "
		        "must run at this MTU; one that does not is refused at "
		        "join\n",
		        my_interface_buf, _mtu, cc_max_payload);
	    } else {
		LM_WARN("clusterer_controller: SIOCGIFMTU on %s failed: %s - "
		        "using default max payload %d\n",
		        my_interface_buf, strerror(errno), cc_max_payload);
	    }
	    close(_mtu_sock);
	}
    }

    /* Size the transmit buffers from the bound that gates them, now that the
     * MTU probe above has settled cc_max_payload. Doing it here rather than at
     * compile time is the whole point: a jumbo-frame link raises
     * cc_max_payload, and a CLCTR_MAX_PAYLOAD-sized buffer could not hold what
     * that bound then admits. */
    cl_ctr_script_buf_sz  = cc_max_payload;
    cl_ctr_consumer_pkt_sz = CL_CTR_PKT_OVERHEAD + cc_max_payload;
    /* The retransmit cache follows the same bound, for the same reason: a
     * reliable send that the transmit buffer accepts must also be one the
     * repair path can hold, or reliability quietly stops at a size the API
     * never mentions.  Whichever is larger - the control plane's biggest
     * handshake packet, or a full-MTU consumer message. */
    cl_ctr_retx_pkt_max = cl_ctr_consumer_pkt_sz > CL_CTR_NODE_ASSIGN_MAX_SZ
                          ? cl_ctr_consumer_pkt_sz : CL_CTR_NODE_ASSIGN_MAX_SZ;
    cl_ctr_script_buf  = pkg_malloc(cl_ctr_script_buf_sz);
    cl_ctr_consumer_pkt = pkg_malloc(cl_ctr_consumer_pkt_sz);
    if (!cl_ctr_script_buf || !cl_ctr_consumer_pkt) {
	LM_ERR("clusterer_controller: no pkg memory for the %d/%d byte "
	       "transmit buffers\n", cl_ctr_script_buf_sz,
	       cl_ctr_consumer_pkt_sz);
	return -1;
    }

    if (cl_ctr_discover_bin_sockets() < 0)
	return -1;

    if (strlen(my_ip) > CL_CTR_MAX_IP_LEN) {
	LM_ERR("clusterer_controller: resolved my_ip too long\n");
	return -1;
    }
    if (inet_aton(my_ip, &addr) == 0) {
	LM_ERR("clusterer_controller: cannot parse resolved my_ip '%s'\n", my_ip);
	return -1;
    }

    /* ---- Multi-cluster: each cluster must name its BIN socket ---------- */

    if (cl_ctr_cluster_count > 1) {
	for (i = 0; i < cl_ctr_cluster_count; i++) {
	    if (cl_ctr_clusters[i].bin_socket[0] == '\0') {
		LM_ERR("clusterer_controller: cluster %d has no bin_socket= "
		       "defined - required when multiple clusters are configured "
		       "(e.g. id=%d,multicast=...,bin_socket=bin:IP:PORT)\n",
		       cl_ctr_clusters[i].cluster_id, cl_ctr_clusters[i].cluster_id);
		return -1;
	    }
	}
    }

    /* ---- Per-cluster: resolve BIN socket, derive key, allocate peers --- */

    for (i = 0; i < cl_ctr_cluster_count; i++) {
	cl_ctr_cluster_t *cl = &cl_ctr_clusters[i];

	/* Resolve sentinels to the global default when the cluster string did
	 * not set them explicitly.  Done here (unconditionally, before workers
	 * fork and before any MI query) so every cl->* setting always holds a
	 * concrete 0/1 value regardless of whether clusterer is loaded - a mix
	 * of global and per-cluster overrides always reports correctly.        */
	if (cl->master_stickiness == -1)
	    cl->master_stickiness = master_stickiness ? 1 : 0;
	if (cl->manage_shtags == -1)
	    cl->manage_shtags = manage_shtags ? 1 : 0;
	if (cl->consumer_retries == -1)
	    cl->consumer_retries = consumer_retries;
	if (cl->consumer_retry_ms == -1)
	    cl->consumer_retry_ms = consumer_retry_ms;
	if (cl->consumer_rate == -1)
	    cl->consumer_rate = consumer_rate_limit;

	/* The replay window is a fixed number of MESSAGES, but what it has to
	 * span is a fixed amount of TIME - the retransmit horizon, which is
	 * configurable and can legally be set as high as 10 x 5000 ms.  Report
	 * the resulting per-peer rate ceiling rather than leaving an operator
	 * to meet it as unexplained loss.  Above the ceiling, a repair copy can
	 * arrive after its slot has been reused and is refused (and, on the
	 * reliable path, deliberately not acknowledged). */
	{
	    int horizon_ms = cl->consumer_retries * cl->consumer_retry_ms;
	    int ceiling = horizon_ms > 0
	                  ? (CL_CTR_REPLAY_WIN_BITS * 1000) / horizon_ms : 0;

	    if (horizon_ms > 0 && ceiling < 1000)
		LM_WARN("clusterer_controller: [cluster %d] consumer retransmit "
		        "horizon is %d ms (%d retries x %d ms), so the %d-slot "
		        "replay window only spans ~%d consumer messages/s from "
		        "any one peer; above that, retransmits arrive too late "
		        "to be judged and are dropped\n", cl->cluster_id,
		        horizon_ms, cl->consumer_retries, cl->consumer_retry_ms,
		        CL_CTR_REPLAY_WIN_BITS, ceiling);
	    else
		LM_DBG("clusterer_controller: [cluster %d] replay window spans "
		       "%d messages, ~%d msg/s per peer at a %d ms retransmit "
		       "horizon\n", cl->cluster_id, CL_CTR_REPLAY_WIN_BITS,
		       ceiling, horizon_ms);
	}

	/* Resolve which BIN socket to use for this cluster.
	 * Priority: explicit bin_socket= in cluster string >
	 *           sole discovered socket >
	 *           first discovered socket (warn if multiple) */
	if (cl->bin_socket[0] != '\0') {
	    /* Explicit override - validate it was actually discovered */
	    int found_bs = 0, bi;
	    for (bi = 0; bi < my_bin_count; bi++) {
		if (strcmp(my_bin_sockets[bi], cl->bin_socket) == 0) {
		    found_bs = 1;
		    break;
		}
	    }
	    if (!found_bs) {
	    	char _disc[CL_CTR_MAX_BIN_SOCKETS * (CL_CTR_MAX_BIN_SOCK_LEN + 2)];
	    	int  _o = 0, _b;
	    	_disc[0] = '\0';
	    	for (_b = 0; _b < my_bin_count; _b++)
	    		_o += snprintf(_disc + _o, sizeof(_disc) - _o, "%s%s",
	    		               _b ? ", " : "", my_bin_sockets[_b]);
	    	LM_ERR("clusterer_controller: cluster %d bin_socket='%s' does not "
	    	       "match any configured BIN listener (discovered: %s) - peers "
	    	       "cannot connect and clusterer replication would silently "
	    	       "fail; fix bin_socket= or the socket=bin: line\n",
	    	       cl->cluster_id, cl->bin_socket, _disc);
	    	return -1;
	    }
	} else if (my_bin_count == 1) {
	    /* Only one socket - unambiguous */
	    {
		size_t _l = strnlen(my_bin_sockets[0], CL_CTR_MAX_BIN_SOCK_LEN - 1);
		memcpy(cl->bin_socket, my_bin_sockets[0], _l);
		cl->bin_socket[_l] = '\0';
	    }
	} else {
	    /* Multiple sockets, no explicit override - use first, warn */
	    {
		size_t _l = strnlen(my_bin_sockets[0], CL_CTR_MAX_BIN_SOCK_LEN - 1);
		memcpy(cl->bin_socket, my_bin_sockets[0], _l);
		cl->bin_socket[_l] = '\0';
	    }
	    LM_WARN("clusterer_controller: cluster %d has no bin_socket= override "
	            "and multiple BIN sockets exist - using %s; add bin_socket= "
	            "to the cluster string to be explicit\n",
	            cl->cluster_id, cl->bin_socket);
	}
	LM_INFO("clusterer_controller: cluster %d: bin_socket=%s\n",
	        cl->cluster_id, cl->bin_socket);

	if (cl_ctr_derive_key(cl) < 0)
	    return -1;

	cl->peers = shm_malloc(sizeof(cl_ctr_peers_t));
	if (!cl->peers) {
	    LM_ERR("clusterer_controller: no shm memory for cluster %d peer table\n",
	           cl->cluster_id);
	    return -1;
	}
	memset(cl->peers, 0, sizeof(cl_ctr_peers_t));
	cl->peers->node_state = CL_CTR_NODE_NEW;
	cl->peers->worker_proc_no = -1;   /* published by cl_ctr_worker after fork */
	cl->peers->eff_manage_shtags     = cl->manage_shtags;
	cl->peers->eff_master_stickiness = cl->master_stickiness;
	cl->peers->eff_query_time        = query_time;
	if (cl->cid_pinned) {
	    char sp[37];
	    memcpy(cl->peers->cid, cl->cid_pin, CL_CTR_CID_SZ);
	    cl->peers->cid_state = CL_CTR_CID_PINNED;
	    cl->peers->cid_since = cl_ctr_now();
	    cl_ctr_cid_str(cl->cid_pin, sp);
	    LM_INFO("clusterer_controller: [cluster %d] cluster uuid pinned to %s\n",
	            cl->cluster_id, sp);
	}

	cl->peers->lock = lock_init_rw();
	if (!cl->peers->lock) {
	    LM_ERR("clusterer_controller: lock_init_rw() failed for cluster %d\n",
	           cl->cluster_id);
	    shm_free(cl->peers);
	    cl->peers = NULL;
	    return -1;
	}
	if (cl_ctr_stats_register(cl) < 0)
	    return -1;

	LM_INFO("clusterer_controller: cluster %d: multicast=%s:%d bin=%s\n",
	        cl->cluster_id, cl->multicast_address, cl->multicast_port,
	        cl->bin_socket);
    }

    LM_INFO("clusterer_controller: my_ip=%s interface=%s query_time=%ds "
            "clusters=%d bin_sockets=%d crypto=%s\n",
            my_ip, my_interface_buf[0] ? my_interface_buf : "(unknown)",
            query_time, cl_ctr_cluster_count, my_bin_count, CL_CTR_CRYPTO_SUITE);

    /* Set worker process count dynamically - one per cluster */
    procs[0].no = cl_ctr_cluster_count;

    /* Load clusterer controller API if clusterer.so is present and
     * use_controller=1 is set.  Soft dependency - controller works
     * standalone even without clusterer loaded.                     */
    {
	load_clusterer_ctrl_binds_f load_fn;
	/* the public clusterer API too - its set_state() serves the 'full'
	 * maintenance level */
	if (find_export("load_clusterer", 0) && load_clusterer_api(&cl_api) == 0)
	    cl_api_loaded = 1;
	load_fn = (load_clusterer_ctrl_binds_f)
	          find_export("load_clusterer_ctrl_binds", 0);
	if (load_fn && load_fn(&clctl) == 0) {
	    clctl_loaded = 1;
	    LM_INFO("clusterer_controller: clusterer API loaded - "
	            "topology will be driven dynamically\n");

	    /* The clusterer marks a cluster controller-managed with
	     * cluster_options use_controller=1; that pre-creates its stub, sets the
	     * controller_managed flag (so it never touches the DB), and arms the
	     * guard against hijacking a native cluster of the same id.  The set of
	     * clusterer-managed ids and the set of 'cluster' configs here must match
	     * exactly - either direction of mismatch is a hard error, since neither
	     * half is usable without the other (a managed id with no controller
	     * config has no bin socket or crypto params; a controller config for an
	     * unmanaged id has nothing legitimate to drive).  Abort naming the id. */

	    /* (a) clusterer marks a cluster managed that we have no config for */
	    {
		int m, k, found;
		for (m = 0; m < clctl.managed_count; m++) {
		    found = 0;
		    for (k = 0; k < cl_ctr_cluster_count; k++)
			if (cl_ctr_clusters[k].cluster_id == clctl.managed_ids[m]) {
			    found = 1;
			    break;
			}
		    if (!found) {
			LM_ERR("clusterer_controller: the clusterer marks cluster %d "
			       "controller-managed (cluster_options use_controller=1) "
			       "but this module has no configuration for it - add "
			       "modparam(\"clusterer_controller\", \"cluster\", "
			       "\"id=%d, ...\"), or drop use_controller for that "
			       "cluster.\n",
			       clctl.managed_ids[m], clctl.managed_ids[m]);
			return -1;
		    }
		}
	    }

	    /* (b) we have a config for a cluster the clusterer did not mark managed */
	    {
		int k, m, managed;
		for (k = 0; k < cl_ctr_cluster_count; k++) {
		    managed = 0;
		    for (m = 0; m < clctl.managed_count; m++)
			if (clctl.managed_ids[m] == cl_ctr_clusters[k].cluster_id) {
			    managed = 1;
			    break;
			}
		    if (!managed) {
			LM_ERR("clusterer_controller: cluster %d is configured here "
			       "but the clusterer did not mark it controller-managed "
			       "- add modparam(\"clusterer\", \"cluster_options\", "
			       "\"cluster_id=%d, use_controller=1\"), or remove this "
			       "module's 'cluster' config for it.\n",
			       cl_ctr_clusters[k].cluster_id, cl_ctr_clusters[k].cluster_id);
			return -1;
		    }
		}
	    }

	    /* When we manage sharing tags, start every tag as BACKUP and
	     * lock out MI/script changes - the controller master decides
	     * who becomes active.  (manage_shtags sentinels were already
	     * resolved to concrete 0/1 in the unconditional loop above.)  */
	    {
		int _ci;
		for (_ci = 0; _ci < cl_ctr_cluster_count; _ci++) {
		    if (!cl_ctr_clusters[_ci].manage_shtags)
			continue;
		    if (clctl.force_backup_shtags)
			clctl.force_backup_shtags(cl_ctr_clusters[_ci].cluster_id);
		    if (clctl.set_shtag_managed)
			clctl.set_shtag_managed(cl_ctr_clusters[_ci].cluster_id);
		}
	    }

	} else {
	    LM_DBG("clusterer_controller: clusterer not loaded or "
	           "use_controller not set - running standalone\n");
	}
    }

    return 0;
}

static int cl_ctr_child_init(int rank)
{
	/* Re-seed the CSPRNG after fork - each worker must have independent state. */
	randombytes_stir();

	/* Sync current_id from shared memory in every child process.
	 * The global current_id diverges after fork - each process needs
	 * to re-read the correct value from cluster->current_node.      */
	if (clctl_loaded && clctl.sync_current_id)
		clctl.sync_current_id();
	return 0;
}

static void mod_destroy(void)
{
    int            i, sock;
    unsigned char  ttl = 32;
    cl_ctr_cluster_t  *cl;

    if (!my_ip)
	goto cleanup;

    /* Send GOODBYE on each cluster's multicast group so peers re-elect */
    for (i = 0; i < cl_ctr_cluster_count; i++) {
	cl = &cl_ctr_clusters[i];
	if (!cl->peers)
	    continue;
	if (cl->peers->count <= 1) {
	    LM_INFO("clusterer_controller: [cluster %d] sole node, "
	            "skipping GOODBYE\n", cl->cluster_id);
	    continue;
	}
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
	    LM_ERR("clusterer_controller: [cluster %d] goodbye socket(): %s\n",
	           cl->cluster_id, strerror(errno));
	    continue;
	}
	setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
	/* Derive session_key locally from master_salt in shm so we can encrypt
	 * GOODBYE - the worker's cl->session_key is in a different process. */
	{
	    size_t plen = strlen(cl->password);
	    cl_ctr_hkdf_sha256((unsigned char *)cl->password, plen,
	                   cl->peers->master_salt, CL_CTR_MASTER_SALT_SZ,
	                   "cl_ctr_session", cl->session_key);
	}
	cl_ctr_send_pkt_with_ip(sock, CL_CTR_PKT_GOODBYE, cl, NULL, 0);
	close(sock);
	LM_INFO("clusterer_controller: [cluster %d] GOODBYE sent\n",
	        cl->cluster_id);
    }

cleanup:
    for (i = 0; i < cl_ctr_cluster_count; i++) {
	cl = &cl_ctr_clusters[i];
	if (!cl->peers)
	    continue;
	if (cl->peers->lock) {
	    lock_destroy_rw(cl->peers->lock);
	    cl->peers->lock = NULL;
	}
	shm_free(cl->peers);
	cl->peers = NULL;
    }
    LM_INFO("clusterer_controller: shut down\n");
}
