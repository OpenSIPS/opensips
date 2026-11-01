/*
 * clusterer_controller - this node's identity, and the node id it proposes
 *
 * Copyright (C) 2026 Yury Kirsanov
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

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cl_ctr.h"
#include "cl_ctr_identity.h"

unsigned char cl_ctr_identity[CL_CTR_IDENTITY_SZ];
const char   *cl_ctr_identity_src = "none";
uint16_t      cl_ctr_proposal;

/* first line of @path into @buf, trailing whitespace cut; its length or -1 */
static int read_line(const char *path, char *buf, int size)
{
	FILE *f = fopen(path, "r");
	int   n;

	if (!f)
		return -1;
	if (!fgets(buf, size, f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	n = strlen(buf);
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == ' ' || buf[n - 1] == '\t'))
		buf[--n] = '\0';
	return n;
}

/* a container shares the host's SMBIOS UUID with every other container */
static int in_container(void)
{
	char buf[4096];
	FILE *f;
	size_t n;

	if (access("/.dockerenv", F_OK) == 0 || access("/run/.containerenv", F_OK) == 0)
		return 1;
	if ((f = fopen("/proc/1/cgroup", "r"))) {
		n = fread(buf, 1, sizeof buf - 1, f);
		fclose(f);
		buf[n] = '\0';
		if (strstr(buf, "docker") || strstr(buf, "lxc") || strstr(buf, "kubepods") ||
		        strstr(buf, "containerd") || strstr(buf, "libpod"))
			return 1;
	}
	return 0;
}

/* the SMBIOS product UUID, unless it is a placeholder ("Not Settable", zeros) */
static int machine_smbios(char *buf, int size)
{
	int n, i, digits = 0;

	if (in_container() || (n = read_line("/sys/class/dmi/id/product_uuid", buf, size)) < 32)
		return -1;
	for (i = 0; i < n; i++)
		if ((buf[i] >= '1' && buf[i] <= '9') || (buf[i] >= 'a' && buf[i] <= 'e') ||
		        (buf[i] >= 'A' && buf[i] <= 'E'))
			digits++;
	return digits >= 8 ? n : -1;
}

/* the first non-zero MAC, of a physical interface if there is one */
static int machine_mac(char *buf, int size)
{
	struct dirent **ifs;
	char path[512];
	int  n, i, pass, len = -1;

	if ((n = scandir("/sys/class/net", &ifs, NULL, alphasort)) < 0)
		return -1;
	for (pass = 0; pass < 2 && len < 0; pass++)
		for (i = 0; i < n && len < 0; i++) {
			if (ifs[i]->d_name[0] == '.' || !strcmp(ifs[i]->d_name, "lo"))
				continue;
			snprintf(path, sizeof path, "/sys/class/net/%s/device", ifs[i]->d_name);
			if (pass == 0 && access(path, F_OK) != 0)
				continue;
			snprintf(path, sizeof path, "/sys/class/net/%s/address", ifs[i]->d_name);
			len = read_line(path, buf, size);
			if (len < 17 || !strcmp(buf, "00:00:00:00:00:00"))
				len = -1;
		}
	for (i = 0; i < n; i++)
		free(ifs[i]);
	free(ifs);
	return len;
}

uint16_t cl_ctr_identity_proposal(const unsigned char *id, int range)
{
	uint32_t h = 2166136261u;
	int i;

	for (i = 0; i < CL_CTR_IDENTITY_SZ; i++) {
		h ^= id[i];
		h *= 16777619u;
	}
	return (uint16_t)(1 + h % (uint32_t)range);
}

void cl_ctr_identity_init(int configured)
{
	char machine[256], msg[512];
	int  len;

	if ((len = machine_smbios(machine, sizeof machine)) > 0) {
		cl_ctr_identity_src = "smbios";
	} else if ((len = machine_mac(machine, sizeof machine)) > 0) {
		cl_ctr_identity_src = "mac";
	} else {
		unsigned char rnd[16];
		randombytes_buf(rnd, sizeof rnd);
		len = sodium_bin2hex(machine, sizeof machine, rnd, sizeof rnd) ? 32 : 0;
		cl_ctr_identity_src = "random";
	}
	len = snprintf(msg, sizeof msg, "%.*s/%s", len, machine, my_ip);
	crypto_generichash(cl_ctr_identity, CL_CTR_IDENTITY_SZ,
		(const unsigned char *)msg, len, NULL, 0);

	if (configured >= 1 && configured <= CL_CTR_MAX_PEERS)
		cl_ctr_proposal = (uint16_t)configured;
	else
		cl_ctr_proposal = cl_ctr_identity_proposal(cl_ctr_identity, CL_CTR_MAX_PEERS);
	if (configured > CL_CTR_MAX_PEERS)
		LM_NOTICE("clusterer_controller: my_node_id %d is beyond the %d node ids "
			"of a controller cluster - not proposed there\n", configured,
			CL_CTR_MAX_PEERS);

	LM_INFO("clusterer_controller: identity from %s; proposes node_id %u%s\n",
		cl_ctr_identity_src, cl_ctr_proposal,
		configured >= 1 && configured <= CL_CTR_MAX_PEERS ? " (my_node_id)" : "");
	if (!strcmp(cl_ctr_identity_src, "random"))
		LM_NOTICE("clusterer_controller: no SMBIOS UUID or MAC to identify this "
			"machine - the proposed node_id changes on every start; set "
			"my_node_id to keep one\n");
}
