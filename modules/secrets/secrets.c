/*
 * Secret provider integration for OpenSIPS
 *
 * Copyright (C) 2026 OpenSIPS Project
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <curl/curl.h>

#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../locking.h"
#include "../../pvar.h"
#include "../../statistics.h"
#include "../../mi/mi.h"
#include "../../lib/cJSON.h"
#include "../../ut.h"

#define ENV_PREFIX "env://"
#define FILE_PREFIX "file://"
#define VAULT_PREFIX "vault://"
#define VAULT_HTTP_PREFIX "vault+http://"
#define VAULT_HTTPS_PREFIX "vault+https://"
#define K8S_PREFIX "k8s://"
#define SECRET_HTTP_BODY_MAX (2 * 1024 * 1024)

struct secret_def {
	str name;
	str spec;
	struct secret_def *next;
};

struct secret_entry {
	str name;
	str spec;
	str value;
	struct secret_entry *next;
};

struct pending_secret {
	struct secret_entry *entry;
	char *value;
	int len;
	struct pending_secret *next;
};

struct http_buffer {
	char *s;
	size_t len;
	size_t size;
};

static struct secret_def *secret_defs;
static struct secret_entry *secret_entries;
static gen_lock_t *secret_lock;

static int allow_missing;
static int vault_timeout = 5;
static int allow_insecure_vault_http = 0;
static char *vault_scheme = "https";
static char *vault_token_env = "VAULT_TOKEN";
static char *vault_namespace_env = "VAULT_NAMESPACE";

static int k8s_timeout = 5;
static char *k8s_api = NULL;
static char *k8s_token_file = "/var/run/secrets/kubernetes.io/serviceaccount/token";
static char *k8s_ca_file = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
static char *k8s_namespace_file = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

static stat_var *reload_failures;

/*
 * $secret() values are copied out of shm into per-process pkg buffers.
 * A small ring is used so that several $secret() values evaluated within the
 * same expression (e.g. a comparison) do not overwrite or free each other.
 */
#define SECRET_PV_BUFS 4
static char *pv_value_buf[SECRET_PV_BUFS];
static int pv_value_buf_len[SECRET_PV_BUFS];
static int pv_value_buf_idx;

static void secret_bzero(void *ptr, size_t len)
{
	volatile unsigned char *p = (volatile unsigned char *)ptr;
	while (p && len--)
		*p++ = 0;
}

static void secret_shm_free(char *ptr, int len)
{
	if (!ptr)
		return;
	if (len > 0)
		secret_bzero(ptr, len);
	shm_free(ptr);
}

static void secret_pkg_free(char *ptr, int len)
{
	if (!ptr)
		return;
	if (len > 0)
		secret_bzero(ptr, len);
	pkg_free(ptr);
}

static void secret_wipe_json(cJSON *node)
{
	cJSON *it;

	if (!node)
		return;
	if (node->valuestring)
		secret_bzero(node->valuestring, strlen(node->valuestring));
	for (it = node->child; it; it = it->next)
		secret_wipe_json(it);
}

static int mod_init(void);
static void mod_destroy(void);
static int secret_param(modparam_t type, void *val);
static int w_secret_exists(struct sip_msg *msg, str *name);
static int pv_parse_secret_name(pv_spec_t *sp, const str *in);
static int pv_get_secret(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static mi_response_t *mi_reload(const mi_params_t *params,
		struct mi_handler *async_hdl);
static mi_response_t *mi_reload_one(const mi_params_t *params,
		struct mi_handler *async_hdl);
static mi_response_t *mi_list(const mi_params_t *params,
		struct mi_handler *async_hdl);

static const cmd_export_t cmds[] = {
	{"secret_exists", (cmd_function)w_secret_exists, {
		{CMD_PARAM_STR, 0, 0}, {0, 0, 0}}, ALL_ROUTES},
	{0, 0, {{0, 0, 0}}, 0}
};

static const param_export_t params[] = {
	{"secret", STR_PARAM|USE_FUNC_PARAM, (void *)secret_param},
	{"allow_missing", INT_PARAM, &allow_missing},
	{"vault_timeout", INT_PARAM, &vault_timeout},
	{"allow_insecure_vault_http", INT_PARAM, &allow_insecure_vault_http},
	{"vault_scheme", STR_PARAM, &vault_scheme},
	{"vault_token_env", STR_PARAM, &vault_token_env},
	{"vault_namespace_env", STR_PARAM, &vault_namespace_env},
	{"k8s_timeout", INT_PARAM, &k8s_timeout},
	{"k8s_api", STR_PARAM, &k8s_api},
	{"k8s_token_file", STR_PARAM, &k8s_token_file},
	{"k8s_ca_file", STR_PARAM, &k8s_ca_file},
	{"k8s_namespace_file", STR_PARAM, &k8s_namespace_file},
	{0, 0, 0}
};

static unsigned long loaded_secret_count(void *unused)
{
	unsigned long n = 0;
	struct secret_entry *it;

	if (!secret_lock)
		return 0;
	lock_get(secret_lock);
	for (it = secret_entries; it; it = it->next)
		if (it->value.s)
			n++;
	lock_release(secret_lock);
	return n;
}

static const stat_export_t mod_stats[] = {
	{"loaded", STAT_IS_FUNC, (stat_var **)loaded_secret_count},
	{"reload_failures", 0, &reload_failures},
	{0, 0, 0}
};

static const mi_export_t mi_cmds[] = {
	{"reload", 0, 0, 0, {
		{mi_reload, {0}},
		{EMPTY_MI_RECIPE}}, {0}},
	{"reload_one", 0, 0, 0, {
		{mi_reload_one, {"name", 0}},
		{EMPTY_MI_RECIPE}}, {0}},
	{"list", 0, 0, 0, {
		{mi_list, {0}},
		{EMPTY_MI_RECIPE}}, {0}},
	{EMPTY_MI_EXPORT}
};

static const pv_export_t mod_pvs[] = {
	{str_const_init("secret"), 1200, pv_get_secret, 0,
		pv_parse_secret_name, 0, 0, 0},
	{{0, 0}, 0, 0, 0, 0, 0, 0, 0}
};

struct module_exports exports = {
	"secrets",
	MOD_TYPE_DEFAULT,
	MODULE_VERSION,
	DEFAULT_DLFLAGS,
	NULL,
	NULL,
	cmds,
	NULL,
	params,
	mod_stats,
	mi_cmds,
	mod_pvs,
	NULL,
	NULL,
	NULL,
	mod_init,
	0,
	mod_destroy,
	0,
	0
};

static int str_dup_pkg(str *dst, const char *src, int len)
{
	dst->s = pkg_malloc(len + 1);
	if (!dst->s)
		return -1;
	memcpy(dst->s, src, len);
	dst->s[len] = '\0';
	dst->len = len;
	return 0;
}

static int str_dup_shm(str *dst, const char *src, int len)
{
	dst->s = shm_malloc(len + 1);
	if (!dst->s)
		return -1;
	memcpy(dst->s, src, len);
	dst->s[len] = '\0';
	dst->len = len;
	return 0;
}

static int secret_param(modparam_t type, void *val)
{
	char *raw, *eq;
	struct secret_def *d;
	int name_len, spec_len;

	if (!val)
		return -1;
	raw = (char *)val;
	eq = strchr(raw, '=');
	if (!eq || eq == raw || !eq[1]) {
		LM_ERR("invalid secret definition; expected name=provider://source\n");
		return -1;
	}

	name_len = eq - raw;
	spec_len = strlen(eq + 1);
	for (d = secret_defs; d; d = d->next) {
		if (d->name.len == name_len &&
			memcmp(d->name.s, raw, name_len) == 0) {
			LM_ERR("duplicate secret name '%.*s'\n", name_len, raw);
			return -1;
		}
	}
	d = pkg_malloc(sizeof(*d));
	if (!d)
		return -1;
	memset(d, 0, sizeof(*d));
	if (str_dup_pkg(&d->name, raw, name_len) < 0 ||
		str_dup_pkg(&d->spec, eq + 1, spec_len) < 0) {
		if (d->name.s)
			pkg_free(d->name.s);
		if (d->spec.s)
			pkg_free(d->spec.s);
		pkg_free(d);
		return -1;
	}

	d->next = secret_defs;
	secret_defs = d;
	return 0;
}

static size_t vault_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct http_buffer *b = userdata;
	size_t n = size * nmemb;
	char *p;

	if (n > SECRET_HTTP_BODY_MAX ||
		b->len > SECRET_HTTP_BODY_MAX - n) {
		LM_ERR("secret provider HTTP response exceeds 2 MiB limit\n");
		return 0;
	}

	if (b->len + n + 1 > b->size) {
		/* grow by hand: pkg_realloc() could leave an unwiped copy behind */
		size_t cap = b->size ? b->size : 4096;

		while (cap < b->len + n + 1)
			cap *= 2;
		p = pkg_malloc(cap);
		if (!p)
			return 0;
		if (b->s) {
			memcpy(p, b->s, b->len);
			secret_pkg_free(b->s, b->size);
		}
		b->s = p;
		b->size = cap;
	}
	memcpy(b->s + b->len, ptr, n);
	b->len += n;
	b->s[b->len] = '\0';
	return n;
}

/* restrict a request (and any redirect) to a single URL scheme */
static void secret_curl_set_protocol(CURL *curl, int https)
{
#if LIBCURL_VERSION_NUM >= 0x075500
	const char *proto = https ? "https" : "http";

	curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, proto);
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, proto);
#else
	long proto = https ? CURLPROTO_HTTPS : CURLPROTO_HTTP;

	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, proto);
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, proto);
#endif
}

/*
 * The bundled cJSON parser is recursive and has no nesting limit, so a
 * malicious or broken endpoint could crash the process with a deeply nested
 * document. Reject anything nested deeper than SECRET_JSON_MAX_DEPTH first.
 */
#define SECRET_JSON_MAX_DEPTH 32

static int secret_json_depth_ok(const char *s)
{
	int depth = 0, in_str = 0;

	for (; *s; s++) {
		if (in_str) {
			if (*s == '\\' && s[1])
				s++;
			else if (*s == '"')
				in_str = 0;
			continue;
		}
		if (*s == '"') {
			in_str = 1;
		} else if (*s == '{' || *s == '[') {
			if (++depth > SECRET_JSON_MAX_DEPTH)
				return 0;
		} else if (*s == '}' || *s == ']') {
			depth--;
		}
	}
	return 1;
}

static cJSON *secret_json_parse(const char *body)
{
	if (!body || !secret_json_depth_ok(body))
		return NULL;
	return cJSON_Parse(body);
}

static cJSON *json_object_get_exact(cJSON *obj, const char *key)
{
	cJSON *it;

	if (!obj || !key)
		return NULL;
	for (it = obj->child; it; it = it->next)
		if (it->string && strcmp(it->string, key) == 0)
			return it;
	return NULL;
}

static cJSON *json_path(cJSON *obj, const char *path)
{
	char *tmp, *tok, *save = NULL;
	cJSON *cur = obj;

	tmp = pkg_malloc(strlen(path) + 1);
	if (!tmp)
		return NULL;
	strcpy(tmp, path);
	for (tok = strtok_r(tmp, ".", &save); tok && cur;
		tok = strtok_r(NULL, ".", &save))
		cur = json_object_get_exact(cur, tok);
	pkg_free(tmp);
	return cur;
}

static int load_env_secret(const str *spec, str *out)
{
	char *name, *v;
	int len = spec->len - (int)strlen(ENV_PREFIX);

	name = pkg_malloc(len + 1);
	if (!name)
		return -1;
	memcpy(name, spec->s + strlen(ENV_PREFIX), len);
	name[len] = '\0';
	v = getenv(name);
	pkg_free(name);
	if (!v)
		return -1;
	return str_dup_pkg(out, v, strlen(v));
}

/*
 * Read a small secret-bearing file into pkg memory. Unbuffered I/O is used so
 * that no unwiped stdio copy of the content is left behind, and only regular
 * files are accepted (symlinks to regular files, as used by Kubernetes and
 * Docker secret mounts, are followed). Trailing CR/LF characters are removed.
 */
static int read_secret_file(const char *path, str *out, int limit)
{
	struct stat st;
	ssize_t n;
	size_t done = 0;
	int fd;

	memset(out, 0, sizeof(*out));
	if (!path || !*path)
		return -1;

	/* O_NONBLOCK: opening a FIFO must not hang the process; it is
	 * rejected by the S_ISREG() check below and has no effect on
	 * reads from regular files */
	fd = open(path, O_RDONLY | O_NOCTTY | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		LM_ERR("cannot open '%s': %s\n", path, strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) < 0) {
		LM_ERR("cannot stat '%s': %s\n", path, strerror(errno));
		goto error;
	}
	if (!S_ISREG(st.st_mode)) {
		LM_ERR("'%s' is not a regular file\n", path);
		goto error;
	}
	if (st.st_size > limit) {
		LM_ERR("'%s' exceeds the %d byte safety limit\n", path, limit);
		goto error;
	}

	out->s = pkg_malloc(st.st_size + 1);
	if (!out->s) {
		LM_ERR("no more pkg memory\n");
		goto error;
	}
	while (done < (size_t)st.st_size) {
		n = read(fd, out->s + done, st.st_size - done);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		done += n;
	}
	if (done != (size_t)st.st_size) {
		LM_ERR("'%s' changed or could not be read completely\n", path);
		secret_pkg_free(out->s, st.st_size + 1);
		memset(out, 0, sizeof(*out));
		goto error;
	}
	close(fd);

	out->len = done;
	while (out->len > 0 &&
			(out->s[out->len - 1] == '\n' || out->s[out->len - 1] == '\r'))
		out->len--;
	out->s[out->len] = '\0';
	return 0;

error:
	close(fd);
	return -1;
}

static int load_file_secret(const str *spec, str *out)
{
	char *path;
	int prefix = strlen(FILE_PREFIX);
	int rc;

	path = pkg_malloc(spec->len - prefix + 1);
	if (!path)
		return -1;
	memcpy(path, spec->s + prefix, spec->len - prefix);
	path[spec->len - prefix] = '\0';

	rc = read_secret_file(path, out, 1024 * 1024);
	pkg_free(path);
	return rc;
}

static int k8s_dns_label_valid(const char *s)
{
	size_t i, len;

	if (!s || !*s)
		return 0;
	len = strlen(s);
	if (len > 63)
		return 0;
	if (!((s[0] >= 'a' && s[0] <= 'z') ||
		  (s[0] >= '0' && s[0] <= '9')) ||
		!((s[len - 1] >= 'a' && s[len - 1] <= 'z') ||
		  (s[len - 1] >= '0' && s[len - 1] <= '9')))
		return 0;

	for (i = 0; i < len; i++)
		if (!((s[i] >= 'a' && s[i] <= 'z') ||
			  (s[i] >= '0' && s[i] <= '9') ||
			  s[i] == '-'))
			return 0;
	return 1;
}

static int k8s_dns_subdomain_valid(const char *s)
{
	const char *p, *label;
	size_t len, label_len;
	char buf[64];

	if (!s || !*s)
		return 0;
	len = strlen(s);
	if (len > 253)
		return 0;

	label = s;
	for (p = s; ; p++) {
		if (*p != '.' && *p != '\0')
			continue;

		label_len = (size_t)(p - label);
		if (label_len == 0 || label_len >= sizeof(buf))
			return 0;
		memcpy(buf, label, label_len);
		buf[label_len] = '\0';
		if (!k8s_dns_label_valid(buf))
			return 0;

		if (*p == '\0')
			break;
		label = p + 1;
	}
	return 1;
}

static int k8s_secret_key_valid(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	if (!s || !*s)
		return 0;
	for (; *p; p++)
		if (!( (*p >= 'a' && *p <= 'z') ||
			   (*p >= 'A' && *p <= 'Z') ||
			   (*p >= '0' && *p <= '9') ||
			   *p == '-' || *p == '_' || *p == '.' ))
			return 0;
	return 1;
}

/* a header value must not be able to inject extra header lines */
static int secret_header_value_valid(const char *s, int len)
{
	int i;

	for (i = 0; i < len; i++)
		if (s[i] == '\r' || s[i] == '\n' || s[i] == '\0')
			return 0;
	return 1;
}

/* strict (padded, no whitespace) base64 check, as produced by Kubernetes */
static int secret_base64_valid(const char *s, size_t len)
{
	size_t i, pad = 0;

	if (len % 4)
		return 0;
	for (i = 0; i < len; i++) {
		if (s[i] == '=') {
			pad++;
			continue;
		}
		if (pad || !((s[i] >= 'A' && s[i] <= 'Z') ||
				(s[i] >= 'a' && s[i] <= 'z') ||
				(s[i] >= '0' && s[i] <= '9') || s[i] == '+' || s[i] == '/'))
			return 0;
	}
	return pad <= 2;
}

static int load_k8s_secret(const str *spec, str *out)
{
	CURL *curl = NULL;
	CURLcode rc;
	struct curl_slist *headers = NULL;
	struct http_buffer body = {0, 0, 0};
	str token = STR_NULL, ns_file = STR_NULL;
	char *tmp = NULL, *hash, *key, *slash, *namespace, *name;
	char *url = NULL, *api_alloc = NULL, *key_copy = NULL;
	char auth[8192];
	const char *api;
	const char *host, *port;
	long status = 0;
	cJSON *root = NULL, *data, *item;
	int max_decoded, decoded, rc_out = -1;

	if (spec->len <= (int)strlen(K8S_PREFIX))
		return -1;

	tmp = pkg_malloc(spec->len + 1);
	if (!tmp)
		goto done;
	memcpy(tmp, spec->s, spec->len);
	tmp[spec->len] = '\0';

	hash = strrchr(tmp, '#');
	if (!hash || !hash[1]) {
		LM_ERR("Kubernetes secret spec must end with #key\n");
		goto done;
	}
	*hash = '\0';
	key = hash + 1;
	name = tmp + strlen(K8S_PREFIX);
	slash = strchr(name, '/');

	if (slash) {
		*slash = '\0';
		namespace = name;
		name = slash + 1;
	} else {
		if (read_secret_file(k8s_namespace_file, &ns_file, 4096) < 0) {
			LM_ERR("cannot read Kubernetes service-account namespace\n");
			goto done;
		}
		namespace = ns_file.s;
	}

	if (!k8s_dns_label_valid(namespace) ||
		!k8s_dns_subdomain_valid(name) ||
		!k8s_secret_key_valid(key)) {
		LM_ERR("invalid Kubernetes namespace, Secret name, or key\n");
		goto done;
	}

	if (read_secret_file(k8s_token_file, &token, 1024 * 1024) < 0 ||
		!token.len) {
		LM_ERR("cannot read Kubernetes service-account token\n");
		goto done;
	}
	if (!secret_header_value_valid(token.s, token.len)) {
		LM_ERR("invalid characters in Kubernetes service-account token\n");
		goto done;
	}

	if (k8s_api && *k8s_api) {
		api = k8s_api;
	} else {
		host = getenv("KUBERNETES_SERVICE_HOST");
		port = getenv("KUBERNETES_SERVICE_PORT_HTTPS");
		if (!port || !*port)
			port = "443";
		if (!host || !*host) {
			LM_ERR("KUBERNETES_SERVICE_HOST is not set\n");
			goto done;
		}
		api_alloc = pkg_malloc(strlen(host) + strlen(port) + 16);
		if (!api_alloc)
			goto done;
		if (strchr(host, ':') && host[0] != '[')
			sprintf(api_alloc, "https://[%s]:%s", host, port);
		else
			sprintf(api_alloc, "https://%s:%s", host, port);
		api = api_alloc;
	}

	url = pkg_malloc(strlen(api) + strlen(namespace) + strlen(name) + 64);
	if (!url)
		goto done;
	sprintf(url, "%s/api/v1/namespaces/%s/secrets/%s", api, namespace, name);

	if (snprintf(auth, sizeof(auth), "Authorization: Bearer %.*s",
			token.len, token.s) >= (int)sizeof(auth)) {
		LM_ERR("Kubernetes service-account token is too large\n");
		goto done;
	}
	headers = curl_slist_append(headers, auth);
	if (!headers)
		goto done;

	curl = curl_easy_init();
	if (!curl)
		goto done;
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, vault_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)k8s_timeout);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)k8s_timeout);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	secret_curl_set_protocol(curl, 1);
	if (k8s_ca_file && *k8s_ca_file)
		curl_easy_setopt(curl, CURLOPT_CAINFO, k8s_ca_file);

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		LM_ERR("Kubernetes Secret request failed: %s\n",
			curl_easy_strerror(rc));
		goto done;
	}
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
	if (status < 200 || status >= 300) {
		LM_ERR("Kubernetes Secret request returned HTTP %ld\n", status);
		goto done;
	}

	root = secret_json_parse(body.s);
	if (!root || root->type != cJSON_Object) {
		LM_ERR("invalid JSON in Kubernetes Secret response\n");
		goto done;
	}
	data = json_object_get_exact(root, "data");
	if (!data || data->type != cJSON_Object) {
		LM_ERR("Kubernetes Secret has no data object\n");
		goto done;
	}

	key_copy = pkg_malloc(strlen(key) + 1);
	if (!key_copy)
		goto done;
	strcpy(key_copy, key);
	item = json_object_get_exact(data, key_copy);
	if (!item || item->type != cJSON_String || !item->valuestring) {
		LM_ERR("Kubernetes Secret key '%s' was not found\n", key);
		goto done;
	}

	if (!secret_base64_valid(item->valuestring, strlen(item->valuestring))) {
		LM_ERR("Kubernetes Secret key '%s' is not valid base64\n", key);
		goto done;
	}

	max_decoded = calc_max_base64_decode_len(strlen(item->valuestring)) + 1;
	out->s = pkg_malloc(max_decoded);
	if (!out->s)
		goto done;
	decoded = base64decode((unsigned char *)out->s,
		(unsigned char *)item->valuestring, strlen(item->valuestring));
	if (decoded < 0) {
		secret_pkg_free(out->s, max_decoded);
		out->s = NULL;
		goto done;
	}
	out->len = decoded;
	out->s[out->len] = '\0';
	rc_out = 0;

done:
	if (root) {
		secret_wipe_json(root);
		cJSON_Delete(root);
	}
	secret_bzero(auth, sizeof(auth));
	if (curl)
		curl_easy_cleanup(curl);
	if (headers)
		curl_slist_free_all(headers);
	if (body.s)
		secret_pkg_free(body.s, body.size);
	if (token.s)
		secret_pkg_free(token.s, token.len);
	if (ns_file.s)
		pkg_free(ns_file.s);
	if (tmp)
		pkg_free(tmp);
	if (url)
		pkg_free(url);
	if (api_alloc)
		pkg_free(api_alloc);
	if (key_copy)
		pkg_free(key_copy);
	return rc_out;
}

/* HTTPS is always allowed, plain HTTP only after an explicit opt-in */
static int vault_scheme_permitted(const char *scheme, int allow_insecure)
{
	if (!scheme)
		return 0;
	if (!strcmp(scheme, "https"))
		return 1;
	if (!strcmp(scheme, "http"))
		return allow_insecure ? 1 : 0;
	return 0;
}

static int load_vault_secret(const str *spec, str *out)
{
	CURL *curl = NULL;
	CURLcode rc;
	struct curl_slist *headers = NULL, *new_headers;
	struct http_buffer body = {0, 0, 0};
	char *tmp = NULL, *hash, *field, *url = NULL;
	char *token, *ns;
	char hdr[4096];
	long status = 0;
	cJSON *root = NULL, *data, *item;
	const char *rest;
	const char *scheme;
	int rc_out = -1;

	tmp = pkg_malloc(spec->len + 1);
	if (!tmp)
		goto done;
	memcpy(tmp, spec->s, spec->len);
	tmp[spec->len] = '\0';
	hash = strrchr(tmp, '#');
	if (!hash || !hash[1]) {
		LM_ERR("Vault secret spec must end with #field\n");
		goto done;
	}
	*hash = '\0';
	field = hash + 1;

	if (!strncmp(tmp, VAULT_HTTP_PREFIX, strlen(VAULT_HTTP_PREFIX))) {
		scheme = "http";
		rest = tmp + strlen(VAULT_HTTP_PREFIX);
	} else if (!strncmp(tmp, VAULT_HTTPS_PREFIX, strlen(VAULT_HTTPS_PREFIX))) {
		scheme = "https";
		rest = tmp + strlen(VAULT_HTTPS_PREFIX);
	} else {
		scheme = vault_scheme;
		rest = tmp + strlen(VAULT_PREFIX);
	}
	if (!vault_scheme_permitted(scheme, allow_insecure_vault_http)) {
		LM_ERR("plain HTTP Vault access is disabled; set "
			"allow_insecure_vault_http=1 only for trusted test networks\n");
		goto done;
	}

	url = pkg_malloc(strlen(scheme) + 3 + strlen(rest) + 1);
	if (!url)
		goto done;
	sprintf(url, "%s://%s", scheme, rest);

	token = vault_token_env ? getenv(vault_token_env) : NULL;
	if (!token || !*token) {
		LM_ERR("Vault token environment variable is not set\n");
		goto done;
	}
	if (!secret_header_value_valid(token, strlen(token)) ||
			snprintf(hdr, sizeof(hdr), "X-Vault-Token: %s", token) >=
			(int)sizeof(hdr)) {
		LM_ERR("invalid or oversized Vault token\n");
		goto done;
	}
	new_headers = curl_slist_append(headers, hdr);
	if (!new_headers)
		goto done;
	headers = new_headers;

	ns = vault_namespace_env ? getenv(vault_namespace_env) : NULL;
	if (ns && *ns) {
		if (!secret_header_value_valid(ns, strlen(ns)) ||
				snprintf(hdr, sizeof(hdr), "X-Vault-Namespace: %s", ns) >=
				(int)sizeof(hdr)) {
			LM_ERR("invalid or oversized Vault namespace\n");
			goto done;
		}
		new_headers = curl_slist_append(headers, hdr);
		if (!new_headers)
			goto done;
		headers = new_headers;
	}

	curl = curl_easy_init();
	if (!curl)
		goto done;
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, vault_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)vault_timeout);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, (long)vault_timeout);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	secret_curl_set_protocol(curl, !strcmp(scheme, "https"));
	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		LM_ERR("Vault request failed: %s\n", curl_easy_strerror(rc));
		goto done;
	}
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
	if (status < 200 || status >= 300) {
		LM_ERR("Vault returned HTTP %ld\n", status);
		goto done;
	}

	root = secret_json_parse(body.s);
	if (!root || root->type != cJSON_Object) {
		LM_ERR("invalid JSON in Vault response\n");
		goto done;
	}
	data = json_object_get_exact(root, "data");
	if (!data || data->type != cJSON_Object) {
		LM_ERR("Vault response has no data object\n");
		goto done;
	}
	/* Vault KV v2 wraps the actual values in data.data. */
	item = json_object_get_exact(data, "data");
	if (item && item->type == cJSON_Object)
		data = item;
	item = json_path(data, field);
	if (!item || item->type != cJSON_String || !item->valuestring) {
		LM_ERR("Vault field '%s' not found or not a string\n", field);
		goto done;
	}
	if (str_dup_pkg(out, item->valuestring, strlen(item->valuestring)) < 0)
		goto done;
	rc_out = 0;

done:
	if (root) {
		secret_wipe_json(root);
		cJSON_Delete(root);
	}
	secret_bzero(hdr, sizeof(hdr));
	if (curl)
		curl_easy_cleanup(curl);
	if (headers)
		curl_slist_free_all(headers);
	if (body.s)
		secret_pkg_free(body.s, body.size);
	if (url)
		pkg_free(url);
	if (tmp)
		pkg_free(tmp);
	return rc_out;
}

static int load_secret_value(const str *spec, str *out)
{
	memset(out, 0, sizeof(*out));
	if (spec->len > (int)strlen(ENV_PREFIX) &&
		!strncmp(spec->s, ENV_PREFIX, strlen(ENV_PREFIX)))
		return load_env_secret(spec, out);
	if (spec->len > (int)strlen(FILE_PREFIX) &&
		!strncmp(spec->s, FILE_PREFIX, strlen(FILE_PREFIX)))
		return load_file_secret(spec, out);
	if (spec->len > (int)strlen(VAULT_PREFIX) &&
		!strncmp(spec->s, VAULT_PREFIX, strlen(VAULT_PREFIX)))
		return load_vault_secret(spec, out);
	if (spec->len > (int)strlen(VAULT_HTTP_PREFIX) &&
		!strncmp(spec->s, VAULT_HTTP_PREFIX, strlen(VAULT_HTTP_PREFIX)))
		return load_vault_secret(spec, out);
	if (spec->len > (int)strlen(VAULT_HTTPS_PREFIX) &&
		!strncmp(spec->s, VAULT_HTTPS_PREFIX, strlen(VAULT_HTTPS_PREFIX)))
		return load_vault_secret(spec, out);
	if (spec->len > (int)strlen(K8S_PREFIX) &&
		!strncmp(spec->s, K8S_PREFIX, strlen(K8S_PREFIX)))
		return load_k8s_secret(spec, out);

	LM_ERR("unsupported secret provider in '%.*s'\n", spec->len, spec->s);
	return -1;
}

static struct secret_entry *find_secret(const str *name)
{
	struct secret_entry *it;
	for (it = secret_entries; it; it = it->next)
		if (it->name.len == name->len &&
			!memcmp(it->name.s, name->s, name->len))
			return it;
	return NULL;
}

static int reload_entry(struct secret_entry *e)
{
	str fresh = STR_NULL;
	char *new_value;

	if (load_secret_value(&e->spec, &fresh) < 0)
		return -1;
	new_value = shm_malloc(fresh.len + 1);
	if (!new_value) {
		secret_pkg_free(fresh.s, fresh.len);
		return -1;
	}
	memcpy(new_value, fresh.s, fresh.len);
	new_value[fresh.len] = '\0';
	secret_pkg_free(fresh.s, fresh.len);

	lock_get(secret_lock);
	if (e->value.s)
		secret_shm_free(e->value.s, e->value.len);
	e->value.s = new_value;
	e->value.len = fresh.len;
	lock_release(secret_lock);
	return 0;
}

static void free_pending_secrets(struct pending_secret *head)
{
	struct pending_secret *p, *next;

	for (p = head; p; p = next) {
		next = p->next;
		if (p->value)
			secret_shm_free(p->value, p->len);
		pkg_free(p);
	}
}

static int reload_all_entries(void)
{
	struct secret_entry *e;
	struct pending_secret *head = NULL, *p;
	str fresh = STR_NULL;

	/*
	 * Fetch and allocate every replacement first. Readers keep seeing the
	 * complete old set until all providers have succeeded.
	 */
	for (e = secret_entries; e; e = e->next) {
		fresh = STR_NULL;
		if (load_secret_value(&e->spec, &fresh) < 0)
			goto error;

		p = pkg_malloc(sizeof(*p));
		if (!p) {
			secret_pkg_free(fresh.s, fresh.len);
			goto error;
		}
		memset(p, 0, sizeof(*p));
		p->value = shm_malloc(fresh.len + 1);
		if (!p->value) {
			pkg_free(p);
			secret_pkg_free(fresh.s, fresh.len);
			goto error;
		}
		memcpy(p->value, fresh.s, fresh.len);
		p->value[fresh.len] = '\0';
		p->len = fresh.len;
		p->entry = e;
		p->next = head;
		head = p;
		secret_pkg_free(fresh.s, fresh.len);
	}

	/* One lock makes the rotation atomic from every script reader's view. */
	lock_get(secret_lock);
	for (p = head; p; p = p->next) {
		if (p->entry->value.s)
			secret_shm_free(p->entry->value.s, p->entry->value.len);
		p->entry->value.s = p->value;
		p->entry->value.len = p->len;
		p->value = NULL;
	}
	lock_release(secret_lock);

	free_pending_secrets(head);
	return 0;

error:
	free_pending_secrets(head);
	return -1;
}

static int add_entry(struct secret_def *d)
{
	struct secret_entry *e;

	e = shm_malloc(sizeof(*e));
	if (!e)
		return -1;
	memset(e, 0, sizeof(*e));
	if (str_dup_shm(&e->name, d->name.s, d->name.len) < 0 ||
		str_dup_shm(&e->spec, d->spec.s, d->spec.len) < 0) {
		if (e->name.s)
			shm_free(e->name.s);
		if (e->spec.s)
			shm_free(e->spec.s);
		shm_free(e);
		return -1;
	}
	e->next = secret_entries;
	secret_entries = e;
	if (reload_entry(e) < 0) {
		LM_ERR("failed to load secret '%.*s'\n", e->name.len, e->name.s);
		if (!allow_missing)
			return -1;
	}
	return 0;
}

static int pv_parse_secret_name(pv_spec_t *sp, const str *in)
{
	pv_spec_p nsp;

	if (!in || !in->s || in->len <= 0) {
		LM_ERR("empty $secret() name\n");
		return -1;
	}

	if (in->s[0] == PV_MARKER) {
		nsp = pkg_malloc(sizeof(*nsp));
		if (!nsp) {
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		if (!pv_parse_spec(in, nsp)) {
			LM_ERR("invalid $secret() name [%.*s]\n", in->len, in->s);
			pv_spec_free(nsp);
			return -1;
		}
		sp->pvp.pvn.type = PV_NAME_PVAR;
		sp->pvp.pvn.u.dname = (void *)nsp;
		return 0;
	}

	sp->pvp.pvn.u.isname.name.s = *in;
	sp->pvp.pvn.type = PV_NAME_INTSTR;
	sp->pvp.pvn.u.isname.type = AVP_NAME_STR;
	return 0;
}

static int pv_get_secret(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	pv_value_t name_val;
	struct secret_entry *e;
	str out;
	int i;

	if (!param)
		return pv_get_null(msg, param, res);
	memset(&name_val, 0, sizeof(name_val));
	if (param->pvn.type == PV_NAME_PVAR) {
		if (pv_get_spec_name(msg, param, &name_val) != 0 ||
			!(name_val.flags & PV_VAL_STR))
			return pv_get_null(msg, param, res);
	} else {
		name_val.rs = param->pvn.u.isname.name.s;
	}

	lock_get(secret_lock);
	e = find_secret(&name_val.rs);
	if (!e || !e->value.s) {
		lock_release(secret_lock);
		return pv_get_null(msg, param, res);
	}
	i = pv_value_buf_idx;
	pv_value_buf_idx = (pv_value_buf_idx + 1) % SECRET_PV_BUFS;
	if (pv_value_buf_len[i] < e->value.len + 1) {
		char *p = pkg_malloc(e->value.len + 1);
		if (!p) {
			lock_release(secret_lock);
			LM_ERR("no more pkg memory\n");
			return -1;
		}
		if (pv_value_buf[i])
			secret_pkg_free(pv_value_buf[i], pv_value_buf_len[i]);
		pv_value_buf[i] = p;
		pv_value_buf_len[i] = e->value.len + 1;
	} else {
		secret_bzero(pv_value_buf[i], pv_value_buf_len[i]);
	}
	memcpy(pv_value_buf[i], e->value.s, e->value.len);
	pv_value_buf[i][e->value.len] = '\0';
	out.s = pv_value_buf[i];
	out.len = e->value.len;
	lock_release(secret_lock);
	return pv_get_strval(msg, param, res, &out);
}

static int w_secret_exists(struct sip_msg *msg, str *name)
{
	struct secret_entry *e;
	int exists;

	if (!name)
		return -1;
	lock_get(secret_lock);
	e = find_secret(name);
	exists = e && e->value.s;
	lock_release(secret_lock);
	return exists ? 1 : -1;
}

static mi_response_t *mi_reload(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	(void)params;
	(void)async_hdl;

	if (reload_all_entries() < 0) {
		if (reload_failures)
			update_stat(reload_failures, 1);
		return init_mi_error(500,
			MI_SSTR("secret reload failed; previous values preserved"));
	}
	return init_mi_result_ok();
}

static mi_response_t *mi_reload_one(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	str name;
	struct secret_entry *e;

	if (get_mi_string_param(params, "name", &name.s, &name.len) < 0)
		return init_mi_param_error();
	lock_get(secret_lock);
	e = find_secret(&name);
	lock_release(secret_lock);
	if (!e)
		return init_mi_error(404, MI_SSTR("secret not found"));
	if (reload_entry(e) < 0) {
		if (reload_failures)
			update_stat(reload_failures, 1);
		return init_mi_error(500, MI_SSTR("secret reload failed"));
	}
	return init_mi_result_ok();
}

static const char *provider_name(const str *spec)
{
	if (!strncmp(spec->s, ENV_PREFIX, strlen(ENV_PREFIX)))
		return "env";
	if (!strncmp(spec->s, FILE_PREFIX, strlen(FILE_PREFIX)))
		return "file";
	if (!strncmp(spec->s, VAULT_PREFIX, strlen(VAULT_PREFIX)) ||
		!strncmp(spec->s, VAULT_HTTP_PREFIX, strlen(VAULT_HTTP_PREFIX)) ||
		!strncmp(spec->s, VAULT_HTTPS_PREFIX, strlen(VAULT_HTTPS_PREFIX)))
		return "vault";
	if (!strncmp(spec->s, K8S_PREFIX, strlen(K8S_PREFIX)))
		return "kubernetes";
	return "unknown";
}

static mi_response_t *mi_list(const mi_params_t *params,
		struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *arr, *obj;
	struct secret_entry *e;
	const char *provider;

	resp = init_mi_result_array(&arr);
	if (!resp)
		return NULL;
	lock_get(secret_lock);
	for (e = secret_entries; e; e = e->next) {
		obj = add_mi_object(arr, NULL, 0);
		if (!obj)
			goto error;
		provider = provider_name(&e->spec);
		if (add_mi_string(obj, MI_SSTR("name"), e->name.s, e->name.len) < 0 ||
			add_mi_string(obj, MI_SSTR("provider"), provider,
				strlen(provider)) < 0 ||
			add_mi_bool(obj, MI_SSTR("loaded"), e->value.s != NULL) < 0)
			goto error;
	}
	lock_release(secret_lock);
	return resp;

error:
	lock_release(secret_lock);
	free_mi_response(resp);
	return NULL;
}

#ifdef UNIT_TESTS
int secrets_test_vault_scheme_allowed(const char *scheme, int allow_insecure)
{
	return vault_scheme_permitted(scheme, allow_insecure);
}

int secrets_test_json_depth_ok(const char *json)
{
	return json ? secret_json_depth_ok(json) : 0;
}

int secrets_test_base64_valid(const char *value)
{
	return value ? secret_base64_valid(value, strlen(value)) : 0;
}

int secrets_test_header_value_valid(const char *value)
{
	return value ? secret_header_value_valid(value, strlen(value)) : 0;
}

int secrets_test_k8s_namespace_valid(const char *value)
{
	return k8s_dns_label_valid(value);
}

int secrets_test_k8s_secret_name_valid(const char *value)
{
	return k8s_dns_subdomain_valid(value);
}

int secrets_test_k8s_key_valid(const char *value)
{
	return k8s_secret_key_valid(value);
}

int secrets_test_json_path(const char *json, const char *path,
	const char *expected)
{
	cJSON *root, *item;
	int ok = 0;

	if (!json || !path || !expected)
		return 0;
	root = secret_json_parse(json);
	if (!root)
		return 0;
	item = json_path(root, path);
	if (item && item->type == cJSON_String && item->valuestring &&
		strcmp(item->valuestring, expected) == 0)
		ok = 1;
	cJSON_Delete(root);
	return ok;
}
#endif

static int mod_init(void)
{
	struct secret_def *d;

	if (vault_timeout < 1)
		vault_timeout = 1;
	if (k8s_timeout < 1)
		k8s_timeout = 1;
	if (!vault_scheme || (strcmp(vault_scheme, "http") &&
			strcmp(vault_scheme, "https"))) {
		LM_ERR("vault_scheme must be either 'http' or 'https'\n");
		return -1;
	}
	if (!vault_scheme_permitted(vault_scheme, allow_insecure_vault_http)) {
		LM_ERR("vault_scheme=http requires allow_insecure_vault_http=1\n");
		return -1;
	}
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		LM_ERR("failed to initialize libcurl\n");
		return -1;
	}

	secret_lock = lock_alloc();
	if (!secret_lock || !lock_init(secret_lock)) {
		LM_ERR("failed to initialize secret lock\n");
		if (secret_lock)
			lock_dealloc(secret_lock);
		secret_lock = NULL;
		curl_global_cleanup();
		return -1;
	}

	for (d = secret_defs; d; d = d->next)
		if (add_entry(d) < 0) {
			mod_destroy();
			return -1;
		}
	return 0;
}

static void mod_destroy(void)
{
	struct secret_entry *e, *next;
	int i;

	for (e = secret_entries; e; e = next) {
		next = e->next;
		if (e->value.s)
			secret_shm_free(e->value.s, e->value.len);
		if (e->name.s)
			shm_free(e->name.s);
		if (e->spec.s)
			shm_free(e->spec.s);
		shm_free(e);
	}
	secret_entries = NULL;
	if (secret_lock) {
		lock_destroy(secret_lock);
		lock_dealloc(secret_lock);
		secret_lock = NULL;
	}
	for (i = 0; i < SECRET_PV_BUFS; i++) {
		if (pv_value_buf[i])
			secret_pkg_free(pv_value_buf[i], pv_value_buf_len[i]);
		pv_value_buf[i] = NULL;
		pv_value_buf_len[i] = 0;
	}
	curl_global_cleanup();
}
