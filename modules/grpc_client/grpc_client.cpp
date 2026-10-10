/*
 * Native asynchronous gRPC client for OpenSIPS
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

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <new>
#include <poll.h>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/generic/generic_stub.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/support/byte_buffer.h>
#include <grpcpp/support/slice.h>
#include <grpcpp/support/status.h>

#ifdef __cplusplus
#define class class_keyword
#undef HAVE_STDATOMIC
#undef HAVE_GENERICS
#endif
extern "C" {
#include "../../poll_types.h"
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../async.h"
#include "../../pvar.h"
#include "../../statistics.h"
}
#ifdef class
#undef class
#endif

static int grpc_default_timeout_ms = 3000;
static int grpc_use_tls = 0;
static char *grpc_ca_file = NULL;
static char *grpc_cert_file = NULL;
static char *grpc_key_file = NULL;
static char *grpc_authority = NULL;
static int grpc_max_cached_channels = 64;

static std::string grpc_ca_pem;
static std::string grpc_cert_pem;
static std::string grpc_key_pem;
static std::unordered_map<std::string, std::shared_ptr<grpc::Channel> > grpc_channels;

static stat_var *grpc_requests;
static stat_var *grpc_success;
static stat_var *grpc_errors;
static stat_var *grpc_timeouts;
static stat_var *grpc_inflight;

struct grpc_async_param {
	std::shared_ptr<grpc::Channel> channel;
	std::unique_ptr<grpc::GenericStub> stub;
	grpc::ClientContext context;
	grpc::ByteBuffer request;
	grpc::ByteBuffer response;
	grpc::Status status;
	std::string method;
	pv_spec_t *response_pv;
	pv_spec_t *code_pv;
	pv_spec_t *error_pv;
	int read_fd;
	int write_fd;
	std::atomic<int> refs;
	std::atomic<bool> callback_done;
	std::atomic<bool> timed_out;

	grpc_async_param() : response_pv(NULL), code_pv(NULL), error_pv(NULL),
		read_fd(-1), write_fd(-1), refs(2), callback_done(false),
		timed_out(false) {}
};

static int mod_init(void);
static void mod_destroy(void);
static int fixup_writable_pv(void **param);
static int w_grpc_unary(struct sip_msg *msg, async_ctx *ctx,
	str *target, str *method, str *request,
	pv_spec_t *response_pv, pv_spec_t *code_pv, pv_spec_t *error_pv,
	str *metadata);
static enum async_ret_code grpc_resume(int fd, struct sip_msg *msg, void *param);
static enum async_ret_code grpc_timeout_resume(int fd, struct sip_msg *msg,
	void *param);

static const acmd_export_t acmds[] = {
	{"grpc_unary", (acmd_function)w_grpc_unary, {
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_STR, 0, 0},
		{CMD_PARAM_VAR, fixup_writable_pv, 0},
		{CMD_PARAM_VAR, fixup_writable_pv, 0},
		{CMD_PARAM_VAR|CMD_PARAM_OPT, fixup_writable_pv, 0},
		{CMD_PARAM_STR|CMD_PARAM_OPT, 0, 0},
		{0, 0, 0}}},
	{0, 0, {{0, 0, 0}}}
};

static const param_export_t params[] = {
	{"default_timeout_ms", INT_PARAM, &grpc_default_timeout_ms},
	{"use_tls", INT_PARAM, &grpc_use_tls},
	{"ca_file", STR_PARAM, &grpc_ca_file},
	{"client_cert_file", STR_PARAM, &grpc_cert_file},
	{"client_key_file", STR_PARAM, &grpc_key_file},
	{"authority", STR_PARAM, &grpc_authority},
	{"max_cached_channels", INT_PARAM, &grpc_max_cached_channels},
	{0, 0, 0}
};

static const stat_export_t mod_stats[] = {
	{"requests", STAT_NO_RESET, &grpc_requests},
	{"success", STAT_NO_RESET, &grpc_success},
	{"errors", STAT_NO_RESET, &grpc_errors},
	{"timeouts", STAT_NO_RESET, &grpc_timeouts},
	{"inflight", STAT_NO_RESET, &grpc_inflight},
	{0, 0, 0}
};

extern "C" {
struct module_exports exports = {
	"grpc_client",
	MOD_TYPE_DEFAULT,
	{ OPENSIPS_FULL_VERSION, OPENSIPS_COMPILE_FLAGS, { VERSIONTYPE, THISREVISION } },
	DEFAULT_DLFLAGS,
	0,
	0,
	0,
	acmds,
	params,
	mod_stats,
	0,
	0,
	0,
	0,
	0,
	mod_init,
	0,
	mod_destroy,
	0,
	0
};
}

static int read_text_file(const char *path, std::string &out)
{
	std::ifstream f;
	if (!path || !*path)
		return 0;
	f.open(path, std::ios::in | std::ios::binary);
	if (!f.is_open()) {
		LM_ERR("cannot open gRPC TLS file %s\n", path);
		return -1;
	}
	out.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
	return 0;
}

static int set_nonblock_cloexec(int fd)
{
	int flags;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -1;
	flags = fcntl(fd, F_GETFD, 0);
	if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
		return -1;
	return 0;
}

static std::shared_ptr<grpc::ChannelCredentials> grpc_credentials(void)
{
	if (!grpc_use_tls)
		return grpc::InsecureChannelCredentials();

	grpc::SslCredentialsOptions opts;
	opts.pem_root_certs = grpc_ca_pem;
	opts.pem_cert_chain = grpc_cert_pem;
	opts.pem_private_key = grpc_key_pem;
	return grpc::SslCredentials(opts);
}

static std::shared_ptr<grpc::Channel> grpc_get_channel(
	const std::string &target, const grpc::ChannelArguments &args)
{
	std::unordered_map<std::string, std::shared_ptr<grpc::Channel> >::iterator it;
	std::shared_ptr<grpc::Channel> channel;

	if (grpc_max_cached_channels > 0) {
		it = grpc_channels.find(target);
		if (it != grpc_channels.end())
			return it->second;
	}

	channel = grpc::CreateCustomChannel(target, grpc_credentials(), args);
	if (!channel || grpc_max_cached_channels <= 0)
		return channel;

	/*
	 * This cache is per OpenSIPS worker process. Active calls retain their
	 * own shared_ptr, so clearing the map never invalidates an in-flight RPC.
	 * Avoid an unbounded map when the target is generated dynamically.
	 */
	if ((int)grpc_channels.size() >= grpc_max_cached_channels)
		grpc_channels.clear();
	grpc_channels[target] = channel;
	return channel;
}

static void trim_ascii(std::string &s)
{
	size_t start = 0, end = s.size();

	while (start < end && (s[start] == ' ' || s[start] == '\t'))
		start++;
	while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t'))
		end--;
	if (start || end != s.size())
		s = s.substr(start, end - start);
}

static int grpc_normalize_metadata_key(std::string &key)
{
	size_t i;

	trim_ascii(key);
	if (key.empty())
		return -1;

	for (i = 0; i < key.size(); i++) {
		unsigned char ch = (unsigned char)key[i];

		if (ch >= 'A' && ch <= 'Z') {
			key[i] = (char)(ch - 'A' + 'a');
			continue;
		}
		if ((ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.')
			continue;
		return -1;
	}

	/* grpc-* is reserved for the protocol implementation. */
	if (key.size() >= 5 && key.compare(0, 5, "grpc-") == 0)
		return -1;
	return 0;
}

static int grpc_proto_ident_valid(const char *s, int len, int allow_dots)
{
	int i, component_start = 1;

	if (!s || len <= 0)
		return 0;

	for (i = 0; i < len; i++) {
		unsigned char ch = (unsigned char)s[i];

		if (allow_dots && ch == '.') {
			if (component_start || i == len - 1)
				return 0;
			component_start = 1;
			continue;
		}

		if (component_start) {
			if (!((ch >= 'A' && ch <= 'Z') ||
				  (ch >= 'a' && ch <= 'z') || ch == '_'))
				return 0;
			component_start = 0;
			continue;
		}

		if (!((ch >= 'A' && ch <= 'Z') ||
			  (ch >= 'a' && ch <= 'z') ||
			  (ch >= '0' && ch <= '9') || ch == '_'))
			return 0;
	}
	return !component_start;
}

static int grpc_method_valid(const str *method)
{
	int i, separator = -1;

	if (!method || !method->s || method->len < 4 || method->s[0] != '/')
		return 0;

	for (i = 1; i < method->len; i++) {
		if (method->s[i] != '/')
			continue;
		if (separator >= 0 || i == 1 || i == method->len - 1)
			return 0;
		separator = i;
	}
	if (separator <= 1)
		return 0;

	return grpc_proto_ident_valid(method->s + 1, separator - 1, 1) &&
		grpc_proto_ident_valid(method->s + separator + 1,
			method->len - separator - 1, 0);
}

static int grpc_metadata_value_valid(const std::string &key,
	const std::string &value)
{
	size_t i;
	bool binary = key.size() >= 4 &&
		key.compare(key.size() - 4, 4, "-bin") == 0;

	if (binary)
		return 1;

	for (i = 0; i < value.size(); i++) {
		unsigned char ch = (unsigned char)value[i];
		if (ch < 0x20 || ch > 0x7e)
			return 0;
	}
	return 1;
}

static int grpc_add_metadata(grpc::ClientContext &ctx, const str *metadata)
{
	std::string input;
	size_t start = 0, sep, eq;

	if (!metadata || !metadata->s || metadata->len <= 0)
		return 0;

	input.assign(metadata->s, metadata->len);
	while (start <= input.size()) {
		sep = input.find(';', start);
		if (sep == std::string::npos)
			sep = input.size();

		std::string item = input.substr(start, sep - start);
		trim_ascii(item);
		if (!item.empty()) {
			eq = item.find('=');
			if (eq == std::string::npos || eq == 0) {
				LM_ERR("invalid gRPC metadata item '%s'; expected key=value\n",
					item.c_str());
				return -1;
			}

			std::string key = item.substr(0, eq);
			std::string value = item.substr(eq + 1);
			trim_ascii(value);
			if (grpc_normalize_metadata_key(key) < 0) {
				LM_ERR("invalid or reserved gRPC metadata key '%s'\n",
					key.c_str());
				return -1;
			}
			if (!grpc_metadata_value_valid(key, value)) {
				LM_ERR("invalid non-binary gRPC metadata value for key '%s'\n",
					key.c_str());
				return -1;
			}
			ctx.AddMetadata(key, value);
		}

		if (sep == input.size())
			break;
		start = sep + 1;
	}
	return 0;
}

static int fixup_writable_pv(void **param)
{
	if (!param || !*param || ((pv_spec_t *)*param)->setf == NULL) {
		LM_ERR("gRPC output parameter must be a writable variable\n");
		return -1;
	}
	return 0;
}

static void set_str_pv(struct sip_msg *msg, pv_spec_t *spec,
	const char *s, int len)
{
	pv_value_t v;
	if (!spec)
		return;
	memset(&v, 0, sizeof(v));
	v.flags = PV_VAL_STR;
	v.rs.s = (char *)(s ? s : "");
	v.rs.len = s ? len : 0;
	if (pv_set_value(msg, spec, 0, &v) < 0)
		LM_ERR("failed to set gRPC string output variable\n");
}

static void set_int_pv(struct sip_msg *msg, pv_spec_t *spec, int value)
{
	pv_value_t v;
	if (!spec)
		return;
	memset(&v, 0, sizeof(v));
	v.flags = PV_VAL_INT | PV_TYPE_INT;
	v.ri = value;
	if (pv_set_value(msg, spec, 0, &v) < 0)
		LM_ERR("failed to set gRPC integer output variable\n");
}

static std::string byte_buffer_to_string(const grpc::ByteBuffer &buffer)
{
	std::vector<grpc::Slice> slices;
	std::string out;
	if (!buffer.Dump(&slices).ok())
		return out;
	for (const auto &slice : slices)
		out.append(reinterpret_cast<const char *>(slice.begin()), slice.size());
	return out;
}

static void grpc_release(grpc_async_param *p)
{
	if (p && p->refs.fetch_sub(1, std::memory_order_acq_rel) == 1)
		delete p;
}

static void grpc_completion(grpc_async_param *p, grpc::Status status)
{
	char signal = 1;
	ssize_t n;

	if (!p)
		return;
	p->status = std::move(status);
	p->callback_done.store(true, std::memory_order_release);

	if (!p->timed_out.load(std::memory_order_acquire) && p->write_fd >= 0) {
		do {
			n = write(p->write_fd, &signal, sizeof(signal));
		} while (n < 0 && errno == EINTR);
	}
	if (p->write_fd >= 0) {
		close(p->write_fd);
		p->write_fd = -1;
	}
	grpc_release(p); /* callback ownership */
}

/* drop a call for which no completion callback was registered yet */
static void grpc_drop_call(grpc_async_param *p)
{
	if (p->read_fd >= 0)
		close(p->read_fd);
	if (p->write_fd >= 0)
		close(p->write_fd);
	delete p;
}

static int grpc_prepare_call(grpc_async_param *p, str *target, str *method,
	str *request, str *metadata)
{
	grpc::Slice request_slice;
	grpc::ChannelArguments channel_args;

	p->method.assign(method->s, method->len);

	if (grpc_authority && *grpc_authority)
		channel_args.SetSslTargetNameOverride(grpc_authority);
	std::string target_s(target->s, target->len);
	p->channel = grpc_get_channel(target_s, channel_args);
	if (!p->channel) {
		LM_ERR("failed to create gRPC channel for %s\n", target_s.c_str());
		return -1;
	}
	p->stub = std::make_unique<grpc::GenericStub>(p->channel);

	if (grpc_add_metadata(p->context, metadata) < 0)
		return -1;

	/* an empty protobuf message is a valid request, but a default-constructed
	 * ByteBuffer is not: gRPC aborts the process on such a send operation */
	if (request->len > 0)
		request_slice = grpc::Slice(request->s, request->len);
	p->request = grpc::ByteBuffer(&request_slice, 1);
	return 0;
}

static int w_grpc_unary(struct sip_msg *msg, async_ctx *ctx,
	str *target, str *method, str *request,
	pv_spec_t *response_pv, pv_spec_t *code_pv, pv_spec_t *error_pv,
	str *metadata)
{
	grpc_async_param *p;
	int fds[2] = {-1, -1};
	int effective_timeout_ms, rc;

	if (!ctx || !target || !target->s || !target->len ||
		!method || !method->s || !method->len || !request) {
		LM_ERR("invalid gRPC async call arguments\n");
		return -1;
	}
	if (!grpc_method_valid(method)) {
		LM_ERR("invalid gRPC method; expected /package.Service/Method\n");
		return -1;
	}
	if (is_main) {
		/* gRPC starts threads which do not survive fork(); never initialize
		 * it in the attendant process, which forks (auto-scaled) workers */
		LM_ERR("gRPC calls are not allowed from the main process\n");
		return -1;
	}

	p = new (std::nothrow) grpc_async_param();
	if (!p) {
		LM_ERR("out of memory allocating gRPC call\n");
		return -1;
	}

	if (pipe(fds) < 0 || set_nonblock_cloexec(fds[0]) < 0 ||
		set_nonblock_cloexec(fds[1]) < 0) {
		LM_ERR("cannot create gRPC completion pipe: %s\n", strerror(errno));
		if (fds[0] >= 0) close(fds[0]);
		if (fds[1] >= 0) close(fds[1]);
		delete p;
		return -1;
	}
	p->read_fd = fds[0];
	p->write_fd = fds[1];
	p->response_pv = response_pv;
	p->code_pv = code_pv;
	p->error_pv = error_pv;

	/* C++ exceptions must never propagate into the C core */
	try {
		rc = grpc_prepare_call(p, target, method, request, metadata);
	} catch (const std::exception &e) {
		LM_ERR("failed to prepare gRPC call: %s\n", e.what());
		rc = -1;
	} catch (...) {
		LM_ERR("failed to prepare gRPC call: unknown exception\n");
		rc = -1;
	}
	if (rc < 0) {
		grpc_drop_call(p);
		return -1;
	}

	effective_timeout_ms = grpc_default_timeout_ms;
	if (ctx->timeout_s &&
		(effective_timeout_ms <= 0 || (int)(ctx->timeout_s * 1000U) < effective_timeout_ms))
		effective_timeout_ms = ctx->timeout_s * 1000U;
	if (effective_timeout_ms > 0)
		p->context.set_deadline(std::chrono::system_clock::now() +
			std::chrono::milliseconds(effective_timeout_ms));
	if (!ctx->timeout_s && effective_timeout_ms > 0)
		ctx->timeout_s = (effective_timeout_ms + 999) / 1000 + 1;

	try {
		p->stub->UnaryCall(&p->context, p->method, grpc::StubOptions(),
			&p->request, &p->response,
			[p](grpc::Status status) { grpc_completion(p, std::move(status)); });
	} catch (...) {
		/* the callback may or may not own the call now: leak it rather
		 * than risk a use-after-free */
		LM_ERR("failed to start gRPC call to %.*s\n", target->len, target->s);
		return -1;
	}

	update_stat(grpc_requests, 1);
	update_stat(grpc_inflight, 1);

	ctx->resume_param = p;
	/* C++ cannot implicitly convert function pointers to void *, so the
	 * ASYNC_SET_RESUME_F() C macro is expanded by hand */
	ctx->resume_f = (void *)grpc_resume;
	ctx->resume_f_name = "grpc_resume";
	ctx->timeout_f = (void *)grpc_timeout_resume;
	async_status = p->read_fd;
	return 1;
}

static void grpc_apply_completed_result(grpc_async_param *p,
	struct sip_msg *msg)
{
	std::string response;
	std::string error;
	int code;

	update_stat(grpc_inflight, -1);
	code = (int)p->status.error_code();
	try {
		if (p->status.ok()) {
			response = byte_buffer_to_string(p->response);
			set_int_pv(msg, p->code_pv, code);
			set_str_pv(msg, p->response_pv, response.data(), response.size());
			set_str_pv(msg, p->error_pv, "", 0);
			update_stat(grpc_success, 1);
			return;
		}
		error = p->status.error_message();
	} catch (...) {
		/* C++ exceptions must never propagate into the C core */
		LM_ERR("failed to copy the gRPC result\n");
		code = (int)grpc::StatusCode::RESOURCE_EXHAUSTED;
		error.clear();
	}
	set_int_pv(msg, p->code_pv, code);
	set_str_pv(msg, p->response_pv, "", 0);
	set_str_pv(msg, p->error_pv, error.data(), error.size());
	update_stat(grpc_errors, 1);
}

static enum async_ret_code grpc_resume(int fd, struct sip_msg *msg, void *param)
{
	grpc_async_param *p = (grpc_async_param *)param;
	char buf[16];

	if (!p)
		return ASYNC_DONE_CLOSE_FD;

	/* When dispatched by the reactor the fd is already readable.  When the
	 * core falls back to sync mode (e.g. async() from a failure route or for
	 * an end-to-end ACK), it keeps calling us while we return
	 * ASYNC_CONTINUE, so block here instead of busy-looping on the
	 * non-blocking pipe.  The RPC deadline bounds the wait. */
	if (fd >= 0 && !p->callback_done.load(std::memory_order_acquire)) {
		struct pollfd pfd;

		pfd.fd = fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		while (poll(&pfd, 1, -1) < 0 && errno == EINTR) {}
	}

	while (fd >= 0 && read(fd, buf, sizeof(buf)) < 0 && errno == EINTR) {}
	if (!p->callback_done.load(std::memory_order_acquire)) {
		async_status = ASYNC_CONTINUE;
		return ASYNC_CONTINUE;
	}

	grpc_apply_completed_result(p, msg);
	grpc_release(p); /* OpenSIPS core ownership */
	async_status = ASYNC_DONE_CLOSE_FD;
	return ASYNC_DONE_CLOSE_FD;
}

static enum async_ret_code grpc_timeout_resume(int fd, struct sip_msg *msg,
	void *param)
{
	grpc_async_param *p = (grpc_async_param *)param;
	static const char timeout_msg[] = "gRPC call timed out";

	if (!p)
		return ASYNC_DONE_CLOSE_FD;

	if (p->callback_done.load(std::memory_order_acquire)) {
		grpc_apply_completed_result(p, msg);
		grpc_release(p);
		async_status = ASYNC_DONE_CLOSE_FD;
		return ASYNC_DONE_CLOSE_FD;
	}

	p->timed_out.store(true, std::memory_order_release);

	if (p->callback_done.load(std::memory_order_acquire)) {
		grpc_apply_completed_result(p, msg);
		grpc_release(p);
		async_status = ASYNC_DONE_CLOSE_FD;
		return ASYNC_DONE_CLOSE_FD;
	}

	p->context.TryCancel();
	set_int_pv(msg, p->code_pv, (int)grpc::StatusCode::DEADLINE_EXCEEDED);
	set_str_pv(msg, p->response_pv, "", 0);
	set_str_pv(msg, p->error_pv, timeout_msg, sizeof(timeout_msg) - 1);
	update_stat(grpc_timeouts, 1);
	update_stat(grpc_errors, 1);
	update_stat(grpc_inflight, -1);

	grpc_release(p); /* callback keeps the object alive until cancellation completes */
	async_status = ASYNC_DONE_CLOSE_FD;
	return ASYNC_DONE_CLOSE_FD;
}

#ifdef UNIT_TESTS
extern "C" int grpc_client_test_metadata_key(const char *input,
	char *out, int out_size)
{
	std::string key;

	if (!input || !out || out_size <= 0)
		return -1;
	key.assign(input);
	if (grpc_normalize_metadata_key(key) < 0 ||
		(int)key.size() >= out_size)
		return -1;
	memcpy(out, key.data(), key.size());
	out[key.size()] = '\0';
	return (int)key.size();
}

extern "C" int grpc_client_test_metadata_value(const char *key,
	const char *value)
{
	std::string key_s, value_s;

	if (!key || !value)
		return 0;
	key_s.assign(key);
	value_s.assign(value);
	return grpc_metadata_value_valid(key_s, value_s);
}

extern "C" int grpc_client_test_method(const char *input)
{
	str method = STR_NULL;

	if (!input)
		return 0;
	method.s = (char *)input;
	method.len = strlen(input);
	return grpc_method_valid(&method);
}
#endif

static int mod_init(void)
{
	if (grpc_default_timeout_ms < 0) {
		LM_ERR("default_timeout_ms cannot be negative\n");
		return -1;
	}
	if (grpc_max_cached_channels < 0) {
		LM_ERR("max_cached_channels cannot be negative\n");
		return -1;
	}
	if (grpc_use_tls) {
		if (read_text_file(grpc_ca_file, grpc_ca_pem) < 0 ||
			read_text_file(grpc_cert_file, grpc_cert_pem) < 0 ||
			read_text_file(grpc_key_file, grpc_key_pem) < 0)
			return -1;
		if ((!grpc_cert_pem.empty() && grpc_key_pem.empty()) ||
			(grpc_cert_pem.empty() && !grpc_key_pem.empty())) {
			LM_ERR("both client_cert_file and client_key_file are required for mTLS\n");
			return -1;
		}
	}
	return 0;
}

static void grpc_secure_clear(std::string &value)
{
	if (!value.empty()) {
		volatile char *p = &value[0];
		size_t n = value.size();
		while (n--)
			*p++ = 0;
	}
	value.clear();
}

static void mod_destroy(void)
{
	grpc_channels.clear();
	grpc_secure_clear(grpc_ca_pem);
	grpc_secure_clear(grpc_cert_pem);
	grpc_secure_clear(grpc_key_pem);
}
