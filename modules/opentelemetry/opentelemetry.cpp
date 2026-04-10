/*
 * OpenTelemetry tracing for OpenSIPS routes
 *
 * Copyright (C) 2026 OpenSIPS Project
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
 *
 * History:
 * --------
 * 2026-01-05 initial release (vlad)
 */


#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <chrono>
#include <string>
#include <memory>
#include <new>

#include "opentelemetry/trace/provider.h"
#include "opentelemetry/trace/scope.h"
#include "opentelemetry/trace/span.h"
#include "opentelemetry/trace/span_context.h"
#include "opentelemetry/trace/tracer.h"
#include "opentelemetry/sdk/resource/resource.h"
#include "opentelemetry/sdk/trace/batch_span_processor.h"
#include "opentelemetry/sdk/trace/simple_processor.h"
#include "opentelemetry/sdk/trace/tracer_provider.h"
#include "opentelemetry/exporters/otlp/otlp_http_exporter_factory.h"
#include "opentelemetry/exporters/otlp/otlp_http_exporter_options.h"
namespace oteltrace = opentelemetry::trace;
namespace otelsdktrace = opentelemetry::sdk::trace;
namespace otelsdkresource = opentelemetry::sdk::resource;
namespace otelotlp = opentelemetry::exporter::otlp;

#ifdef __cplusplus
/* Relax C-only headers for C++ compilation. */
#define class class_keyword
#undef HAVE_STDATOMIC
#undef HAVE_GENERICS
#endif

extern "C" {
#include "../../poll_types.h"
#include "../../sr_module.h"
#include "../../dprint.h"
#include "../../mem/mem.h"
#include "../../mem/shm_mem.h"
#include "../../profiling.h"
#include "../../log_interface.h"
#include "../../str.h"
#include "../../pt.h"
#include "../../route.h"
#include "../../version.h"
#include "../../ip_addr.h"
#include "../../mi/mi.h"
}

#ifdef class
#undef class
#endif

static int otel_enabled_cfg = 0;
static int *otel_enabled = NULL;
static int otel_log_level = L_DBG;
static int otel_use_batch = 1;
static str otel_service_name = str_init("opensips");
static str otel_exporter_endpoint = STR_NULL;

struct otel_span {
	opentelemetry::nostd::shared_ptr<oteltrace::Span> span;
	std::unique_ptr<oteltrace::Scope> scope;
	const char *name;
	int route_type;
	int depth;
	int is_root;
	const char *file;
	int line;
	struct otel_span *parent;
};

static __thread struct otel_span *otel_span_top;
static __thread int otel_log_in_cb;

static __thread profiling_ctx_t otel_parent_ctx;
static __thread int otel_parent_ctx_set;
static int otel_trace_registered;
static int otel_log_consumer_registered;

static opentelemetry::nostd::shared_ptr<oteltrace::Tracer> otel_tracer;
static opentelemetry::nostd::shared_ptr<oteltrace::TracerProvider> otel_provider;

static int mod_init(void);
static int child_init(int rank);
static void destroy(void);
static mi_response_t *otel_mi_enable(const mi_params_t *params,
	struct mi_handler *async_hdl);
static void otel_log_consumer(int level, int facility, const char *module,
	const char *func, char *format, va_list ap);
static int otel_ensure_provider(void);
extern profiling_handlers_t otel_trace_handlers;
static int otel_init_provider(void);
static void otel_span_reset(void);

static inline int otel_is_enabled(void)
{
	return otel_enabled && *otel_enabled;
}

static void otel_parent_ctx_clear(void)
{
	memset(&otel_parent_ctx, 0, sizeof(otel_parent_ctx));
	otel_parent_ctx_set = 0;
}

static int otel_ensure_provider(void)
{
	if (otel_is_enabled() && !otel_tracer) {
		if (otel_init_provider() != 0) {
			LM_ERR("failed to initialize tracer provider\n");
			return -1;
		}
	}
	return 0;
}

static int otel_runtime_set_enable(int enable)
{
	if (enable) {
		if (otel_is_enabled())
			return 0;
		if (otel_enabled)
			*otel_enabled = 1;
		otel_enabled_cfg = 1;

		if (otel_ensure_provider() != 0) {
			if (otel_enabled)
				*otel_enabled = 0;
			otel_enabled_cfg = 0;
			return -1;
		}
		return 0;
	}

	if (!otel_is_enabled())
		return 0;

	if (otel_enabled)
		*otel_enabled = 0;
	otel_enabled_cfg = 0;

	otel_span_reset();
	otel_parent_ctx_clear();

	return 0;
}

static int otel_get_ctx(profiling_ctx_t *ctx)
{
	if (!ctx)
		return 0;
	memset(ctx, 0, sizeof(*ctx));
	if (otel_span_top && otel_span_top->span) {
		auto sc = otel_span_top->span->GetContext();
		if (!sc.IsValid())
			return 0;
		memcpy(ctx->trace_id, sc.trace_id().Id().data(), sizeof(ctx->trace_id));
		memcpy(ctx->span_id, sc.span_id().Id().data(), sizeof(ctx->span_id));
		ctx->trace_flags = sc.trace_flags().flags();
		return 1;
	}
	return 0;
}

static int otel_set_ctx(const profiling_ctx_t *ctx)
{
	if (!ctx)
		return 0;
	memcpy(&otel_parent_ctx, ctx, sizeof(otel_parent_ctx));
	otel_parent_ctx_set = 1;
	return 1;
}

static void otel_span_reset(void)
{
	struct otel_span *span, *next;

	span = otel_span_top;
	while (span) {
		next = span->parent;
		if (span->span)
			span->span->End();
		span->scope.reset();
		span->~otel_span();
		pkg_free(span);
		span = next;
	}

	otel_span_top = NULL;
}

static int otel_init_provider(void)
{
	std::string service_name(otel_service_name.s ? otel_service_name.s : "opensips",
		otel_service_name.s ? otel_service_name.len : (int)strlen("opensips"));

	otelsdkresource::ResourceAttributes attrs = {
		{ "service.name", service_name },
		{ "process.pid", (int64_t)my_pid() }
	};

	auto resource = otelsdkresource::Resource::Create(attrs);

	otelotlp::OtlpHttpExporterOptions opts;
	if (otel_exporter_endpoint.len && otel_exporter_endpoint.s)
		opts.url = std::string(otel_exporter_endpoint.s, otel_exporter_endpoint.len);

	auto exporter = otelotlp::OtlpHttpExporterFactory::Create(opts);
	std::unique_ptr<otelsdktrace::SpanProcessor> processor;

	if (otel_use_batch) {
		otelsdktrace::BatchSpanProcessorOptions bs_opts;
		processor = std::make_unique<otelsdktrace::BatchSpanProcessor>(std::move(exporter), bs_opts);
	} else {
		processor = std::make_unique<otelsdktrace::SimpleSpanProcessor>(std::move(exporter));
	}

	auto provider = opentelemetry::nostd::shared_ptr<oteltrace::TracerProvider>(
		std::make_shared<otelsdktrace::TracerProvider>(std::move(processor), resource));
	oteltrace::Provider::SetTracerProvider(provider);
	otel_tracer = provider->GetTracer("opensips.opentelemetry", OPENSIPS_FULL_VERSION);
	otel_provider = provider;

	return 0;
}

static void otel_set_msg_attributes(struct sip_msg *msg, oteltrace::Span *span)
{
	if (!span || !msg)
		return;

	if (msg->first_line.type == SIP_REQUEST) {
		str *m = &msg->first_line.u.request.method;
		span->SetAttribute("sip.method", opentelemetry::nostd::string_view(m->s, m->len));
		span->SetAttribute("opensips.top_route", route_type_name(REQUEST_ROUTE));
		if (msg->first_line.u.request.uri.s && msg->first_line.u.request.uri.len)
			span->SetAttribute("sip.ruri",
				opentelemetry::nostd::string_view(msg->first_line.u.request.uri.s,
					msg->first_line.u.request.uri.len));
	} else if (msg->first_line.type == SIP_REPLY) {
		span->SetAttribute("sip.status_code", (int64_t)msg->first_line.u.reply.statuscode);
		if (msg->first_line.u.reply.reason.s && msg->first_line.u.reply.reason.len)
			span->SetAttribute("sip.reason",
				opentelemetry::nostd::string_view(msg->first_line.u.reply.reason.s,
					msg->first_line.u.reply.reason.len));
		span->SetAttribute("opensips.top_route", route_type_name(ONREPLY_ROUTE));
	}

	if (msg->callid && msg->callid->body.s && msg->callid->body.len)
		span->SetAttribute("sip.call_id",
			opentelemetry::nostd::string_view(msg->callid->body.s, msg->callid->body.len));

	if (msg->cseq && msg->cseq->body.s && msg->cseq->body.len)
		span->SetAttribute("sip.cseq",
			opentelemetry::nostd::string_view(msg->cseq->body.s, msg->cseq->body.len));

	if (msg->via1 && msg->via1->host.s && msg->via1->host.len)
		span->SetAttribute("net.host.ip",
			opentelemetry::nostd::string_view(msg->via1->host.s, msg->via1->host.len));

	span->SetAttribute("net.peer.ip", ip_addr2a(&msg->rcv.src_ip));
	span->SetAttribute("net.peer.port", (int64_t)msg->rcv.src_port);
}

static struct otel_span *otel_span_start(const char *name, int route_type,
	int depth, int is_root, const char *file, int line)
{
	struct otel_span *span;
	int has_parent_ctx = 0;
	int has_parent_link = 0;

	if (!otel_is_enabled())
		return NULL;

	if (otel_ensure_provider() != 0)
		return NULL;

	span = (struct otel_span *)pkg_malloc(sizeof *span);
	if (!span)
		return NULL;
	new (span) otel_span();

	if (otel_tracer) {
		oteltrace::StartSpanOptions opts;
		opts.kind = oteltrace::SpanKind::kInternal;
		if (otel_span_top && otel_span_top->span) {
			opts.parent = otel_span_top->span->GetContext();
			has_parent_ctx = 1;
			has_parent_link = 1;
		} else if (otel_parent_ctx_set) {
			has_parent_ctx = 1;
			opentelemetry::trace::TraceId tid(opentelemetry::nostd::span<const uint8_t, 16>(otel_parent_ctx.trace_id, 16));
			opentelemetry::trace::SpanId sid(opentelemetry::nostd::span<const uint8_t, 8>(otel_parent_ctx.span_id, 8));
			opentelemetry::trace::TraceFlags tf(otel_parent_ctx.trace_flags);
			opentelemetry::trace::SpanContext sc(tid, sid, tf, true);
			if (sc.IsValid()) {
				opts.parent = sc;
				has_parent_link = 1;
				if (otel_parent_ctx.has_start_time) {
					opts.start_system_time = opentelemetry::common::SystemTimestamp(
						std::chrono::nanoseconds(otel_parent_ctx.start_system_ns));
					opts.start_steady_time = opentelemetry::common::SteadyTimestamp(
						std::chrono::nanoseconds(otel_parent_ctx.start_steady_ns));
				}
			}
			otel_parent_ctx_clear();
		}

		auto s = otel_tracer->StartSpan(name ? name : "<route>", opts);
		s->SetAttribute("opensips.route.type", route_type_name(route_type));
		s->SetAttribute("opensips.route.is_root", (int64_t)(has_parent_link ? 0 : is_root));
		if (file) {
			s->SetAttribute("code.filepath", file);
			s->SetAttribute("code.lineno", line);
		}

		span->scope = std::unique_ptr<oteltrace::Scope>(new oteltrace::Scope(s));
		span->span = s;
	}

	span->name = name;
	span->route_type = route_type;
	span->depth = depth;
	span->is_root = is_root;
	span->file = file;
	span->line = line;
	span->parent = otel_span_top;

	otel_span_top = span;

	return span;
}

static void otel_span_end(struct otel_span *span)
{
	if (!span)
		return;

	if (span->span)
		span->span->End();
	span->scope.reset();
	span->span = nullptr;

	otel_span_top = span->parent;
	span->~otel_span();
	pkg_free(span);
}

static void otel_on_start(int data_type, const char *name, int subtype,
	int depth, void *payload)
{
	struct sip_msg *msg = (struct sip_msg *)payload;

	if (!otel_is_enabled())
		return;

	if (otel_ensure_provider() != 0)
		return;

	if (otel_parent_ctx_set)
		return;

	otel_span_reset();

	otel_span_start(name, subtype, depth, 1, NULL, 0);

	if (otel_span_top && otel_span_top->span) {
		otel_set_msg_attributes(msg, otel_span_top->span.get());
		otel_span_top->span->SetAttribute("sip.raw",
			opentelemetry::nostd::string_view(msg->buf, msg->len));
	}

	(void)msg;
	(void)data_type;
}

static void otel_on_end(int data_type, const char *name, int subtype,
	int depth, int status, void *payload)
{
	if (!otel_is_enabled())
		return;

	if (otel_ensure_provider() != 0)
		return;

	(void)payload;
	(void)data_type;
	(void)name;
	(void)subtype;
	(void)depth;
	(void)status;

	otel_span_reset();
}

static void otel_on_enter(int data_type, const char *name, int subtype,
	int depth, const char *file, int line, void *payload)
{
	if (!otel_is_enabled())
		return;

	if (otel_ensure_provider() != 0)
		return;

	otel_span_start(name ? name : "<route>", subtype, depth, 0, file, line);

	(void)payload;
	(void)data_type;
}

static void otel_on_exit(int data_type, const char *name, int subtype,
	int depth, const char *file, int line, int status, void *payload)
{
	if (!otel_is_enabled())
		return;

	if (otel_ensure_provider() != 0)
		return;

	(void)payload;
	(void)data_type;
	(void)name;
	(void)subtype;
	(void)depth;
	(void)file;
	(void)line;
	(void)status;

	otel_span_end(otel_span_top);
}

static const char *level_to_str(int level)
{
	switch (level) {
	case L_ALERT: return "alert";
	case L_CRIT: return "crit";
	case L_ERR: return "error";
	case L_WARN: return "warn";
	case L_NOTICE: return "notice";
	case L_INFO: return "info";
	case L_DBG: return "debug";
	default: return "unknown";
	}
}

static void otel_log_consumer(int level, int facility, const char *module,
	const char *func, char *format, va_list ap)
{
	char buf[512];
	int len;
	va_list ap_copy;

	if (!otel_is_enabled() || otel_log_in_cb)
		return;

	if (otel_ensure_provider() != 0)
		return;

	if (!otel_span_top)
		return;

	otel_log_in_cb = 1;

	va_copy(ap_copy, ap);
	len = vsnprintf(buf, sizeof(buf), format, ap_copy);
	va_end(ap_copy);

	if (len < 0) {
		otel_log_in_cb = 0;
		return;
	}

	if (len >= (int)sizeof(buf))
		len = sizeof(buf) - 1;

	buf[len] = '\0';

	if (otel_span_top->span) {
		otel_span_top->span->AddEvent("log", {
			{ "log.level", level_to_str(level) },
			{ "log.message", buf }
		});
	}

	(void)facility;
	(void)module;
	(void)func;

	otel_log_in_cb = 0;
}

profiling_handlers_t otel_trace_handlers = {
	.name = "opentelemetry",
	.accepted_data_types = PROFILING_DATA_TYPE_SCRIPT,
	.next = NULL,
	.on_start = otel_on_start,
	.on_end = otel_on_end,
	.on_enter = otel_on_enter,
	.on_exit = otel_on_exit,
	.get_ctx = otel_get_ctx,
	.set_ctx = otel_set_ctx,
};

static const param_export_t params[] = {
	{ "enable", INT_PARAM, &otel_enabled_cfg },
	{ "log_level", INT_PARAM, &otel_log_level },
	{ "use_batch", INT_PARAM, &otel_use_batch },
	{ "service_name", STR_PARAM, &otel_service_name.s },
	{ "exporter_endpoint", STR_PARAM, &otel_exporter_endpoint.s },
	{ 0, 0, 0 }
};

static const mi_export_t mi_cmds[] = {
	{ "enable", 0, 0, 0, {
		{ otel_mi_enable, { "enable", 0 } },
		{ EMPTY_MI_RECIPE }
		}, {"otel_enable", 0}},
	{ EMPTY_MI_EXPORT }
};

extern "C" struct module_exports exports = {
	"opentelemetry",
	MOD_TYPE_DEFAULT,
	{ OPENSIPS_FULL_VERSION, OPENSIPS_COMPILE_FLAGS, { VERSIONTYPE, THISREVISION } },
	DEFAULT_DLFLAGS,
	0,
	0,
	0,
	0,
	params,
	0,
	mi_cmds,
	0,
	0,
	0,
	0,
	mod_init,
	0,
	destroy,
	child_init,
	0
};

static int mod_init(void)
{
	if (!otel_enabled) {
		otel_enabled = (int *)shm_malloc(sizeof(*otel_enabled));
		if (!otel_enabled) {
			LM_ERR("no shm memory for opentelemetry enable\n");
			return -1;
		}
		*otel_enabled = otel_enabled_cfg;
	}

	if (!otel_is_enabled()) {
		LM_INFO("opentelemetry module disabled\n");
	}

	if (otel_service_name.s)
		otel_service_name.len = strlen(otel_service_name.s);
	if (otel_exporter_endpoint.s)
		otel_exporter_endpoint.len = strlen(otel_exporter_endpoint.s);

	/* no provider init here; each process initializes on demand */

	return 0;
}

static int child_init(int rank)
{
	(void)rank;

	otel_span_reset();
	otel_log_in_cb = 0;
	otel_parent_ctx_clear();

	if (!otel_trace_registered) {
		if (register_profiling_handler(&otel_trace_handlers) != 0) {
			LM_ERR("failed to register profiling hooks\n");
			return -1;
		}
		otel_trace_registered = 1;
	}

	if (!otel_log_consumer_registered) {
		if (register_log_consumer(OTEL_CONSUMER_NAME, otel_log_consumer,
			otel_log_level, 0) != 0) {
			LM_ERR("failed to register OpenTelemetry log consumer\n");
			return -1;
		}
		otel_log_consumer_registered = 1;
	}

	if (otel_ensure_provider() != 0)
		return -1;

	return 0;
}

static mi_response_t *otel_mi_enable(const mi_params_t *params,
	struct mi_handler *async_hdl)
{
	mi_response_t *resp;
	mi_item_t *resp_obj;
	int enable;
	int rc;

	(void)async_hdl;

	if (get_mi_int_param(params, "enable", &enable) < 0)
		return init_mi_param_error();

	if (enable != 0 && enable != 1)
		return init_mi_error(400, MI_SSTR("Bad enable value"));

	rc = otel_runtime_set_enable(enable);
	if (rc < 0)
		return init_mi_error(500, MI_SSTR("Failed to update enable"));

	resp = init_mi_result_object(&resp_obj);
	if (!resp)
		return 0;
	if (add_mi_number(resp_obj, MI_SSTR("enabled"), enable) < 0) {
		free_mi_response(resp);
		return 0;
	}

	return resp;
}

static void destroy(void)
{
	if (otel_is_enabled())
		unregister_profiling_handler(&otel_trace_handlers);

	otel_span_reset();
}
