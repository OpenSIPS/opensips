/*
 * Copyright (C) 2024 OpenSIPS Solutions
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
 *
 *
 */


#include "../../ut.h"
#include "../../evi/evi_transport.h"
#include "../../route.h"
#include "../../reactor.h"
#include "../../usr_avp.h"
#include "../../lib/list.h"
#include "../../ipc.h"
#include "../../str_list.h"
#include "sqs_producer.h"

extern struct list_head *sqs_urls;

extern int sqs_pipe[2];  /* used to send jobs to the sqs process */

int sqs_create_pipe(void)
{
	int rc;

	sqs_pipe[0] = sqs_pipe[1] = -1;
	do {
		rc = pipe(sqs_pipe);
	} while (rc < 0 && errno == EINTR);

	if (rc < 0) {
		LM_ERR("cannot create status pipe [%d:%s]\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

void sqs_destroy_pipe(void)
{
	if (sqs_pipe[0] != -1)
		close(sqs_pipe[0]);
	if (sqs_pipe[1] != -1)
		close(sqs_pipe[1]);
}

int sqs_init_writer(void)
{
	int flags;

	if (sqs_pipe[0] != -1) {
		close(sqs_pipe[0]);
		sqs_pipe[0] = -1;
	}

	flags = fcntl(sqs_pipe[1], F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed: %s\n", strerror(errno));
		goto error;
	}
	if (fcntl(sqs_pipe[1], F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
		goto error;
	}

	return 0;
error:
	close(sqs_pipe[1]);
	sqs_pipe[1] = -1;
	return -1;
}

static void sig_handler(int signo) {
	struct list_head *it;
	sqs_queue_t *queue;

	switch (signo) {
	case SIGTERM:
		LM_DBG("Terminating SQS process\n");

		list_for_each(it, sqs_urls) {
			queue = list_entry(it, sqs_queue_t, list);
			if (queue->config) {
				shutdown_sqs(queue->config);
			}

			shm_free(queue->config);
			shm_free(queue);
		}
		exit(0);
	default:
		LM_DBG("Caught signal %d\n", signo);
	}

}

static int parse_queue_url(str *queue_url, char **region, char **endpoint) {
	char *url_copy = strndup(queue_url->s, queue_url->len);
	if (!url_copy) {
		LM_ERR("Strdup failed!\n");
		return -1;
	}

	char *endpoint_start = strstr(url_copy, "http");
	if (endpoint_start) {
		char *endpoint_end = strrchr(endpoint_start, '/');
		if (endpoint_end) {
			*endpoint_end = '\0';
			*endpoint = strdup(endpoint_start);
		}
	}

	LM_NOTICE("ENDPOINT: %s\n", *endpoint ? *endpoint : "NULL");

	char *region_start = strstr(url_copy, "://sqs.") + strlen("://sqs.");
	if (region_start) {
		char *region_end = strchr(region_start, '.');
		if (region_end) {
			*region_end = '\0';
			*region = strdup(region_start);
		}
	}

	LM_NOTICE("REGION: %s\n", *region ? *region : "NULL");

	free(url_copy);
	return 0;
}

void sqs_process(int rank) {
	suppress_proc_log_event();
	signal(SIGTERM, sig_handler);

	LM_NOTICE("Starting SQS worker process...\n");

	if (init_worker_reactor("SQS worker", RCT_PRIO_MAX) != 0) {
		LM_CRIT("Failed to init SQS worker reactor\n");
		abort();
	}

	struct list_head *it;
	sqs_queue_t *queue;

	list_for_each(it, sqs_urls) {
		queue = list_entry(it, sqs_queue_t, list);

		char *region = NULL;
		char *endpoint = NULL;
		if (parse_queue_url(&queue->url, &region, &endpoint) != 0) {
			LM_ERR("Failed to parse queue URL\n");
			shm_free(queue->config);
			shm_free(queue);
			return;
		}

		init_sqs(queue->config, region, endpoint);
		free(region);
		free(endpoint);

		if (reactor_add_reader(sqs_pipe[0], F_SQS_JOB, RCT_PRIO_ASYNC, NULL) < 0) {
			LM_ERR("Failed to add pipe reader to reactor\n");
			abort();
		}
	}

	reactor_main_loop(SQS_REACTOR_TIMEOUT, out_err, );

out_err:
	destroy_io_wait(&_worker_io);
	reset_proc_log_event();
	abort();
}


static int handle_io(struct fd_map *fm, int idx, int event_type) {
	sqs_queue_t *queue;
	int bytes_read;
	int queue_len, body_len;
	char *queue_str, *body_str;
	str queue_id, message_body;

	switch (fm->type) {
	case F_SQS_JOB:

		bytes_read = read(sqs_pipe[0], &queue_len, sizeof(int));
		if (bytes_read != sizeof(int)) {
			LM_ERR("Failed to read queue length from pipe, error: %s\n", strerror(errno));
			return -1;
		}

		bytes_read = read(sqs_pipe[0], &body_len, sizeof(int));
		if (bytes_read != sizeof(int)) {
			LM_ERR("Failed to read body length from pipe, error: %s\n", strerror(errno));
			return -1;
		}

		queue_str = (char *)malloc(queue_len);
		body_str = (char *)malloc(body_len);
		if (!queue_str || !body_str) {
			LM_ERR("Failed to allocate memory for strings\n");
			return -1;
		}

		bytes_read = read(sqs_pipe[0], queue_str, queue_len);
		if (bytes_read != queue_len) {
			LM_ERR("Failed to read queue string from pipe, error: %s\n", strerror(errno));
			free(queue_str);
			free(body_str);
			return -1;
		}

		bytes_read = read(sqs_pipe[0], body_str, body_len);
		if (bytes_read != body_len) {
			LM_ERR("Failed to read body string from pipe, error: %s\n", strerror(errno));
			free(queue_str);
			free(body_str);
			return -1;
		}

		queue_id.s = queue_str;
		queue_id.len = queue_len;
		message_body.s = body_str;
		message_body.len = body_len;

		queue = get_script_url(&queue_id);
		if (!queue) {
			LM_ERR("Unknown queue id: %.*s\n", queue_id.len, queue_id.s);
			free(queue_str);
			free(body_str);
			return -1;
		}
		
		int result = sqs_send_message(queue->config, queue->url, message_body);
		if (result != 0) {
			LM_ERR("Failed to send message to SQS\n");
		}

		free(queue_str);
		free(body_str);

		break;
	default:
		LM_ERR("Unknown fd type %d in SQS worker\n", fm->type);
		return -1;
	}

	return 0;
}

