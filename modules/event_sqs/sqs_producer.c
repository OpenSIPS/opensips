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

#define SQS_SEND_JOB_RETRIES 3

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
		}
		exit(0);
	default:
		LM_DBG("Caught signal %d\n", signo);
	}

}

int parse_queue_url(str *queue_url, char **region, char **endpoint) {
	char *url_copy, *endpoint_start, *endpoint_end, *region_start, *region_end;
	url_copy = strndup(queue_url->s, queue_url->len);
	if (!url_copy) {
		LM_ERR("Strdup failed!\n");
		return -1;
	}

	endpoint_start = strstr(url_copy, "http");
	if (endpoint_start) {
		endpoint_end = strrchr(endpoint_start, '/');
		if (endpoint_end) {
			*endpoint_end = '\0';
			*endpoint = strdup(endpoint_start);
		}
	}

	LM_DBG("ENDPOINT: %s\n", *endpoint ? *endpoint : "NULL");

	region_start = strstr(url_copy, "://sqs.") + strlen("://sqs.");
	if (region_start) {
		region_end = strchr(region_start, '.');
		if (region_end) {
			*region_end = '\0';
			*region = strdup(region_start);
		}
	}

	LM_DBG("REGION: %s\n", *region ? *region : "NULL");

	free(url_copy);
	return 0;
}

int sqs_init_config(sqs_queue_t *queue) {
	char *region, *endpoint;
	region = NULL;
	endpoint = NULL;
	if (parse_queue_url(&queue->url, &region, &endpoint) != 0) {
		LM_ERR("Failed to parse queue URL\n");
		shm_free(queue->config);
		shm_free(queue);
		return -1;
	}

	if (init_sqs(queue->config, region, endpoint) != 0) {
		LM_ERR("Failed to initialize SQS configuration\n");
		free(region);
		free(endpoint);
		shm_free(queue->config);
		shm_free(queue);
		return -1;
	}

	free(region);
	free(endpoint);
	return 0;
}

sqs_job_t *sqs_prepare_job(sqs_queue_t *queue, str *message_body, sqs_job_type_t job_type) {
	sqs_job_t *job;
	size_t job_size;

	job_size = sizeof(sqs_job_t) + message_body->len;

	job = (sqs_job_t *)shm_malloc(job_size);
	if (!job) {
		LM_ERR("Failed to allocate memory for SQS job\n");
		return NULL;
	}

	job->type = job_type;
	job->message_len = message_body->len;

	job->message = (char *)(job + 1);
	memcpy(job->message, message_body->s, job->message_len);

	job->queue = queue;

	return job;
}

int sqs_send_job(sqs_job_t *job) {
	int rc;
	int retries = SQS_SEND_JOB_RETRIES;

	do {
		rc = write(sqs_pipe[1], &job, sizeof(sqs_job_t *));
	} while (rc < 0 && (errno == EINTR || retries-- > 0));

	if (rc < 0) {
		LM_ERR("Failed to write on pipe %d - %s\n", errno, strerror(errno));
		shm_free(job);
		return -1;
	}

	return 0;
}

sqs_job_t *sqs_receive_job(void) {
	int rc;
	int retries = SQS_SEND_JOB_RETRIES;
	sqs_job_t *recv;

	if (sqs_pipe[0] == -1)
		return NULL;

	do {
		rc = read(sqs_pipe[0], &recv, sizeof(sqs_job_t *));
	} while (rc < 0 && (errno == EINTR || retries-- > 0));

	if (rc < 0) {
		LM_ERR("Failed to read from pipe: %d - %s\n", errno, strerror(errno));
		return NULL;
	}

	return recv;
}

void sqs_destroy_job(sqs_job_t *job) {
	if (!job)
		return;

	shm_free(job);
}

void sqs_process(int rank) {
	int ret;
	struct list_head *it;
	sqs_queue_t *queue;

	suppress_proc_log_event();
	signal(SIGTERM, sig_handler);

	LM_DBG("Starting SQS worker process...\n");

	if (init_worker_reactor("SQS worker", RCT_PRIO_MAX) != 0) {
		LM_CRIT("Failed to init SQS worker reactor\n");
		abort();
	}

	list_for_each(it, sqs_urls) {
		queue = list_entry(it, sqs_queue_t, list);

		ret = sqs_init_config(queue);
		if (ret == -1)
			goto out_err;
	}

	if (reactor_add_reader(sqs_pipe[0], F_SQS_JOB, RCT_PRIO_ASYNC, NULL) < 0) {
		LM_ERR("Failed to add pipe reader to reactor\n");
		abort();
	}

	reactor_main_loop(SQS_REACTOR_TIMEOUT, out_err, );

out_err:
	destroy_io_wait(&_worker_io);
	reset_proc_log_event();
	abort();
}

static int handle_io(struct fd_map *fm, int idx, int event_type) {
	sqs_job_t *job;
	sqs_queue_t *queue;
	int ret;

	switch (fm->type) {
	case F_SQS_JOB:

		job = sqs_receive_job();
		if (!job) {
			LM_ERR("Cannot receive job\n");
			return 0;
		}

		queue = job->queue;

		switch (job->type) {
			case SQS_JOB_SEND:

				if (!queue->config) {
					LM_DBG("Queue not found. Initializing new queue for URL: %.*s\n", job->queue->url.len, job->queue->url.s);

					queue->url.s = job->queue->url.s;
					queue->url.len = job->queue->url.len;

					queue->config = shm_malloc(sizeof(sqs_config));
					if (!queue->config) {
						LM_ERR("Failed to allocate memory for SQS config\n");
						goto out_err;
					}

					ret = sqs_init_config(queue);
					if (ret == -1)
						goto out_err;
				}

				if (sqs_send_message(queue->config, queue->url, (str) {job->message, job->message_len}) != 0) {
					LM_ERR("Failed to send message to SQS\n");
				}
				break;

			case SQS_JOB_SHUTDOWN:
				if (queue->config) {
					shutdown_sqs(queue->config);
					shm_free(queue->config);
					queue->config = NULL;
					LM_DBG("SQS connection for URL: %.*s shut down\n", queue->url.len, queue->url.s);
				} else {
					LM_DBG("SQS connection for URL: %.*s was not active, nothing to shut down\n", queue->url.len, queue->url.s);
				}
				break;

			default:
				LM_ERR("Unknown job type received\n");
				goto out_err;
		}
		shm_free(job);
		break;

	default:
		LM_CRIT("unknown fd type %d in SQS worker\n", fm->type);
		return -1;
	}

	return 0;

out_err:
	sqs_destroy_job(job);
	return -1;
}
