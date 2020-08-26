/*
 * Copyright (C) 2020 OpenSIPS Solutions
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

#ifndef _KAFKA_PROD_H_
#define _KAFKA_PROD_H_

#include <librdkafka/rdkafka.h>

/* producer flags */
#define PROD_INIT			(1<<0)
#define PROD_MSG_KEY_CALLID	(1<<1)

struct s_list {
	char *s;
	struct s_list *next;
};

typedef struct _kafka_producer {
	struct s_list *conf_strings;
	rd_kafka_t *rk;
	rd_kafka_topic_t *rkt;
	rd_kafka_queue_t *rkqu;
	int queue_event_fd[2];  /* socket pair used to poll the kafka event queue */
	int flags;
} kafka_producer_t;

/* broker instance used when publishing directly from script */
typedef struct _script_broker {
	str id;
	kafka_producer_t *prod;
	struct list_head list;
} kafka_broker_t;

enum kafka_job_type {
	KAFKA_JOB_EVI,
	KAFKA_JOB_SCRIPT
};

typedef struct _evi_job_data {
	evi_reply_sock *evi_sock;
	evi_async_ctx_t evi_async_ctx;
} evi_job_data_t;

typedef struct _script_job_data {
	kafka_broker_t *broker;
	int report_rt_idx;
} script_job_data_t;

typedef struct _kafka_job {
	enum kafka_job_type type;
	void *data;  /* evi_job_data_t or script_job_data_t */
	str payload;
	str key;
} kafka_job_t;

struct kafka_report_param {
	kafka_job_t *job;	
	enum evi_status status;
};

void s_list_free(struct s_list *list);
void kafka_process(int rank);
int kafka_create_pipe(void);
void kafka_destroy_pipe(void);
int kafka_init_writer(void);
int kafka_send_job(kafka_job_t *job);
void kafka_evi_destroy(evi_reply_sock *sock);

#endif
