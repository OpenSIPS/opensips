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

#ifndef _SQS_PROD_H_
#define _SQS_PROD_H_
#include <sys/eventfd.h> 
#include "signal.h"
#include "sqs_lib.h"

/* transport protocols name */
#define SQS_NAME	"sqs"
#define SQS_STR	{ SQS_NAME, sizeof(SQS_NAME) - 1}
/* module flag */
#define SQS_FLAG	(int)(1 << 20)
#define SQS_REACTOR_TIMEOUT 1
#define QUEUE_EV_MARKER "EeEe"
#define QUEUE_EV_MARKER_LEN (sizeof(QUEUE_EV_MARKER) - 1)
#define F_SQS_JOB -3    /* new job from an worker process */
#define F_SQS_EVENT -4  /* new event in librdkafka main event queue */

typedef struct _sqs_queue {
	str id;
	str url;
	sqs_config *config;
	struct list_head list;
	struct list_head job_list;
	int event_fd;
} sqs_queue_t;

typedef enum {
		SQS_JOB_SEND,		/* Send message */
		SQS_JOB_SHUTDOWN	/* Shutdown connection */
} sqs_job_type_t;

typedef struct {
	sqs_job_type_t type;
	int message_len;
	char *message;
	sqs_queue_t *queue;
} sqs_job_t;

sqs_queue_t *get_script_url(str *id);
int parse_queue_url(str *queue_url, char **region, char **endpoint);
void sqs_process(int rank);
int sqs_create_pipe(void);
void sqs_destroy_pipe(void);
int sqs_init_writer(void);
int sqs_send_job(sqs_job_t *job);
sqs_job_t *sqs_receive_job(void);
#endif
