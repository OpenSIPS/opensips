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

#include <librdkafka/rdkafka.h>

#include "../../ut.h"
#include "../../reactor.h"
#include "../../evi/evi_transport.h"
#include "../../route.h"
#include "../../usr_avp.h"
#include "../../lib/list.h"
#include "../../ipc.h"
#include "../../str_list.h"
#include "kafka_producer.h"

#define KAFKA_SEND_JOB_RETRIES 3

#define KAFKA_ENQ_RETRIES 2
#define KAFKA_ENQ_RETRY_TIMEOUT 50 /* ms */
#define KAFKA_FLUSH_TIMEOUT 250 /* ms */

#define QUEUE_EV_MARKER "EeEe"
#define QUEUE_EV_MARKER_LEN (sizeof(QUEUE_EV_MARKER) - 1)

/* reactor FD types */
#define F_KAFKA_JOB -3    /* new job from an worker process */
#define F_KAFKA_EVENT -4  /* new event in librdkafka main event queue */

#define KAFKA_REACTOR_TIMEOUT 1

void dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque);

static int kafka_pipe[2];  /* used to send jobs to the kafka process */

static str rt_id_avp_name = str_init("kafka_id");
static str rt_status_avp_name = str_init("kafka_status");
static str rt_key_avp_name = str_init("kafka_key");
static str rt_msg_avp_name = str_init("kafka_msg");

extern struct list_head *kafka_brokers;

void s_list_free(struct s_list *list)
{
	struct s_list *prev;

	while (list) {
		prev = list;
		list = list->next;

		shm_free(prev);
	}
}

int kafka_create_pipe(void)
{
	int rc;

	kafka_pipe[0] = kafka_pipe[1] = -1;
	do {
		rc = pipe(kafka_pipe);
	} while (rc < 0 && errno == EINTR);

	if (rc < 0) {
		LM_ERR("cannot create status pipe [%d:%s]\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

void kafka_destroy_pipe(void)
{
	if (kafka_pipe[0] != -1)
		close(kafka_pipe[0]);
	if (kafka_pipe[1] != -1)
		close(kafka_pipe[1]);
}

int kafka_init_writer(void)
{
	int flags;

	if (kafka_pipe[0] != -1) {
		close(kafka_pipe[0]);
		kafka_pipe[0] = -1;
	}

	flags = fcntl(kafka_pipe[1], F_GETFL);
	if (flags == -1) {
		LM_ERR("fcntl failed: %s\n", strerror(errno));
		goto error;
	}
	if (fcntl(kafka_pipe[1], F_SETFL, flags | O_NONBLOCK) == -1) {
		LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
		goto error;
	}

	return 0;
error:
	close(kafka_pipe[1]);
	kafka_pipe[1] = -1;
	return -1;
}

static void kafka_init_reader(void)
{
	if (kafka_pipe[1] != -1) {
		close(kafka_pipe[1]);
		kafka_pipe[1] = -1;
	}
}

void kafka_terminate_producer(kafka_producer_t *prod)
{
	LM_DBG("Terminating producer for topic: %s\n", prod->conf_strings->next->s);

	rd_kafka_flush(prod->rk, KAFKA_FLUSH_TIMEOUT);

	reactor_del_reader(prod->queue_event_fd[0], -1, 0);

	close(prod->queue_event_fd[0]);
	prod->queue_event_fd[0] = -1;
	close(prod->queue_event_fd[1]);
	prod->queue_event_fd[0] = -1;

	rd_kafka_queue_destroy(prod->rkqu);
	prod->rkqu = NULL;
	rd_kafka_topic_destroy(prod->rkt);
	prod->rkt = NULL;
	rd_kafka_destroy(prod->rk);
	prod->rk = NULL;

	prod->flags &= ~PROD_INIT;
}

void kafka_evi_destroy(evi_reply_sock *sock)
{
	kafka_producer_t *prod = ((kafka_broker_t *)sock->params)->prod;

	LM_DBG("Freeing socket: %.*s\n", sock->address.len, sock->address.s);

	if (prod->flags & PROD_INIT)
		kafka_terminate_producer(prod);

	s_list_free(prod->conf_strings);

	shm_free(sock);
}

int kafka_send_job(kafka_job_t *job)
{
	int rc;
	int retries = KAFKA_SEND_JOB_RETRIES;

	do {
		rc = write(kafka_pipe[1], &job, sizeof job);
	} while (rc < 0 && (errno == EINTR || retries-- > 0));

	if (rc < 0) {
		LM_ERR("failed to write on pipe\n");
		shm_free(job);
		return -1;
	}

	return 0;
}

static kafka_job_t *kafka_receive_job(void)
{
	int rc;
	int retries = KAFKA_SEND_JOB_RETRIES;
	kafka_job_t *recv;

	if (kafka_pipe[0] == -1)
		return NULL;

	do {
		rc = read(kafka_pipe[0], &recv, sizeof recv);
	} while (rc < 0 && (errno == EINTR || retries-- > 0));

	if (rc < 0) {
		LM_ERR("failed to read from pipe\n");
		return NULL;
	}

	return recv;
}

static int kafka_set_prop(rd_kafka_conf_t *conf, rd_kafka_topic_conf_t *topic_conf,
	char *pname, char *pval)
{
	char errstr[512];

	if (pname[0] == 'g' && pname[1] =='.') {
		if (rd_kafka_conf_set(conf, pname + 2, pval,
			errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
			LM_ERR("Error setting global config property [%s]: %s\n",
				pname + 2, errstr);
			return -1;
		}
	} else if (pname[0] == 't' && pname[1] =='.') {
		if (rd_kafka_topic_conf_set(topic_conf, pname + 2, pval,
			errstr, sizeof(errstr)) != RD_KAFKA_CONF_OK) {
			LM_ERR("Error setting topic config property [%s]: %s\n",
				pname + 2, errstr);
			return -1;
		}
	} else {
		LM_ERR("Unknown property [%s]\n", pname);
		return -1;
	}

	return 0;
}

int kafka_init_conf(struct s_list *conf_strings,
	rd_kafka_conf_t **conf, rd_kafka_topic_conf_t **topic_conf)
{
	char errstr[512];
	struct s_list *conf_s;

	*conf = rd_kafka_conf_new();
	if (!*conf) {
		LM_ERR("Failed to get kafka conf object\n");
		return -1;
	}

	*topic_conf = rd_kafka_topic_conf_new();
	if (!*topic_conf) {
		LM_ERR("Failed to get kafka topic conf object\n");
		goto error;
	}

	conf_s = conf_strings;
	if (rd_kafka_conf_set(*conf, "bootstrap.servers", conf_s->s, errstr,
		sizeof(errstr)) != RD_KAFKA_CONF_OK) {
		LM_ERR("Error setting config property [bootstrap.servers]: %s\n", errstr);
		goto error;
	}

	for (conf_s = conf_s->next->next; conf_s; conf_s = conf_s->next->next)
		kafka_set_prop(*conf, *topic_conf, conf_s->s, conf_s->next->s);

	rd_kafka_conf_set_dr_msg_cb(*conf, dr_msg_cb);

	return 0;

error:
	if (*conf)
		rd_kafka_conf_destroy(*conf);
	if (*topic_conf)
		rd_kafka_topic_conf_destroy(*topic_conf);
	return -1;
}

static int kafka_enq_msg(kafka_job_t *job)
{
	kafka_producer_t *prod;
	kafka_broker_t *broker;
	#if (RD_KAFKA_VERSION >= 0x010001ff)
	rd_kafka_resp_err_t err;
	char errstr[512];
	#endif
	int rc;
	unsigned int retries = KAFKA_ENQ_RETRIES;

	broker = (job->type == KAFKA_JOB_EVI) ?
		((evi_job_data_t *)job->data)->evi_sock->params :
		((script_job_data_t *)job->data)->broker;
	prod = broker->prod;

	do {
		rc = rd_kafka_produce(prod->rkt, RD_KAFKA_PARTITION_UA, RD_KAFKA_MSG_F_COPY,
			job->payload.s, job->payload.len, job->key.s, job->key.len, job);
		if (rc < 0) {
			LM_ERR("Failed to enqueue message for topic (%s): %s\n",
				prod->conf_strings->next->s, rd_kafka_err2str(rd_kafka_last_error()));

			if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
				/* wait for some messages to be delivered from the queue */
				rd_kafka_poll(prod->rk, KAFKA_ENQ_RETRY_TIMEOUT);
			}
			#if (RD_KAFKA_VERSION >= 0x010001ff)
			else if (rd_kafka_last_error() == RD_KAFKA_RESP_ERR__FATAL) {
				err = rd_kafka_fatal_error(prod->rk, errstr, sizeof(errstr));
				LM_ERR("librdkafka fatal error: %s: %s\n",
					rd_kafka_err2name(err), errstr);
				rc = -2;  /* terminate producer instance */
				retries = 0;
			} else {
				retries = 0;
			}
			#endif
		} else {
			LM_DBG("Enqueued message for topic: %s\n", prod->conf_strings->next->s);
		}
	} while (rc < 0 && retries-- > 0);

	return rc;
}

static struct usr_avp * get_report_rt_avps(kafka_job_t *job,
	script_job_data_t *job_data, enum evi_status status)
{
	struct usr_avp *avp, *avp_list = NULL;
	int avp_id;
	int_str val;

	if (parse_avp_spec(&rt_id_avp_name, &avp_id) < 0) {
		LM_ERR("Cannot get AVP ID\n");
		goto error;
	}
	val.s = job_data->broker->id;
	avp = new_avp(AVP_VAL_STR, avp_id, val);

	avp->next = avp_list;
	avp_list = avp;

	if (parse_avp_spec(&rt_status_avp_name, &avp_id) < 0) {
		LM_ERR("Cannot get AVP ID\n");
		goto error;
	}
	val.n = status;
	avp = new_avp(0, avp_id, val);

	avp->next = avp_list;
	avp_list = avp;

	if (parse_avp_spec(&rt_key_avp_name, &avp_id) < 0) {
		LM_ERR("Cannot get AVP ID\n");
		goto error;
	}
	val.s = job->key;
	avp = new_avp(AVP_VAL_STR, avp_id, val);

	avp->next = avp_list;
	avp_list = avp;

	if (parse_avp_spec(&rt_msg_avp_name, &avp_id) < 0) {
		LM_ERR("Cannot get AVP ID\n");
		goto error;
	}
	val.s = job->payload;
	avp = new_avp(AVP_VAL_STR, avp_id, val);

	avp->next = avp_list;
	avp_list = avp;

	return avp_list;

error:
	if (avp_list)
		destroy_avp_list(&avp_list);
	return NULL;
}

void kafka_report_status(int sender, void *param)
{
	struct kafka_report_param *p =
		(struct kafka_report_param *)param;

	if (p->job->type == KAFKA_JOB_EVI) {
		evi_job_data_t *job_data = (evi_job_data_t *)p->job->data;

		job_data->evi_async_ctx.status_cb(job_data->evi_async_ctx.cb_param,
			p->status);
	} else {
		script_job_data_t *job_data = (script_job_data_t *)p->job->data;
		struct sip_msg *req;
		struct usr_avp **old_avps;
		struct usr_avp *report_avps;

		req = get_dummy_sip_msg();
		if (!req) {
			LM_ERR("Failed to get DUMMY SIP msg\n");
			goto free;
		}

		report_avps = get_report_rt_avps(p->job, job_data, p->status);
		if (!report_avps) {
			LM_ERR("Failed to get report route AVPs\n");
			goto free;
		}
		old_avps = set_avp_list(&report_avps);

		set_route_type(REQUEST_ROUTE);
		run_top_route(sroutes->request[job_data->report_rt_idx], req);

		set_avp_list(old_avps);
		destroy_avp_list(&report_avps);

		release_dummy_sip_msg(req);
	}

free:
	shm_free(p->job);
	shm_free(p);
}

static int kafka_dispatch_report(kafka_job_t *job, enum evi_status status)
{
	struct kafka_report_param *report_param;

	if ((job->type == KAFKA_JOB_EVI &&
		((evi_job_data_t *)job->data)->evi_async_ctx.status_cb == NULL) ||
		(job->type == KAFKA_JOB_SCRIPT &&
		((script_job_data_t *)job->data)->report_rt_idx == -1))
		/* no reporting required */
		return 1;

	report_param = shm_malloc(sizeof *report_param);
	if (!report_param) {
		LM_ERR("oom!\n");
		return -1;
	}

	report_param->job = job;
	report_param->status = status;

	return ipc_dispatch_rpc(kafka_report_status, report_param);
}

void dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque)
{
	kafka_job_t *job = (kafka_job_t *)rkmessage->_private;
	enum evi_status status = EVI_STATUS_SUCCESS;
	int rc;

	if (!job) {
		LM_ERR("Invalid kafka job in parameter\n");
		return;
	}

	if (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR) {
		LM_ERR("Failed to deliver message for topic (%s) : %s\n",
			rd_kafka_topic_name(rkmessage->rkt), rd_kafka_err2str(rkmessage->err));
		status = EVI_STATUS_FAIL;
	}

	LM_DBG("message delivery status: %d for topic %s\n",
		status, rd_kafka_topic_name(rkmessage->rkt));

	if ((rc = kafka_dispatch_report(job, status)) < 0)
		LM_ERR("Failed to dispatch status report\n");

	if (rc != 0)
		shm_free(job);
}

static inline int kafka_init_producer(kafka_producer_t *prod)
{
	char errstr[512];
	int flags;
	rd_kafka_conf_t *conf = NULL;
	rd_kafka_topic_conf_t *topic_conf = NULL;

	if (!prod) {
		LM_ERR("Invalid producer instance in evi sock params\n");
		return -1;
	}

	if (!(prod->flags & PROD_INIT)) {
		if (kafka_init_conf(prod->conf_strings, &conf, &topic_conf) < 0) {
			LM_ERR("Failed to init kafka config\n");
			goto error;
		}

		prod->rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf,
			errstr, sizeof(errstr));
		if (!prod->rk) {
			LM_ERR("Failed to create producer instance: %s\n", errstr);
			goto error;
		}
		conf = NULL;

		prod->rkt = rd_kafka_topic_new(prod->rk, prod->conf_strings->next->s,
			topic_conf);
		if (!prod->rkt) {
			LM_ERR("Failed to create topic instance (%s): %s\n",
				prod->conf_strings->next->s, rd_kafka_err2str(rd_kafka_last_error()));
			goto error;
		}
		topic_conf = NULL;

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, prod->queue_event_fd) < 0) {
			LM_ERR("Failed to create socket pair\n");
			goto error;
		}
		/* mark the socket to be passed to librdkafka as non-blocking */
		flags = fcntl(prod->queue_event_fd[1], F_GETFL);
		if (flags == -1) {
			LM_ERR("fcntl failed: %s\n", strerror(errno));
			goto error;
		}
		if (fcntl(prod->queue_event_fd[1], F_SETFL, flags | O_NONBLOCK) == -1) {
			LM_ERR("fcntl: set non-blocking failed: %s\n", strerror(errno));
			goto error;
		}

		if (reactor_add_reader(prod->queue_event_fd[0], F_KAFKA_EVENT,
			RCT_PRIO_ASYNC, prod) < 0) {
			LM_ERR("Failed to add queue event socket to reactor\n");
			goto error;
		}

		prod->rkqu = rd_kafka_queue_get_main(prod->rk);
		rd_kafka_queue_io_event_enable(prod->rkqu, prod->queue_event_fd[1],
			QUEUE_EV_MARKER, QUEUE_EV_MARKER_LEN);

		prod->flags |= PROD_INIT;
	}

	return 0;

error:
	if (prod->queue_event_fd[0] != -1) {
		close(prod->queue_event_fd[0]);
		prod->queue_event_fd[0] = -1;
	}
	if (prod->queue_event_fd[1] != -1) {
		close(prod->queue_event_fd[1]);
		prod->queue_event_fd[0] = -1;
	}
	if (conf)
		rd_kafka_conf_destroy(conf);
	if (topic_conf)
		rd_kafka_topic_conf_destroy(topic_conf);
	if (prod->rkqu) {
		rd_kafka_queue_destroy(prod->rkqu);
		prod->rkqu = NULL;
	}
	if (prod->rkt) {
		rd_kafka_topic_destroy(prod->rkt);
		prod->rkt = NULL;
	}
	if (prod->rk) {
		rd_kafka_destroy(prod->rk);
		prod->rk = NULL;
	}
	return -1;
}

static int kafka_handle_job(kafka_job_t *job)
{
	int rc;
	kafka_producer_t *prod;
	kafka_broker_t *broker;

	if (job->type == KAFKA_JOB_EVI) {
		if (!job->payload.s[0]) {
			/* terminate this producer and free the evi sock */
			kafka_evi_destroy(((evi_job_data_t *)job->data)->evi_sock);
			return 1;
		}

		broker = ((evi_job_data_t *)job->data)->evi_sock->params;
	} else {
		broker = ((script_job_data_t *)job->data)->broker;
	}

	prod = broker->prod;

	if (kafka_init_producer(prod) < 0) {
		LM_ERR("Failed to init producer\n");
		goto report_fail;
	}

	if ((rc = kafka_enq_msg(job)) < 0) {
		if (rc == -2)
			kafka_terminate_producer(prod);
		goto report_fail;
	}

	return 0;

report_fail:
	if ((rc = kafka_dispatch_report(job, EVI_STATUS_FAIL)) < 0)
		LM_ERR("Failed to dispatch status report\n");
	return rc;
}

static void sig_handler(int signo)
{
	struct list_head *it;
	kafka_broker_t *broker;

	switch (signo) {
	case SIGTERM:
		LM_DBG("Terminating kafka process\n");

		list_for_each(it, kafka_brokers) {
			broker = list_entry(it, kafka_broker_t, list);

			if (broker->prod->flags & PROD_INIT)
				kafka_terminate_producer(broker->prod);
			
			s_list_free(broker->prod->conf_strings);
		}
		exit(0);
	default:
	 LM_DBG("caught signal %d\n",signo);
	}
}

static int handle_io(struct fd_map *fm, int idx, int event_type)
{
	kafka_job_t *job;
	kafka_producer_t *prod;
	int bytes_read;
	char buf[QUEUE_EV_MARKER_LEN];

	switch (fm->type) {
	case F_KAFKA_JOB:
		job = kafka_receive_job();
		if (!job) {
			LM_ERR("Cannot receive job\n");
			return 0;
		}

		if (kafka_handle_job(job) != 0)
			shm_free(job);
		break;
	case F_KAFKA_EVENT:
		prod = (kafka_producer_t *)fm->data;

		do {
			bytes_read = read(prod->queue_event_fd[0], buf, QUEUE_EV_MARKER_LEN);
		} while (bytes_read < 0 && errno == EINTR);

		if (bytes_read == QUEUE_EV_MARKER_LEN &&
			!memcmp(buf, QUEUE_EV_MARKER, QUEUE_EV_MARKER_LEN)) {
			/* call delivery report callbacks */
			rd_kafka_poll(((kafka_producer_t *)fm->data)->rk, 0);
		} else {
			LM_ERR("Received bad marker for queue event\n");
		}

		break;
	default:
		LM_CRIT("unknown fd type %d in Kafka worker\n", fm->type);
		return -1;
	}

	return 0;
}

void kafka_process(int rank)
{
	signal(SIGTERM, sig_handler);

	if (init_worker_reactor("Kafka worker", RCT_PRIO_MAX) != 0) {
		LM_CRIT("Failed to init Kafka worker reactor");
		abort();
	}

	kafka_init_reader();

	if (reactor_add_reader(kafka_pipe[0], F_KAFKA_JOB, RCT_PRIO_ASYNC, NULL) < 0) {
		LM_CRIT("Failed to add kafka pipe to reactor\n");
		abort();
	}

	reactor_main_loop(KAFKA_REACTOR_TIMEOUT, out_err, );

out_err:
	destroy_io_wait(&_worker_io);
	abort();
}
