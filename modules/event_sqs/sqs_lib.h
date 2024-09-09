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

#ifndef SQS_LIB
#define SQS_LIB


#include "../../str.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	void *options;
	void *clientConfig;
} sqs_config;

int init_sqs(sqs_config *config, const char* region, const char* endpoint);
void shutdown_sqs(sqs_config *config);
int sqs_send_message(sqs_config *config, str queueUrl, str messageBody);

#ifdef __cplusplus
}
#endif
#endif // SQS_LIB
