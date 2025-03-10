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

#include <aws/core/Aws.h>
#include <aws/sqs/SQSClient.h>
#include <aws/sqs/model/CreateQueueRequest.h>
#include <aws/sqs/model/DeleteQueueRequest.h>
#include <aws/sqs/model/GetQueueUrlRequest.h>
#include <aws/sqs/model/ListQueuesRequest.h>
#include <aws/sqs/model/SendMessageRequest.h>
#include <aws/sqs/model/ReceiveMessageRequest.h>
#include <aws/sqs/model/DeleteMessageRequest.h>
#include <iostream>
#include "sqs_lib.h"

extern "C" {
#include "../../dprint.h"

int init_sqs(sqs_config *config, const char* region, const char* endpoint) {
	Aws::SDKOptions* options = new Aws::SDKOptions();
	if (options == NULL) {
		return -1;
	}
	Aws::InitAPI(*options);

	Aws::Client::ClientConfiguration* clientConfig = new Aws::Client::ClientConfiguration();
	if (clientConfig == NULL) {
		Aws::ShutdownAPI(*options);
		delete(options);
		return -1;
	}

	clientConfig->region = region ? region : "";
	clientConfig->endpointOverride = endpoint ? endpoint : "";
	if(!strcmp(clientConfig->region.c_str(), "") && !strcmp(clientConfig->endpointOverride.c_str(), "")) {
		Aws::ShutdownAPI(*options);
		delete(options);
		return -1;
	}

	config->clientConfig = clientConfig;
	config->options = options;

	return 0;
}
void shutdown_sqs(sqs_config *config) {
	Aws::SDKOptions *options = static_cast<Aws::SDKOptions*>(config->options);
	Aws::ShutdownAPI(*options);

	delete static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	delete options;
}

int sqs_send_message(sqs_config *config, str queueUrl, str messageBody) {
	Aws::SQS::SQSClient sqsClient(*reinterpret_cast<Aws::Client::ClientConfiguration*>(config->clientConfig));

	Aws::SQS::Model::SendMessageRequest request;
	request.SetQueueUrl(std::string(queueUrl.s, queueUrl.len));
	request.SetMessageBody(std::string(messageBody.s, messageBody.len));

	const Aws::SQS::Model::SendMessageOutcome outcome = sqsClient.SendMessage(request);
	if (outcome.IsSuccess()) {
		LM_DBG("Successfully sent message to %.*s\n", queueUrl.len, queueUrl.s);
		return 0;
	}

	LM_ERR("Error sending message to %.*s: %s\n", queueUrl.len, queueUrl.s, outcome.GetError().GetMessage().c_str());
	return -1;
}

}
