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

void init_sqs(sqs_config *config) {
	config->options = new Aws::SDKOptions();
	Aws::InitAPI(*reinterpret_cast<Aws::SDKOptions*>(config->options));
	config->clientConfig = new Aws::Client::ClientConfiguration();
	reinterpret_cast<Aws::Client::ClientConfiguration*>(config->clientConfig)->region = "u-east-1";
	reinterpret_cast<Aws::Client::ClientConfiguration*>(config->clientConfig)->endpointOverride = "http://localhost:4566";
}

void shutdown_sqs(sqs_config *config) {
	Aws::ShutdownAPI(*reinterpret_cast<Aws::SDKOptions*>(config->options));
	delete reinterpret_cast<Aws::SDKOptions*>(config->options);
	delete reinterpret_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
}


int sqs_send_message(sqs_config *config, str queueUrl, str messageBody) {
	Aws::SQS::SQSClient sqsClient(*reinterpret_cast<Aws::Client::ClientConfiguration*>(config->clientConfig));

	Aws::SQS::Model::SendMessageRequest request;
	request.SetQueueUrl(std::string(queueUrl.s, queueUrl.len));
	request.SetMessageBody(std::string(messageBody.s, messageBody.len));

	const Aws::SQS::Model::SendMessageOutcome outcome = sqsClient.SendMessage(request);
	if (outcome.IsSuccess()) {
		LM_NOTICE("Successfully sent message to %.*s\n", queueUrl.len, queueUrl.s);
		return 0;
	} else {
		LM_ERR("Error sending message to %.*s: %s\n", queueUrl.len, queueUrl.s, outcome.GetError().GetMessage().c_str());
		return -1;
	}
}

}
