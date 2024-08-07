#ifndef SQS_LIB
#define SQS_LIB
#include <stdbool.h>


#include "../../str.h"
#include "../../lib/list.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _sqs_broker {
	str id;
	str queue_url;
	struct list_head list;
} sqs_broker_t;


typedef struct {
	void *options;
	void *clientConfig;
} sqs_config;

void init_sqs(sqs_config *config);
void shutdown_sqs(sqs_config *config);

int sqs_send_message(sqs_config *config, str queueUrl, str messageBody);

#ifdef __cplusplus
}
#endif
#endif // SQS_LIB
