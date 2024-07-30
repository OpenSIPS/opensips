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
 */


#include <aws/core/Aws.h>
#include <aws/dynamodb/DynamoDBClient.h>
#include <aws/dynamodb/model/AttributeDefinition.h>
#include <aws/dynamodb/model/CreateTableRequest.h>
#include <aws/dynamodb/model/KeySchemaElement.h>
#include <aws/dynamodb/model/ProvisionedThroughput.h>
#include <aws/dynamodb/model/ScalarAttributeType.h>
#include <aws/dynamodb/model/PutItemRequest.h>
#include <aws/dynamodb/model/DeleteItemRequest.h>
#include <aws/dynamodb/model/QueryRequest.h>
#include <aws/dynamodb/model/ScanRequest.h>
#include <aws/dynamodb/model/GetItemRequest.h>
#include <aws/dynamodb/model/UpdateItemRequest.h>
#include <aws/dynamodb/model/UpdateItemResult.h>
#include <iostream>
#include <sstream>
#include "dynamodb_lib.h"




extern "C" {

int init_dynamodb(dynamodb_con* con) {
	dynamodb_config config;
	Aws::SDKOptions* options = new Aws::SDKOptions();
	if (options == NULL) {
		return -1;
	}
	Aws::InitAPI(*options);

	config.options = options;
	config.clientConfig = NULL;

	Aws::Client::ClientConfiguration* clientConfig = new Aws::Client::ClientConfiguration();
	if (clientConfig == NULL) {
		Aws::ShutdownAPI(*options);
		delete(options);
		return -1;
	}

	if (con->endpoint.s != NULL) {
		clientConfig->endpointOverride = std::string(con->endpoint.s, con->endpoint.len);
	} else if (con->region.s != NULL) {
		clientConfig->region = std::string(con->region.s, con->region.len);
	} else {
		Aws::ShutdownAPI(*options);
		delete(options);
		return -1;
	}

	config.clientConfig = clientConfig;
	con->config = config;
	return 0;
}


void shutdown_dynamodb(dynamodb_config *config) {
	Aws::SDKOptions *options = static_cast<Aws::SDKOptions*>(config->options);
	Aws::ShutdownAPI(*options);

	delete static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	delete options;
}

int insert_item_dynamodb(dynamodb_config *config,
				const str tableName,
				const str partitionKey,
				const str partitionValue,
				const str attributeName,
				const str attributeValue,
				int ttl) {
	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);

	Aws::DynamoDB::Model::UpdateItemRequest request;
	request.SetTableName(std::string(tableName.s, tableName.len));

	Aws::DynamoDB::Model::AttributeValue partitionKeyValue;	
	partitionKeyValue.SetS(std::string(partitionValue.s, partitionValue.len));
	request.AddKey(std::string(partitionKey.s, partitionKey.len), partitionKeyValue);

	Aws::String updateExpression = "SET #attrName = :attrValue";
	Aws::Map<Aws::String, Aws::String> expressionAttributeNames;
	expressionAttributeNames["#attrName"] = std::string(attributeName.s, attributeName.len);

	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> expressionAttributeValues;
	Aws::DynamoDB::Model::AttributeValue attributeValueObj;

	attributeValueObj.SetS(std::string(attributeValue.s, attributeValue.len));
	expressionAttributeValues[":attrValue"] = attributeValueObj;

	if (ttl > 0) {
		updateExpression += ", #ttl = :ttlValue";
		expressionAttributeNames["#ttl"] = DYNAMODB_TTL_S;
		Aws::DynamoDB::Model::AttributeValue ttlValueObj;
		ttlValueObj.SetN(std::to_string(time(NULL) + ttl));
		expressionAttributeValues[":ttlValue"] = ttlValueObj;
	}

	request.SetUpdateExpression(updateExpression);
	request.SetExpressionAttributeNames(expressionAttributeNames);
	request.SetExpressionAttributeValues(expressionAttributeValues);

	const Aws::DynamoDB::Model::UpdateItemOutcome &outcome = dynamoClient.UpdateItem(request);
	if (!outcome.IsSuccess()) {
		std::cerr << "Failed to update item: " << outcome.GetError().GetMessage() << std::endl;
		return -1;
	}
	return 0;
}

int delete_item_dynamodb(dynamodb_config *config,
						 const str tableName,
						 const str partitionKey,
						 const str partitionValue) {
	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);

	Aws::DynamoDB::Model::DeleteItemRequest request;
	request.AddKey(std::string(partitionKey.s, partitionKey.len), Aws::DynamoDB::Model::AttributeValue().SetS(std::string(partitionValue.s, partitionValue.len)));
	request.SetTableName(std::string(tableName.s, tableName.len));

	const Aws::DynamoDB::Model::DeleteItemOutcome &outcome = dynamoClient.DeleteItem(request);
	if (!outcome.IsSuccess()) {
		std::cerr << "Failed to delete item: " << outcome.GetError().GetMessage() << std::endl;
		return -1;
	}
	return 0;
}

query_item_t* query_item_dynamodb(dynamodb_config *config,
								  const str tableName,
								  const str partitionKey,
								  const str partitionValue,
								  const str attributeKey) {

	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);
	Aws::DynamoDB::Model::QueryRequest request;

	query_item_t *result = new query_item_t;
	result->str = nullptr;
	result->number = 0;
	result->type = query_item_t::NULL_TYPE;

	request.SetTableName(std::string(tableName.s, tableName.len));
	request.SetKeyConditionExpression("#keyToMatch = :valueToMatch");

	Aws::Map<Aws::String, Aws::String> keyValues;
	keyValues.emplace("#keyToMatch", std::string(partitionKey.s, partitionKey.len));
	request.SetExpressionAttributeNames(keyValues);

	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> attributeValues;
	attributeValues.emplace(":valueToMatch", Aws::DynamoDB::Model::AttributeValue().SetS(std::string(partitionValue.s, partitionValue.len)));
	request.SetExpressionAttributeValues(attributeValues);

	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> exclusiveStartKey;
	do {
		if (!exclusiveStartKey.empty()) {
			request.SetExclusiveStartKey(exclusiveStartKey);
			exclusiveStartKey.clear();
		}
		const Aws::DynamoDB::Model::QueryOutcome &outcome = dynamoClient.Query(request);
		if (outcome.IsSuccess()) {
			const Aws::Vector<Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue>> &items = outcome.GetResult().GetItems();
			if (!items.empty()) {
				for (const auto &item : items) {
					const auto &attribute = item.find(std::string(attributeKey.s, attributeKey.len));
					if (attribute != item.end()) {
						if (attribute->second.GetS() != "") {
							std::string strValue = attribute->second.GetS();
							result->str = new str;
							result->str->len = strValue.length();
							result->str->s = new char[result->str->len + 1];
							std::strcpy(result->str->s, strValue.c_str());
							result->type = query_item_t::STR_TYPE;
						}
						if (attribute->second.GetN() != "") {
							result->number = std::stoi(attribute->second.GetN());
							result->type = query_item_t::INT_TYPE;
						}
					} else {
						std::cout << "Not found" << std::endl;
					}
				}
			} else {
				std::cerr << "No item found in table: " << std::endl;
			}
			exclusiveStartKey = outcome.GetResult().GetLastEvaluatedKey();
		} else {
			std::cerr << "Failed to Query items: " << outcome.GetError().GetMessage() << std::endl;
			return NULL;
		}
	} while (!exclusiveStartKey.empty());

	return result;
}

query_result_t* query_items_dynamodb(dynamodb_config *config,
									 const str tableName,
									 const str partitionKey,
									 const str partitionValue) {
	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);
	Aws::DynamoDB::Model::QueryRequest request;

	request.SetTableName(std::string(tableName.s, tableName.len));
	request.SetKeyConditionExpression("#keyToMatch = :valueToMatch");

	Aws::Map<Aws::String, Aws::String> keyValues;
	keyValues.emplace("#keyToMatch", std::string(partitionKey.s, partitionKey.len));
	request.SetExpressionAttributeNames(keyValues);

	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> attributeValues;
	attributeValues.emplace(":valueToMatch", std::string(partitionValue.s, partitionValue.len));
	request.SetExpressionAttributeValues(attributeValues);

	query_result_t *queryResult = new query_result_t;
	queryResult->num_rows = 0;
	queryResult->items = nullptr;

	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> exclusiveStartKey;
	do {
		if (!exclusiveStartKey.empty()) {
			request.SetExclusiveStartKey(exclusiveStartKey);
			exclusiveStartKey.clear();
		}
		const Aws::DynamoDB::Model::QueryOutcome &outcome = dynamoClient.Query(request);
		if (outcome.IsSuccess()) {
			const Aws::Vector<Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue>> &items = outcome.GetResult().GetItems();
			for (const auto &item : items) {
				rows_t row;
				row.no_attributes = item.size();
				row.key = strdup(std::string(partitionKey.s, partitionKey.len).c_str());
				if (!row.key) {
					std::cerr << "Strdup failed\n" << std::endl;
					return NULL;
				}

				row.key_value = strdup(std::string(partitionValue.s, partitionValue.len).c_str());
				if (!row.key_value) {
					std::cerr << "Strdup failed\n" << std::endl;
					return NULL;
				}

				row.attributes = new key_value_pair_t[item.size()];

				int attribute_index = 0;
				for (const auto &i : item) {
					row.attributes[attribute_index].key = strdup(i.first.c_str());
					if (!row.attributes[attribute_index].key) {
						std::cerr << "Strdup failed\n" << std::endl;
						return NULL;
					}

					if (i.second.GetS() != "") {
						row.attributes[attribute_index].value = strdup(i.second.GetS().c_str());
						if (!row.attributes[attribute_index].value) {
							std::cerr << "Strdup failed\n" << std::endl;
							return NULL;
						}

					} else if (i.second.GetN() != "") {
						row.attributes[attribute_index].value = strdup(i.second.GetN().c_str());
						if (!row.attributes[attribute_index].value) {
							std::cerr << "Strdup failed\n" << std::endl;
							return NULL;
						}
					} else {
					row.attributes[attribute_index].value = nullptr;
					}
					++attribute_index;
				}

				rows_t *new_items = new rows_t[queryResult->num_rows + 1];
				if (queryResult->items != nullptr) {
					std::copy(queryResult->items, queryResult->items + queryResult->num_rows, new_items);
					delete[] queryResult->items;
				}
				queryResult->items = new_items;
				queryResult->items[queryResult->num_rows] = row;
				++queryResult->num_rows;
			}
			exclusiveStartKey = outcome.GetResult().GetLastEvaluatedKey();
		} else {
			std::cerr << "Failed to Query items: " << outcome.GetError().GetMessage() << std::endl;
			if (queryResult->items != nullptr) {
				for (int i = 0; i < queryResult->num_rows; ++i) {
					delete[] queryResult->items[i].attributes;
				}
				delete[] queryResult->items;
			}
			delete queryResult;
			return nullptr;
		}
	} while (!exclusiveStartKey.empty());

	return queryResult;
}


query_result_t *scan_table_dynamodb(dynamodb_config *config,
									const str tableName,
									const str key) {

	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);
	Aws::DynamoDB::Model::ScanRequest request;
	request.SetTableName(std::string(tableName.s, tableName.len));

	query_result_t *result = new query_result_t;
	result->num_rows = 0;
	result->items = nullptr;

	std::vector<rows_t> rows;

	do {
		const Aws::DynamoDB::Model::ScanOutcome &outcome = dynamoClient.Scan(request);
		if (outcome.IsSuccess()) {
			const Aws::Vector<Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue>>& items = outcome.GetResult().GetItems();

			for (const auto &itemMap : items) {
				rows_t row;
				row.no_attributes = itemMap.size() - 1;
				row.attributes = new key_value_pair_t[row.no_attributes];
				int attr_index = 0;

				for (const auto &itemEntry : itemMap) {
					if (itemEntry.first == std::string(key.s, key.len)) {
						row.key = strdup(itemEntry.first.c_str());
						if (!row.key) {
							std::cerr << "Strdup failed\n" << std::endl;
							return NULL;
						}

						row.key_value = strdup(itemEntry.second.GetS().c_str());
						if (!row.key_value) {
							std::cerr << "Strdup failed\n" << std::endl;
							return NULL;
						}

					} else {
						row.attributes[attr_index].key = strdup(itemEntry.first.c_str());
						if (!row.attributes[attr_index].key) {
							std::cerr << "Strdup failed\n" << std::endl;
							return NULL;
						}

						if (itemEntry.second.GetS() != "") {

							row.attributes[attr_index].value = strdup(itemEntry.second.GetS().c_str());
							if (!row.attributes[attr_index].value) {
								std::cerr << "Strdup failed\n" << std::endl;
								return NULL;
							}

						} else if (itemEntry.second.GetN() != "") {

							row.attributes[attr_index].value = strdup(itemEntry.second.GetN().c_str());
							if (!row.attributes[attr_index].value) {
								std::cerr << "Strdup failed\n" << std::endl;
								return NULL;
							}

						} else {

							row.attributes[attr_index].value = nullptr;

						}
						attr_index++;
					}

				}

				rows.push_back(row);
			}
			request.SetExclusiveStartKey(outcome.GetResult().GetLastEvaluatedKey());
		} else {
			std::cerr << "Failed to Scan items: " << outcome.GetError().GetMessage() << std::endl;
			delete result;
			return nullptr;
		}
	} while (!request.GetExclusiveStartKey().empty());

	result->num_rows = rows.size();
	result->items = new rows_t[result->num_rows];
	for (int i = 0; i < result->num_rows; ++i) {
		result->items[i] = rows[i];
	}

	return result;
}

int *update_item_inc_dynamodb(dynamodb_config *config,
							  const str tableName,
							  const str partitionKey,
							  const str partitionValue,
							  const str valueKey,
							  int incrementValue,
							  int ttl) {
	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);

	Aws::DynamoDB::Model::GetItemRequest getItemRequest;
	getItemRequest.SetTableName(std::string(tableName.s, tableName.len));
	std::string partitionValue_string = std::string(partitionValue.s, partitionValue.len);
	getItemRequest.AddKey(std::string(partitionKey.s, partitionKey.len), Aws::DynamoDB::Model::AttributeValue(partitionValue_string));

	const Aws::DynamoDB::Model::GetItemOutcome &getItemOutcome = dynamoClient.GetItem(getItemRequest);
	if (!getItemOutcome.IsSuccess()) {
		std::cerr << getItemOutcome.GetError().GetMessage() << std::endl;
		return NULL;
	}

	const Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> &item = getItemOutcome.GetResult().GetItem();
	if (item.empty()) {
		std::cerr << "Item not found." << std::endl;
		return NULL;
	}

	int currentValue = 0;
	const auto &attributeIter = item.find(std::string(valueKey.s, valueKey.len));
	if (attributeIter != item.end() && attributeIter->second.GetType() == Aws::DynamoDB::Model::ValueType::STRING) {
		try {
			currentValue = std::stoi(attributeIter->second.GetS());
		} catch (const std::exception &e) {
			std::cerr << "Error converting current value to integer: " << e.what() << std::endl;
			return NULL;
		}
	} else {
		std::cerr << "Attribute not found or not a string." << std::endl;
		return NULL;
	}

	int *newValue = new int;
	*newValue = currentValue + incrementValue;

	Aws::DynamoDB::Model::UpdateItemRequest updateRequest;
	updateRequest.SetTableName(std::string(tableName.s, tableName.len));
	updateRequest.AddKey(std::string(partitionKey.s, partitionKey.len), Aws::DynamoDB::Model::AttributeValue(partitionValue_string));

	Aws::String update_expression = "SET #valKey = :newval";
	Aws::Map<Aws::String, Aws::String> expressionAttributeNames;
	expressionAttributeNames["#valKey"] = std::string(valueKey.s, valueKey.len);

	Aws::DynamoDB::Model::AttributeValue newValueAttribute;
	newValueAttribute.SetN(std::to_string(*newValue));
	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> expressionAttributeValues;
	expressionAttributeValues[":newval"] = newValueAttribute;

	if (ttl > 0) {
		update_expression += ", #ttl = :ttlValue";
		expressionAttributeNames["#ttl"] = DYNAMODB_TTL_S;
		Aws::DynamoDB::Model::AttributeValue ttlValueObj;
		ttlValueObj.SetN(std::to_string(time(NULL) + ttl));
		expressionAttributeValues[":ttlValue"] = ttlValueObj;
	}
	updateRequest.SetUpdateExpression(update_expression);
	updateRequest.SetExpressionAttributeNames(expressionAttributeNames);
	updateRequest.SetExpressionAttributeValues(expressionAttributeValues);

	const Aws::DynamoDB::Model::UpdateItemOutcome &updateOutcome = dynamoClient.UpdateItem(updateRequest);
	if (!updateOutcome.IsSuccess()) {
		std::cerr << updateOutcome.GetError().GetMessage() << std::endl;
		return NULL;
	}

	return newValue;
}

int *update_item_sub_dynamodb(dynamodb_config *config,
							  const str tableName,
							  const str partitionKey,
							  const str partitionValue,
							  const str valueKey,
							  int decrementValue,
							  int ttl) {
	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);

	Aws::DynamoDB::Model::GetItemRequest getItemRequest;
	getItemRequest.SetTableName(std::string(tableName.s, tableName.len));
	std::string partitionValue_string = std::string(partitionValue.s, partitionValue.len);
	getItemRequest.AddKey(std::string(partitionKey.s, partitionKey.len), Aws::DynamoDB::Model::AttributeValue(partitionValue_string));

	const Aws::DynamoDB::Model::GetItemOutcome &getItemOutcome = dynamoClient.GetItem(getItemRequest);
	if (!getItemOutcome.IsSuccess()) {
		std::cerr << getItemOutcome.GetError().GetMessage() << std::endl;
		return NULL;
	}

	const Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> &item = getItemOutcome.GetResult().GetItem();
	if (item.empty()) {
		std::cout << "Item not found." << std::endl;
		return NULL;
	}

	int currentValue = 0;
	const auto &attributeIter = item.find(std::string(valueKey.s, valueKey.len));
	if (attributeIter != item.end() && attributeIter->second.GetType() == Aws::DynamoDB::Model::ValueType::STRING) {
		try {
			currentValue = std::stoi(attributeIter->second.GetS());
		} catch (const std::exception &e) {
			std::cerr << "Error converting current value to integer: " << e.what() << std::endl;
			return NULL;
		}
	} else {
		std::cerr << "Attribute not found or not a string." << std::endl;
		return NULL;
	}

	int *newValue = new int;
	*newValue = currentValue - decrementValue;

	Aws::DynamoDB::Model::UpdateItemRequest updateRequest;
	updateRequest.SetTableName(std::string(tableName.s, tableName.len));
	updateRequest.AddKey(std::string(partitionKey.s, partitionKey.len), Aws::DynamoDB::Model::AttributeValue(partitionValue_string));

	Aws::String update_expression = "SET #valKey = :newval";
	Aws::Map<Aws::String, Aws::String> expressionAttributeNames;
	expressionAttributeNames["#valKey"] = std::string(valueKey.s, valueKey.len);

	Aws::DynamoDB::Model::AttributeValue newValueAttribute;
	newValueAttribute.SetN(std::to_string(*newValue));
	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> expressionAttributeValues;
	expressionAttributeValues[":newval"] = newValueAttribute;

	if (ttl > 0) {
		update_expression += ", #ttl = :ttlValue";
		expressionAttributeNames["#ttl"] = "ttl";
		Aws::DynamoDB::Model::AttributeValue ttlValueObj;
		ttlValueObj.SetN(std::to_string(time(NULL) + ttl));
		expressionAttributeValues[":ttlValue"] = ttlValueObj;
	}

	updateRequest.SetUpdateExpression(update_expression);
	updateRequest.SetExpressionAttributeNames(expressionAttributeNames);
	updateRequest.SetExpressionAttributeValues(expressionAttributeValues);

	const Aws::DynamoDB::Model::UpdateItemOutcome &updateOutcome = dynamoClient.UpdateItem(updateRequest);
	if (!updateOutcome.IsSuccess()) {
		std::cerr << updateOutcome.GetError().GetMessage() << std::endl;
		return NULL;
	}

	return newValue;
}

}
