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

dynamodb_config init_dynamodb(dynamodb_con *con) {
	dynamodb_config config;
	Aws::SDKOptions *options = new Aws::SDKOptions();
	Aws::InitAPI(*options);

	Aws::Client::ClientConfiguration *clientConfig = new Aws::Client::ClientConfiguration();

	config.options = options;
	config.clientConfig = clientConfig;

	if(con->endpoint != NULL) {
		clientConfig->endpointOverride = con->endpoint;
	} else if(con->region != NULL) {
		clientConfig->region = con->region;
	} else {
		exit(-1);
	}

	return config;
}

void shutdown_dynamodb(dynamodb_config *config) {
	Aws::SDKOptions *options = static_cast<Aws::SDKOptions*>(config->options);
	Aws::ShutdownAPI(*options);

	delete static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	delete options;
}

bool create_table_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey) {
	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);

	Aws::String awsTableName(tableName);
	Aws::String awsPrimaryKey(partitionKey);

	std::cout << "Creating table " << awsTableName <<
					" with a simple primary key: \"" << awsPrimaryKey << "\"." << std::endl;

	Aws::DynamoDB::Model::CreateTableRequest request;

	Aws::DynamoDB::Model::AttributeDefinition hashKey;
	hashKey.SetAttributeName(awsPrimaryKey);
	hashKey.SetAttributeType(Aws::DynamoDB::Model::ScalarAttributeType::S);
	request.AddAttributeDefinitions(hashKey);

	Aws::DynamoDB::Model::KeySchemaElement keySchemaElement;
	keySchemaElement.WithAttributeName(awsPrimaryKey).WithKeyType(Aws::DynamoDB::Model::KeyType::HASH);
	request.AddKeySchema(keySchemaElement);

	Aws::DynamoDB::Model::ProvisionedThroughput throughput;
	throughput.WithReadCapacityUnits(5).WithWriteCapacityUnits(5);
	request.SetProvisionedThroughput(throughput);
	request.SetTableName(awsTableName);

	const Aws::DynamoDB::Model::CreateTableOutcome &outcome = dynamoClient.CreateTable(request);
	if (outcome.IsSuccess()) {
		std::cout << "Table \"" << outcome.GetResult().GetTableDescription().GetTableName() <<
						" created!" << std::endl;
	} else {
		std::cerr << "Failed to create table: " << outcome.GetError().GetMessage() << std::endl;
	}
	return outcome.IsSuccess();
}


int insert_item_dynamodb(dynamodb_config *config,
				const char *tableName,
				const char *partitionKey,
				const char *partitionValue,
				const char *attributeName,
				const char *attributeValue) {
	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);

	Aws::DynamoDB::Model::UpdateItemRequest request;
	request.SetTableName(tableName);

	Aws::DynamoDB::Model::AttributeValue partitionKeyValue;
	partitionKeyValue.SetS(partitionValue);
	request.AddKey(partitionKey, partitionKeyValue);

	Aws::String updateExpression = "SET #attrName = :attrValue";
	request.SetUpdateExpression(updateExpression);

	Aws::Map<Aws::String, Aws::String> expressionAttributeNames;
	expressionAttributeNames["#attrName"] = attributeName;
	request.SetExpressionAttributeNames(expressionAttributeNames);

	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> expressionAttributeValues;
	Aws::DynamoDB::Model::AttributeValue attributeValueObj;
	attributeValueObj.SetS(attributeValue);
	expressionAttributeValues[":attrValue"] = attributeValueObj;
	request.SetExpressionAttributeValues(expressionAttributeValues);

	const Aws::DynamoDB::Model::UpdateItemOutcome &outcome = dynamoClient.UpdateItem(request);
	if (outcome.IsSuccess())
		return 0;

	return -1;
}

bool delete_item_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue) {
	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);

	Aws::DynamoDB::Model::DeleteItemRequest request;
	request.AddKey(partitionKey, Aws::DynamoDB::Model::AttributeValue().SetS(partitionValue));
	request.SetTableName(tableName);

	const Aws::DynamoDB::Model::DeleteItemOutcome &outcome = dynamoClient.DeleteItem(request);
	if (outcome.IsSuccess()) {
	std::cout << "Item \"" << partitionValue << "\" deleted!" << std::endl;
		return true;
	} else {
		std::cerr << "Failed to delete item: " << outcome.GetError().GetMessage() << std::endl;
		return false;
	}
}

char* query_item_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue, const char *attributeKey) {

	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);
	Aws::DynamoDB::Model::QueryRequest request;

	request.SetTableName(tableName);
	request.SetKeyConditionExpression("#keyToMatch = :valueToMatch");

	Aws::Map<Aws::String, Aws::String> keyValues;
	keyValues.emplace("#keyToMatch", partitionKey);
	request.SetExpressionAttributeNames(keyValues);

	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> attributeValues;
	attributeValues.emplace(":valueToMatch", Aws::DynamoDB::Model::AttributeValue().SetS(partitionValue));
	request.SetExpressionAttributeValues(attributeValues);

	std::ostringstream result;

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
					const auto &attribute = item.find(attributeKey);
					if (attribute != item.end() && attribute->second.GetType() == Aws::DynamoDB::Model::ValueType::STRING) {
						result << attribute->second.GetS() << std::endl;
					} else {
						result << attributeKey << ": Not found or not a string." << std::endl;
					}
				}
			} else {
				result << "No item found in table: " << tableName << std::endl;
				return NULL;
			}
			exclusiveStartKey = outcome.GetResult().GetLastEvaluatedKey();
		} else {
			result << "Failed to Query items: " << outcome.GetError().GetMessage() << std::endl;
			return NULL;
		}
	} while (!exclusiveStartKey.empty());

	std::string resultStr = result.str();
	char *resultCStr = new char[resultStr.length() + 1];
	std::strcpy(resultCStr, resultStr.c_str());

	return resultCStr;
}

query_result_t* query_items_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue) {
	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);
	Aws::DynamoDB::Model::QueryRequest request;

	request.SetTableName(tableName);
	request.SetKeyConditionExpression("#keyToMatch = :valueToMatch");

	Aws::Map<Aws::String, Aws::String> keyValues;
	keyValues.emplace("#keyToMatch", partitionKey);
	request.SetExpressionAttributeNames(keyValues);

	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> attributeValues;
	attributeValues.emplace(":valueToMatch", partitionValue);
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
				row.key = strdup(partitionKey);
				if(!row.key) {
					std::cerr << "Strdup failed" << std::endl;
					return NULL;
				}

				row.key_value = strdup(partitionValue);
				if(!row.key_value) {
					std::cerr << "Strdup failed" << std::endl;
					return NULL;
				}

				row.attributes = new key_value_pair_t[item.size()];

				int attribute_index = 0;
				for (const auto &i : item) {
					row.attributes[attribute_index].key = strdup(i.first.c_str());
					if(!row.attributes[attribute_index].key) {
						std::cerr << "Strdup failed" << std::endl;
						return NULL;
					}

					if (i.second.GetS() != "") {
						row.attributes[attribute_index].value = strdup(i.second.GetS().c_str());
						if(!row.attributes[attribute_index].value) {
							std::cerr << "Strdup failed" << std::endl;
							return NULL;
						}

					} else if (i.second.GetN() != "") {
						row.attributes[attribute_index].value = strdup(i.second.GetN().c_str());
						if(!row.attributes[attribute_index].value) {
							std::cerr << "Strdup failed" << std::endl;
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


query_result_t *scan_table_dynamodb(dynamodb_config *config, const char *tableName, const char *key) {

	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);
	Aws::DynamoDB::Model::ScanRequest request;
	request.SetTableName(tableName);

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
					if (itemEntry.first == key) {
						row.key = strdup(itemEntry.first.c_str());
						if(!row.key) {
							std::cerr << "Strdup failed" << std::endl;
							return NULL;
						}

						row.key_value = strdup(itemEntry.second.GetS().c_str());
						if(!row.key_value) {
							std::cerr << "Strdup failed" << std::endl;
							return NULL;
						}

					} else {
						row.attributes[attr_index].key = strdup(itemEntry.first.c_str());
						if(!row.attributes[attr_index].key) {
							std::cerr << "Strdup failed" << std::endl;
							return NULL;
						}

						if (itemEntry.second.GetS() != "") {

							row.attributes[attr_index].value = strdup(itemEntry.second.GetS().c_str());
							if(!row.attributes[attr_index].value) {
							std::cerr << "Strdup failed" << std::endl;
							return NULL;
						}

						} else if (itemEntry.second.GetN() != "") {

							row.attributes[attr_index].value = strdup(itemEntry.second.GetN().c_str());
							if(!row.attributes[attr_index].value) {
							std::cerr << "Strdup failed" << std::endl;
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

int update_item_inc_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue, const char *valueKey, int incrementValue) {
	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);

	Aws::DynamoDB::Model::GetItemRequest getItemRequest;
	getItemRequest.SetTableName(tableName);
	getItemRequest.AddKey(partitionKey, Aws::DynamoDB::Model::AttributeValue(partitionValue));

	const Aws::DynamoDB::Model::GetItemOutcome &getItemOutcome = dynamoClient.GetItem(getItemRequest);
	if (!getItemOutcome.IsSuccess()) {
		std::cerr << getItemOutcome.GetError().GetMessage() << std::endl;
		return -1;
	}

	const Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> &item = getItemOutcome.GetResult().GetItem();
	if (item.empty()) {
		std::cerr << "Item not found." << std::endl;
		return -1;
	}

	int currentValue = 0;
	const auto &attributeIter = item.find(valueKey);
	if (attributeIter != item.end() && attributeIter->second.GetType() == Aws::DynamoDB::Model::ValueType::STRING) {
		try {
			currentValue = std::stoi(attributeIter->second.GetS());
		} catch (const std::exception &e) {
			std::cerr << "Error converting current value to integer: " << e.what() << std::endl;
			return -1;
		}
	} else {
		std::cerr << "Attribute not found or not a string." << std::endl;
		return -1;
	}

	int newValue = currentValue + incrementValue;

	Aws::DynamoDB::Model::UpdateItemRequest updateRequest;
	updateRequest.SetTableName(tableName);
	updateRequest.AddKey(partitionKey, Aws::DynamoDB::Model::AttributeValue(partitionValue));

	Aws::String update_expression = "SET #valKey = :newval";
	updateRequest.SetUpdateExpression(update_expression);

	Aws::Map<Aws::String, Aws::String> expressionAttributeNames;
	expressionAttributeNames["#valKey"] = valueKey;
	updateRequest.SetExpressionAttributeNames(expressionAttributeNames);

	Aws::DynamoDB::Model::AttributeValue newValueAttribute;
	newValueAttribute.SetN(std::to_string(newValue));
	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> expressionAttributeValues;
	expressionAttributeValues[":newval"] = newValueAttribute;
	updateRequest.SetExpressionAttributeValues(expressionAttributeValues);

	const Aws::DynamoDB::Model::UpdateItemOutcome &updateOutcome = dynamoClient.UpdateItem(updateRequest);
	if (!updateOutcome.IsSuccess()) {
		std::cerr << updateOutcome.GetError().GetMessage() << std::endl;
		return -1;
	}

	return newValue;
}

int update_item_sub_dynamodb(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue, const char *valueKey, int decrementValue) {
	Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
	Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);

	Aws::DynamoDB::Model::GetItemRequest getItemRequest;
	getItemRequest.SetTableName(tableName);
	getItemRequest.AddKey(partitionKey, Aws::DynamoDB::Model::AttributeValue(partitionValue));

	const Aws::DynamoDB::Model::GetItemOutcome &getItemOutcome = dynamoClient.GetItem(getItemRequest);
	if (!getItemOutcome.IsSuccess()) {
		std::cerr << getItemOutcome.GetError().GetMessage() << std::endl;
		return -1;
	}

	const Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> &item = getItemOutcome.GetResult().GetItem();
	if (item.empty()) {
		std::cerr << "Item not found." << std::endl;
		return -1;
	}

	int currentValue = 0;
	const auto &attributeIter = item.find(valueKey);
	if (attributeIter != item.end() && attributeIter->second.GetType() == Aws::DynamoDB::Model::ValueType::STRING) {
		try {
			currentValue = std::stoi(attributeIter->second.GetS());
		} catch (const std::exception &e) {
			std::cerr << "Error converting current value to integer: " << e.what() << std::endl;
			return -1;
		}
	} else {
		std::cerr << "Attribute not found or not a string." << std::endl;
		return -1;
	}

	int newValue = currentValue - decrementValue;

	Aws::DynamoDB::Model::UpdateItemRequest updateRequest;
	updateRequest.SetTableName(tableName);
	updateRequest.AddKey(partitionKey, Aws::DynamoDB::Model::AttributeValue(partitionValue));

	Aws::String update_expression = "SET #valKey = :newval";
	updateRequest.SetUpdateExpression(update_expression);

	Aws::Map<Aws::String, Aws::String> expressionAttributeNames;
	expressionAttributeNames["#valKey"] = valueKey;
	updateRequest.SetExpressionAttributeNames(expressionAttributeNames);

	Aws::DynamoDB::Model::AttributeValue newValueAttribute;
	newValueAttribute.SetN(std::to_string(newValue));
	Aws::Map<Aws::String, Aws::DynamoDB::Model::AttributeValue> expressionAttributeValues;
	expressionAttributeValues[":newval"] = newValueAttribute;
	updateRequest.SetExpressionAttributeValues(expressionAttributeValues);

	const Aws::DynamoDB::Model::UpdateItemOutcome &updateOutcome = dynamoClient.UpdateItem(updateRequest);
	if (!updateOutcome.IsSuccess()) {
		std::cerr << updateOutcome.GetError().GetMessage() << std::endl;
		return -1;
	}

	return newValue;
}


}
