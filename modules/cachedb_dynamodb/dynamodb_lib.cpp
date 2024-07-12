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
#include <iostream>
#include <sstream>
#include "dynamodb_lib.h"


extern "C" {

dynamodb_config init_dynamodb(dynamodb_con *con) {
    dynamodb_config config;
    Aws::SDKOptions *options = new Aws::SDKOptions();
    Aws::InitAPI(*options);

    Aws::Client::ClientConfiguration *clientConfig = new Aws::Client::ClientConfiguration();
    if(con->endpoint != NULL) {
        clientConfig->endpointOverride = con->endpoint;
    } else if(con->region != NULL) {
        clientConfig->region = con->region;
    } else {
        exit(-1);
    }

    config.options = options;
    config.clientConfig = clientConfig;
    return config;
}

void shutdown_dynamodb(dynamodb_config *config) {
    Aws::SDKOptions *options = static_cast<Aws::SDKOptions*>(config->options);
    Aws::ShutdownAPI(*options);

    delete static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
    delete options;
}

bool create_table(dynamodb_config *config, const char *tableName, const char *partitionKey) {
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

bool put_item(dynamodb_config *config, const char *tableName, const char *partitionKey,
                const char *partitionValue, const char *founder, int employeeCount, int yearFounded,
                int qualityRanking) {
    Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
    Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);

    Aws::DynamoDB::Model::PutItemRequest putItemRequest;
    putItemRequest.SetTableName(tableName);
    putItemRequest.AddItem(partitionKey, Aws::DynamoDB::Model::AttributeValue().SetS(partitionValue));
    putItemRequest.AddItem("Founder", Aws::DynamoDB::Model::AttributeValue().SetS(founder));
    putItemRequest.AddItem("Employee Count", Aws::DynamoDB::Model::AttributeValue().SetN(std::to_string(employeeCount)));
    putItemRequest.AddItem("Year Founded", Aws::DynamoDB::Model::AttributeValue().SetN(std::to_string(yearFounded)));
    putItemRequest.AddItem("Quality Ranking", Aws::DynamoDB::Model::AttributeValue().SetN(std::to_string(qualityRanking)));

    const Aws::DynamoDB::Model::PutItemOutcome outcome = dynamoClient.PutItem(putItemRequest);
    if (outcome.IsSuccess()) {
        std::cout << "Successfully added Item!" << std::endl;
        return true;
    } else {
        std::cerr << outcome.GetError().GetMessage() << std::endl;
        return false;
    }
}

int insert_item(dynamodb_config *config,
                    const char *tableName,
                    const char *partitionKey,
                    const char *partitionValue,
                    const char *attributeName,
                    const char *attributeValue) {
    Aws::Client::ClientConfiguration *clientConfig = static_cast<Aws::Client::ClientConfiguration*>(config->clientConfig);
    Aws::DynamoDB::DynamoDBClient dynamoClient(*clientConfig);

    // Define PutItem request
    Aws::DynamoDB::Model::PutItemRequest request;
    request.SetTableName(tableName);

    // Set partition key attribute
    Aws::DynamoDB::Model::AttributeValue partitionKeyValue;
    partitionKeyValue.SetS(partitionValue);
    request.AddItem(partitionKey, partitionKeyValue);

    // Set additional attribute
    Aws::DynamoDB::Model::AttributeValue additionalAttributeValue;
    additionalAttributeValue.SetS(attributeValue);
    request.AddItem(attributeName, additionalAttributeValue);

    // Insert the item
    const Aws::DynamoDB::Model::PutItemOutcome &outcome = dynamoClient.PutItem(request);
    if (outcome.IsSuccess()) {
        std::cout << "Item was inserted successfully" << std::endl;
        return 0;
    } else {
        std::cerr << "Failed to insert item: " << outcome.GetError().GetMessage() << std::endl;
        return -1;
    }
}


bool delete_item(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue) {
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

char* query_item(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue, const char *attributeKey) {

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
char *query_items(dynamodb_config *config, const char *tableName, const char *partitionKey, const char *partitionValue) {

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
                result << "Number of items retrieved from Query: " << items.size() << std::endl;
                for (const auto &item : items) {
                    result << "******************************************************" << std::endl;
                    for (const auto &i : item) {
                        result << i.first << ": " << i.second.GetS() << std::endl;
                    }
                }
            } else {
                result << "No item found in table: " << tableName << std::endl;
            }
            exclusiveStartKey = outcome.GetResult().GetLastEvaluatedKey();
        } else {
            result << "Failed to Query items: " << outcome.GetError().GetMessage() << std::endl;
            return NULL;
        }
    } while (!exclusiveStartKey.empty());

    std::string resultStr = result.str();
    char *result_str = new char[resultStr.length() + 1];
    std::strcpy(result_str, resultStr.c_str());

    return result_str;
}

}
