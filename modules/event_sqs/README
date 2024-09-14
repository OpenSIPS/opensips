event_sqs Module
     __________________________________________________________

   Table of Contents

   1. Admin Guide

        1.1. Overview
        1.2. Dependencies

              1.2.1. OpenSIPS Modules
              1.2.2. External Libraries or Applications
              1.2.3. Deploying Amazon SQS locally on your computer

        1.3. Exported Parameters

              1.3.1. queue_url (string)

        1.4. Exported Functions

              1.4.1. sqs_publish_message(queue_id, message)
              1.4.2.

        1.5. Examples

              1.5.1. Event-Driven Messaging with Event Interface

   2. Contributors

        2.1. By Commit Statistics
        2.2. By Commit Activity

   3. Documentation

        3.1. Contributors

   List of Tables

   2.1. Top contributors by DevScore^(1), authored commits^(2) and
          lines added/removed^(3)

   2.2. Most recently active contributors^(1) to this module

   List of Examples

   1.1. Set queue_url parameter
   1.2. sqs_publish_message() function usage

Chapter 1. Admin Guide

1.1. Overview

   The event_sqs module is an implementation of an Amazon SQS
   producer. It serves as a transport backend for the Event
   Interface and also provides a stand-alone connector to be used
   from the OpenSIPS script in order to publish messages to SQS
   queues.

   https://aws.amazon.com/sqs/

1.2. Dependencies

1.2.1. OpenSIPS Modules

   There is no need to load any module before this module.

1.2.2. External Libraries or Applications

   The following libraries or applications must be installed
   before running OpenSIPS with this module loaded:
     * AWS SDK for C++:
       By following these steps, you'll have the AWS SDK for C++
       installed and configured on your Linux system, allowing you
       to integrate with SQS: AWS SDK for C++ Installation Guide
       Additional instructions for installation can be found at:
       AWS SDK for C++ GitHub Repository

1.2.3. Deploying Amazon SQS locally on your computer

   For testing purposes, you can run SQS locally. To achieve this,
   you start localstack on your computer:

pip install localstack
localstack start

   Don't forget to set the necessary environment variables for
   testing, for example:

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1

   Here you can find some cli commands such as create-queue,
   send/receive-message, etc.:
   https://docs.aws.amazon.com/cli/latest/reference/sqs/

1.3. Exported Parameters

1.3.1. queue_url (string)

   This parameter specifies the configuration for an SQS queue
   that can be used to publish messages directly from the script,
   using the sqs_publish_message() function or to send messages
   using raise_event function.

   The format of the parameter is: [ID]sqs_url, where ID is an
   identifier for this SQS queue instance and sqs_url is the full
   url of the queue.

   The queue_url contains:
     * endpoint
     * region

   This parameter can be set multiple times.

   Example 1.1. Set queue_url parameter

...

modparam("event_sqs", "queue_url",
          "[q1]https://sqs.us-west-2.amazonaws.com/123456789012/Queue1")

modparam("event_sqs", "queue_url",
          "[q2]http://sqs.us-east-1.localhost.localstack.cloud:4566/0000
00000000/Queue2")

...

1.4. Exported Functions

1.4.1. sqs_publish_message(queue_id, message)

   Publishes a message to an SQS queue. As the actual send
   operation is done asynchronously, this function does not block
   and returns immediately after queuing the message for sending.

   This function can be used from any route.

   The function has the following parameters:
     * queue_id (string) The ID of the SQS queue. Must be one of
       the IDs defined through the `queue_url` modparam.
     * message (string) - The payload of the message to publish.

   Example 1.2. sqs_publish_message() function usage

...

$var(msg) = "Hello, this is a message to SQS!";
sqs_publish_message("q1", $var(msg));

...

1.5. Examples

1.5.1. Event-Driven Messaging with Event Interface

   OpenSIPS' event interface can be utilized to send messages to
   SQS by subscribing to an event and raising it when needed.

   Steps:
     * Event Subscription:
       First, register the event subscription in your OpenSIPS
       configuration file within the `startup_route`:

subscribe_event("MY_EVENT",
        "sqs:http://sqs.us-east-1.localhost.localstack.cloud:4566/000000
000000/Queue2");

     * Event Subscription via CLI:
       After starting OpenSIPS, you can subscribe to the event
       from another terminal using the OpenSIPS CLI:

opensips-cli -x mi event_subscribe MY_EVENT \
          sqs:http://sqs.us-east-1.localhost.localstack.cloud:4566/00000
0000000/Queue2

     * Raise the Event and Send Message:
       Finally, to send a message, raise the subscribed event with
       the desired message content:

opensips-cli -x mi raise_event MY_EVENT 'OpenSIPS Message'

Chapter 2. Contributors

2.1. By Commit Statistics

   Table 2.1. Top contributors by DevScore^(1), authored
   commits^(2) and lines added/removed^(3)
                   Name               DevScore Commits Lines ++ Lines --
   1. Alexandra Titoc                    27       7      1629     366
   2. Razvan Crainea (@razvancrainea)    5        3       9        4

   (1) DevScore = author_commits + author_lines_added /
   (project_lines_added / project_commits) + author_lines_deleted
   / (project_lines_deleted / project_commits)

   (2) including any documentation-related commits, excluding
   merge commits. Regarding imported patches/code, we do our best
   to count the work on behalf of the proper owner, as per the
   "fix_authors" and "mod_renames" arrays in
   opensips/doc/build-contrib.sh. If you identify any
   patches/commits which do not get properly attributed to you,
   please submit a pull request which extends "fix_authors" and/or
   "mod_renames".

   (3) ignoring whitespace edits, renamed files and auto-generated
   files

2.2. By Commit Activity

   Table 2.2. Most recently active contributors^(1) to this module
                   Name                 Commit Activity
   1. Razvan Crainea (@razvancrainea) Sep 2024 - Sep 2024
   2. Alexandra Titoc                 Aug 2024 - Aug 2024

   (1) including any documentation-related commits, excluding
   merge commits

Chapter 3. Documentation

3.1. Contributors

   Last edited by: Razvan Crainea (@razvancrainea), Alexandra
   Titoc.

   Documentation Copyrights:

   Copyright © 2024 www.opensips-solutions.com
