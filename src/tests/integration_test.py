# -*- coding: utf-8 -*-
"""
    Integration Test
    ----------------

    Executes tests against live Teams webhook

"""
import logging
import os
from typing import List

import boto3
from dotenv import dotenv_values

logging.basicConfig(
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger(__name__)

def _get_files(directory: str) -> List[str]:
    """
    Helper function to get list of files under `directory`

    :params directory: directory to pull list of files from
    :returns: list of files names under directory specified
    """
    return [
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, f))
    ]


def test_lambda_handler():
    """
    Invoke lambda handler with sample SNS messages

    Messages should arrive at the live webhook specified
    """
    config = dotenv_values(".int.env")
    lambda_client = boto3.client("lambda", region_name=config['REGION'])

    # These are SNS messages that invoke the lambda handler;
    # the event payload is in the `message` field
    messages = _get_files(directory="./data/messages")

    for message in messages:
        with open(message, "r") as mfile:
            msg = mfile.read()
        response = lambda_client.invoke(
            FunctionName=config['LAMBDA_FUNCTION_NAME'],
            InvocationType="Event",
            Payload=msg,
        )
        log.debug(response)


def test_event_publish_to_sns_topic():
    """
    Publish sample events to SNS topic created

    Messages should arrive at the live webhook specified
    """
    config = dotenv_values(".int.env")
    sns_client = boto3.client("sns", region_name=config['REGION'])

    # These are event payloads that will get published
    events = _get_files(directory="./data/events")

    for event in events:
        with open(event, "r") as efile:
            msg = efile.read()
        response = sns_client.publish(
            TopicArn=config['SNS_TOPIC_ARN'],
            Message=msg,
            Subject=event,
        )
        log.debug(response)
