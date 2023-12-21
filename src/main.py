# -*- coding: utf-8 -*-
import json
import logging
import os
from typing import Any
from typing import Dict

from notify_teams import get_teams_message_payload
from notify_teams import get_teams_message_strucuture
from notify_teams import send_teams_notification

logging.basicConfig(
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG if os.environ.get("DEBUG", "False") == "True" else logging.INFO)


def lambda_handler(event: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Lambda function to parse notification events and forward to Teams

    :param event: lambda expected event object
    :param context: lambda expected context object
    :returns: str
    """
    print("Lambda function started")
    print(log.level)
    if os.environ.get("DEBUG", "False") == "True":
        log.info("Debug mode enabled")
    else:
        log.info("Debug mode disabled")

    log.debug(f"Event: {json.dumps(event)}")

    responses = list(dict())

    for record in event["Records"]:
        sns = record["Sns"]
        subject = sns["Subject"]
        message = sns["Message"]
        region = sns["TopicArn"].split(":")[3]

        payload = get_teams_message_payload(
            message=message, region=region, subject=subject
        )

        for attachment in payload["attachments"]:
            teams_message = get_teams_message_strucuture(payload=attachment)
            response = send_teams_notification(teams_message=teams_message)
            responses.append(response)

            log.debug(f"{response=}")

            if json.loads(response)["code"] != 200:
                response_info = json.loads(response)["info"]
                log.error(
                    f"Error: received status `{response_info}` using event `{event}` and context `{context}`"
                )

    print("Lambda function finished")

    return ", ".join(responses)
