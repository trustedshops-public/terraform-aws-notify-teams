# -*- coding: utf-8 -*-
import json
import logging
import os
from typing import Any
from typing import Dict

from notifyteams.notify_teams import get_teams_message_payload
from notifyteams.notify_teams import get_teams_message_strucuture
from notifyteams.notify_teams import send_teams_notification

logging.basicConfig(
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger(__name__)


def lambda_handler(event: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Lambda function to parse notification events and forward to Teams

    :param event: lambda expected event object
    :param context: lambda expected context object
    :returns: none
    """
    # Level	Numeric value
    # CRITICAL	50
    # ERROR	    40
    # WARNING	30
    # INFO	    20
    # DEBUG	    10
    # NOTSET	0
    if os.environ.get("DEBUG", "False") == "True":
        log.setLevel(level=10)
    else:
        log.setLevel(level=20)

    if os.environ.get("LOG_EVENTS", "False") == "True":
        log.info(f"Event logging enabled: `{json.dumps(event)}`")

    responses = list(dict())

    for record in event["Records"]:
        sns = record["Sns"]
        subject = sns["Subject"]
        message = sns["Message"]
        region = sns["TopicArn"].split(":")[3]

        payload = get_teams_message_payload(
            message=message, region=region, subject=subject
        )

        log.debug(f"{payload}")

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

    log.debug(f"{responses=}")

    return ", ".join(responses)
