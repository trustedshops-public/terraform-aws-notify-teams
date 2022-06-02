# -*- coding: utf-8 -*-
"""
    Notify Teams
    ------------

    Receives event payloads that are parsed and sent to Teams

"""
import base64
import json
import logging
import os
import re
import urllib.parse
import urllib.request
from enum import Enum
from typing import Any, Dict, Optional, Union, cast

import boto3
import pymsteams
from botocore.exceptions import NoCredentialsError

# Set default region if not provided
REGION = os.environ.get("AWS_REGION", "eu-central-1")

# Create client so its cached/frozen between invocations
KMS_CLIENT = boto3.client("kms", region_name=REGION)

logging.basicConfig(
    format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger(__name__)


class AwsService(Enum):
    """AWS service supported by function"""

    cloudwatch = "cloudwatch"
    guardduty = "guardduty"


def decrypt_url(encrypted_url: str) -> str:
    """
    Decrypt encrypted URL with KMS

      :param encrypted_url: URL to decrypt with KMS
      :returns: plaintext URL
    """
    try:
        decrypted_payload = KMS_CLIENT.decrypt(
            CiphertextBlob=base64.b64decode(encrypted_url)
        )
        return decrypted_payload["Plaintext"].decode()
    except Exception:
        log.exception("Failed to decrypt URL with KMS")
        return ""


def get_account_info() -> (str, str):
    """
    Gather Account details
    :returns: AWS Account Details
    """
    account_id = "Not Found"
    alias = "Not Found"
    try:
        account_id = boto3.client("sts").get_caller_identity().get("Account")
        alias = boto3.client("iam").list_account_aliases()["AccountAliases"][0]
    except NoCredentialsError:
        log.error("Could not determine Account details")
    return account_id, alias


def get_service_url(region: str, service: str) -> str:
    """
    Get the appropriate service URL for the region

      :param region: name of the AWS region
      :param service: name of the AWS service
      :returns: AWS console url formatted for the region and service provided
    """
    try:
        service_name = AwsService[service].value
        if region.startswith("us-gov-"):
            return f"https://console.amazonaws-us-gov.com/{service_name}/home?region={region}"
        else:
            return f"https://console.aws.amazon.com/{service_name}/home?region={region}"

    except KeyError:
        log.error(f"Service {service} is currently not supported")
        raise


class CloudWatchAlarmState(Enum):
    """Maps CloudWatch notification state to Teams message format color"""

    # {
    #  "red": "FF0000",
    #  "green": "00FF00",
    #  "blue": "0000FF",
    #  "yellow": "FFFF00"
    #  }
    OK = "00FF00"
    INSUFFICIENT_DATA = "0000FF"
    ALARM = "FF0000"


def format_cloudwatch_alarm(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    """
    Format CloudWatch alarm event into Teams message format

      :params message: SNS message body containing CloudWatch alarm event
      :region: AWS region where the event originated from
      :returns: formatted Teams message payload
    """

    cloudwatch_url = get_service_url(region=region, service="cloudwatch")
    alarm_name = message["AlarmName"]

    return {
        "color": CloudWatchAlarmState[message["NewStateValue"]].value,
        "fallback": f"Alarm {alarm_name} triggered",
        "fields": [
            {"title": "Alarm Name", "value": f"`{alarm_name}`", "short": True},
            {
                "title": "Alarm Description",
                "value": f"`{message['AlarmDescription']}`",
                "short": False,
            },
            {
                "title": "Alarm reason",
                "value": f"`{message['NewStateReason']}`",
                "short": False,
            },
            {
                "title": "Old State",
                "value": f"`{message['OldStateValue']}`",
                "short": True,
            },
            {
                "title": "Current State",
                "value": f"`{message['NewStateValue']}`",
                "short": True,
            },
            {
                "title": "Link to Alarm",
                "value": f"{cloudwatch_url}#alarm:alarmFilter=ANY;name={urllib.parse.quote(alarm_name)}",
                "short": False,
            },
        ],
        "text": f"AWS CloudWatch notification - {message['AlarmName']}",
    }


class GuardDutyFindingSeverity(Enum):
    """Maps GuardDuty finding severity to Teams message format color"""

    # {
    #  "red": "FF0000",
    #  "green": "00FF00",
    #  "blue": "0000FF",
    #  "yellow": "FFFF00"
    #  }
    Low = "#777777"
    Medium = "FFFF00"
    High = "FF0000"


def format_guardduty_finding(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    """
    Format GuardDuty finding event into Teams message format

    :params message: SNS message body containing GuardDuty finding event
    :params region: AWS region where the event originated from
    :returns: formatted Teams message payload
    """

    guardduty_url = get_service_url(region=region, service="guardduty")
    detail = message["detail"]
    service = detail.get("service", {})
    severity_score = detail.get("severity")

    if severity_score < 4.0:
        severity = "Low"
    elif severity_score < 7.0:
        severity = "Medium"
    else:
        severity = "High"

    return {
        "color": GuardDutyFindingSeverity[severity].value,
        "fallback": f"GuardDuty Finding: {detail.get('title')}",
        "fields": [
            {
                "title": "Description",
                "value": f"`{detail['description']}`",
                "short": False,
            },
            {
                "title": "Finding Type",
                "value": f"`{detail['type']}`",
                "short": False,
            },
            {
                "title": "First Seen",
                "value": f"`{service['eventFirstSeen']}`",
                "short": True,
            },
            {
                "title": "Last Seen",
                "value": f"`{service['eventLastSeen']}`",
                "short": True,
            },
            {"title": "Severity", "value": f"`{severity}`", "short": True},
            {
                "title": "Count",
                "value": f"`{service['count']}`",
                "short": True,
            },
            {
                "title": "Link to Finding",
                "value": f"{guardduty_url}#/findings?search=id%3D{detail['id']}",
                "short": False,
            },
        ],
        "text": f"AWS GuardDuty Finding - {detail.get('title')}",
    }


def format_default(
    message: Union[str, Dict], subject: Optional[str] = None
) -> Dict[str, Any]:
    """
    Default formatter, converting event into Teams message format

    :params message: SNS message body containing message/event
    :returns: formatted Teams message payload
    """

    attachments = {
        "fallback": "A new message",
        "text": "AWS notification",
        "title": subject if subject else "Message",
        "mrkdwn_in": ["value"],
    }
    fields = []

    if type(message) is dict:
        for k, v in message.items():
            value = f"{json.dumps(v)}" if isinstance(v, (dict, list)) else str(v)
            fields.append({"title": k, "value": f"`{value}`", "short": len(value) < 25})
    else:
        fields.append({"value": message, "short": False})

    if fields:
        attachments["fields"] = fields  # type: ignore

    return attachments


def get_teams_message_payload(
    message: Union[str, Dict], region: str, subject: Optional[str] = None
) -> Dict:
    """
    Parse notification message and format into Teams message payload

    :params message: SNS message body notification payload
    :params region: AWS region where the event originated from
    :params subject: Optional subject line for Teams notification
    :returns: Teams message payload
    """

    payload = {}
    attachment = None

    if not message:
        raise KeyError

    if isinstance(message, str):
        try:
            message = json.loads(message)
        except json.JSONDecodeError:
            log.debug("Not a structured payload, just a string message")

    message = cast(Dict[str, Any], message)

    if "AlarmName" in message:
        notification = format_cloudwatch_alarm(message=message, region=region)
        attachment = notification

    elif (
        isinstance(message, Dict) and message.get("detail-type") == "GuardDuty Finding"
    ):
        notification = format_guardduty_finding(
            message=message, region=message["region"]
        )
        attachment = notification

    elif "attachments" in message or "text" in message:
        payload = {**payload, **message}

    else:
        attachment = format_default(message=message, subject=subject)

    if attachment:
        payload["attachments"] = [attachment]  # type: ignore

    return payload


def send_teams_notification(teams_message: pymsteams.connectorcard) -> str:
    """
    Send notification payload to Teams

    :params teams_message: formatted Teams message payload
    :returns: response details from sending notification
    """
    teams_url = os.environ["TEAMS_WEBHOOK_URL"]
    teams_message.newhookurl(teams_url)
    teams_message.send()
    response = teams_message.last_http_response.status_code
    return json.dumps({"code": response})


def _find_url_in_string(url: str) -> [str]:
    """
    Checks if a url is in a string

    :params url: possible url in string
    :returns: if found the Array of str containing the url otherwise
    an empty Array
    """
    # findall() has been used
    # with valid conditions for urls in string
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2," \
            r"4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([" \
            r"^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’])) "
    url = re.findall(regex, url)
    return [x[0] for x in url]


def _create_section(payload: Dict[str, Any]) -> pymsteams.cardsection:
    """
    Create section from payload fields

    :params payload: generally formatted payload
    :returns: teams section payload
    """
    section = pymsteams.cardsection()
    for index, field in enumerate(payload["fields"]):
        if "title" in field and "value" in field:
            urls = _find_url_in_string(field["value"])
            if len(urls) > 0:
                for url in urls:
                    section.addFact(field["title"], field["value"])
                    section.linkButton(field["title"], url)
            else:
                section.addFact(field["title"], field["value"])
        elif "value" in field:
            section.addFact("Message #{:02d}".format(index + 1), field["value"])
    return section


def get_teams_message_strucuture(payload: Dict[str, Any]) -> pymsteams.connectorcard:
    """
    Create from structured payload teams specific payload

    :params payload: generally formatted payload
    :returns: teams message payload
    """
    result = pymsteams.connectorcard(None)
    account_info = pymsteams.cardsection()
    # account_info.disableMarkdown()
    account_id, alias = get_account_info()
    account_info.addFact("Account ID", account_id)
    account_info.addFact("Account Alias", alias)
    result.addSection(account_info)
    if "color" in payload:
        result.color(payload["color"])
    if "fallback" in payload:
        result.summary(payload["fallback"])
    if "text" in payload:
        result.text(payload["text"])
    if "title" in payload:
        result.title(payload["title"])
    if "fields" in payload:
        section = _create_section(payload)
        result.addSection(section)
    return result


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
