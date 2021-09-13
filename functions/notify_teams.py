from __future__ import print_function
from urllib.error import HTTPError

import pymsteams

import re
import os
import boto3
import json
import base64
import urllib.request
import urllib.parse
import logging


def decrypt(encrypted_url):
    region = os.environ['AWS_REGION']
    try:
        kms = boto3.client('kms', region_name=region)
        plaintext = kms.decrypt(CiphertextBlob=base64.b64decode(encrypted_url))[
            'Plaintext']
        return plaintext.decode()
    except Exception:
        logging.exception("Failed to decrypt URL with KMS")


def cloudwatch_notification(message, region):
    states = {'OK': 'green', 'INSUFFICIENT_DATA': 'yellow', 'ALARM': 'red'}
    if region.startswith("us-gov-"):
        cloudwatch_url = "https://console.amazonaws-us-gov.com/cloudwatch/home?region="
    else:
        cloudwatch_url = "https://console.aws.amazon.com/cloudwatch/home?region="

    return {
        "color": states[message['NewStateValue']],
        "fallback": "Alarm {} triggered".format(message['AlarmName']),
        "fields": [
            {"title": "Alarm Name",
                "value": message['AlarmName'], "short": True},
            {"title": "Alarm Description",
                "value": message['AlarmDescription'], "short": False},
            {"title": "Alarm reason",
                "value": message['NewStateReason'], "short": False},
            {"title": "Old State",
                "value": message['OldStateValue'], "short": True},
            {"title": "Current State",
                "value": message['NewStateValue'], "short": True},
            {
                "title": "Link to Alarm",
                "value": cloudwatch_url + region + "#alarm:alarmFilter=ANY;name=" + urllib.parse.quote(message['AlarmName']),
                "short": False
            }
        ]
    }


def default_notification(subject, message):
    attachments = {
        "fallback": "A new message",
        "title": subject if subject else "Message",
        "mrkdwn_in": ["value"],
        "fields": []
    }
    if type(message) is dict:
        for k, v in message.items():
            value = f"`{json.dumps(v)}`" if isinstance(
                v, (dict, list)) else str(v)
            attachments['fields'].append(
                {
                    "title": k,
                    "value": value,
                    "short": len(value) < 25
                }
            )
    else:
        attachments['fields'].append({"value": message, "short": False})

    return attachments


def FindURL(string):
    # findall() has been used
    # with valid conditions for urls in string
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex, string)
    return [x[0] for x in url]


def notify_teams(subject, message, region):
    colors = {"red": "FF0000", "green": "00FF00",
              "blue": "0000FF", "yellow": "FFFF00"}
    teams_url = os.environ['TEAMS_WEBHOOK_URL']
    if not teams_url.startswith("http"):
        teams_url = decrypt(teams_url)

    if type(message) is str:
        try:
            message = json.loads(message)
        except json.JSONDecodeError as err:
            logging.exception(f'JSON decode error: {err}')

    payload = {
        "attachments": []
    }
    notification = {}

    if "AlarmName" in message:
        notification = cloudwatch_notification(message, region)
        payload['text'] = "AWS CloudWatch notification - " + \
            message["AlarmName"]
    elif "attachments" in message or "text" in message:
        payload = {**payload, **message}
    else:
        notification = default_notification(subject, message)
        payload['text'] = "AWS Notification"

    print(payload)
    print(notification)
    teams_message = pymsteams.connectorcard(teams_url)

    summary = payload
    summary["notification"] = notification
    teams_message.summary(json.dumps(summary))

    if "color" in notification:
        teams_message.color(colors[notification["color"]])
    else:
        teams_message.color(colors["blue"])
    if "text" in payload:
        teams_message.title(payload["text"])
    else:
        teams_message.title("AWS Notification")

    if notification == {}:
        section = pymsteams.cardsection()
        section.title("Notification")
        section.text("No data provided")
        teams_message.addSection(section)
    elif "fields" in notification:
        section = pymsteams.cardsection()
        section.title("Notification")
        for index, field in enumerate(notification["fields"]):
            if "title" in field and "value" in field:
                urls = FindURL(field["value"])
                if len(urls) > 0:
                    for url in urls:
                        section.addFact(field["title"], field["value"])
                        teams_message.addLinkButton(field["title"], url)
                else:
                    section.addFact(field["title"], field["value"])
            elif "value" in field:
                section.addFact("Message #{:02d}".format(
                    index+1), field["value"])
        teams_message.addSection(section)
    else:
        section = pymsteams.cardsection()
        section.title("Notification")
        teams_message.text(notification)
        teams_message.addSection(section)

    if "attachments" in payload:
        for index, attachment in enumerate(payload["attachments"]):
            section = pymsteams.cardsection()
            if "title" in attachment:
                section.title("Attachement - {}".format(attachment['title']))
            else:
                section.title("Attachement - {:02d}".format(index))
            if "pretext" in attachment:
                section.text(attachment["pretext"])
            if "author_name" in attachment:
                section.addFact("Author Name", attachment["author_name"])
            if "author_link" in attachment:
                section.addFact("Author Link", attachment["author_link"])
            if "author_icon" in attachment:
                section.addFact("Author Icon", attachment["author_icon"])
                section.addImage(attachment["author_icon"])
            if "title_link" in attachment:
                section.addFact("Title Link", attachment["title_link"])
            if "text" in attachment:
                section.addFact("Text", attachment["text"])
            if "thumb_url" in attachment:
                section.addFact("Thumb URL", attachment["thumb_url"])
                section.addImage(attachment["thumb_url"])
            if "footer" in attachment:
                section.addFact("Footer", attachment["thumb_url"])
            if "footer_icon" in attachment:
                section.addFact("Footer Icon", attachment["footer_icon"])
                section.addImage(attachment["footer_icon"])
            if "ts" in attachment:
                section.addFact("TS", attachment["ts"])
            if "fields" in attachment:
                for index, field in enumerate(attachment["fields"]):
                    if "title" in field and "value" in field:
                        urls = FindURL(field["value"])
                        if len(urls) > 0:
                            for url in urls:
                                teams_message.addLinkButton(
                                    field["title"], url)
                        else:
                            section.addFact(field["title"], field["value"])
                    elif "value" in field:
                        section.addFact("Message #{:02d}".format(
                            index+1), field["value"])
            teams_message.addSection(section)

    teams_message.send()
    response = json.dumps({"code": teams_message.last_http_status.status_code})
    return response


def lambda_handler(event, context):
    if 'LOG_EVENTS' in os.environ and os.environ['LOG_EVENTS'] == 'True':
        logging.warning(
            'Event logging enabled: `{}`'.format(json.dumps(event)))

    subject = event['Records'][0]['Sns']['Subject']
    message = event['Records'][0]['Sns']['Message']
    region = event['Records'][0]['Sns']['TopicArn'].split(":")[3]
    response = notify_teams(subject, message, region)

    if json.loads(response)["code"] != 200:
        logging.error("Error: received status `{}` using event `{}` and context `{}`".format(
            json.loads(response)["info"], event, context))

    return response
