# -*- coding: utf-8 -*-
from enum import Enum

# {
#  "red": "FF0000",
#  "green": "00FF00",
#  "blue": "0000FF",
#  "yellow": "FFFF00"
#  }


class CloudWatchAlarmState(Enum):
    """Maps CloudWatch notification state to Teams message format color"""

    OK = "00FF00"
    INSUFFICIENT_DATA = "0000FF"
    ALARM = "FF0000"


class GuardDutyFindingSeverity(Enum):
    """Maps GuardDuty finding severity to Teams message format color"""

    Low = "#777777"
    Medium = "FFFF00"
    High = "FF0000"
