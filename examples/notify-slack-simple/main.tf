provider "aws" {
  region = "eu-west-1"
}

resource "aws_sns_topic" "my_sns" {
  name = "my-sns"
}

module "notify_teams" {
  source = "../../"

  sns_topic_name   = aws_sns_topic.my_sns.name
  create_sns_topic = false

  teams_webhook_url = "<YOUR WEBHOOK>"

  tags = {
    Name = "notify-teams-simple"
  }

  depends_on = [aws_sns_topic.my_sns]
}
