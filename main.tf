data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  sns_topic_arn = try(
    aws_sns_topic.this[0].arn,
    "arn:${data.aws_partition.current.id}:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${var.sns_topic_name}",
    ""
  )

  lambda_policy_document = {
    sid       = "AllowWriteToCloudwatchLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [replace("${try(aws_cloudwatch_log_group.this[0].arn, "")}:*", ":*:*", ":*")]
  }

  lambda_policy_document_kms = {
    sid       = "AllowKMSDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [var.kms_key_arn]
  }

  lambda_policy_document_sts = {
    sid       = "AllowListAlias"
    effect    = "Allow"
    actions   = ["iam:ListAccountAliases"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "lambda" {
  count = var.create ? 1 : 0

  dynamic "statement" {
    for_each = concat([local.lambda_policy_document], var.kms_key_arn != "" ? [local.lambda_policy_document_kms] : [], [local.lambda_policy_document_sts])
    content {
      sid       = statement.value.sid
      effect    = statement.value.effect
      actions   = statement.value.actions
      resources = statement.value.resources
    }
  }
}

resource "aws_cloudwatch_log_group" "this" {
  count = var.create ? 1 : 0

  name              = "/aws/lambda/${var.lambda_function_name}"
  retention_in_days = var.cloudwatch_log_group_retention_in_days
  kms_key_id        = var.cloudwatch_log_group_kms_key_id

  tags = merge(var.tags, var.cloudwatch_log_group_tags)
}

resource "aws_sns_topic" "this" {
  count = var.create_sns_topic && var.create ? 1 : 0

  name = var.sns_topic_name

  kms_master_key_id = var.sns_topic_kms_key_id

  tags = merge(var.tags, var.sns_topic_tags)
}

resource "aws_sns_topic_subscription" "this" {
  count = var.create ? 1 : 0

  topic_arn     = local.sns_topic_arn
  protocol      = "lambda"
  endpoint      = module.lambda.lambda_function_arn
  filter_policy = var.subscription_filter_policy
}

resource "null_resource" "this" {
  count = var.create ? 1 : 0
  provisioner "local-exec" {
    command     = "pipenv lock && pipenv requirements > requirements.txt"
    working_dir = "${path.module}/src"
  }
}

module "lambda" {
  source  = "terraform-aws-modules/lambda/aws"
  version = "6.5.0"

  create = var.create

  function_name = var.lambda_function_name
  description   = var.lambda_description

  handler = "main.lambda_handler"
  source_path = [{
    path             = "${path.module}/src",
    pip_requirements = "${path.module}/src/requirements.txt"
    patterns = [
      "!.DS_Store",
      "!__pycache__/.*",
      "!.idea/.*",
      "!.pytest_cache/.*",
      "!notifyteams.egg-info/.*",
      "!tests/.*",
      "!.flake8",
      "!.gitignore",
      "!.pyproject.toml",
      "!Pipfile",
      "!Pipfile.lock",
    ]
  }]
  recreate_missing_package       = var.recreate_missing_package
  runtime                        = "python3.11"
  timeout                        = 30
  kms_key_arn                    = var.kms_key_arn
  reserved_concurrent_executions = var.reserved_concurrent_executions
  ephemeral_storage_size         = var.lambda_function_ephemeral_storage_size

  # If publish is disabled, there will be "Error adding new Lambda Permission for notify_teams:
  # InvalidParameterValueException: We currently do not support adding policies for $LATEST."
  publish = true

  environment_variables = {
    TEAMS_WEBHOOK_URL = var.teams_webhook_url
    LOG_EVENTS        = var.log_events ? "True" : "False"
    DEBUG             = var.lambda_debug ? "True" : "False"
  }

  create_role               = var.lambda_role == ""
  lambda_role               = var.lambda_role
  role_name                 = "${var.iam_role_name_prefix}-${var.lambda_function_name}"
  role_permissions_boundary = var.iam_role_boundary_policy_arn
  role_tags                 = var.iam_role_tags
  role_path                 = var.iam_role_path
  policy_path               = var.iam_policy_path

  # Do not use Lambda's policy for cloudwatch logs, because we have to add a policy
  # for KMS conditionally. This way attach_policy_json is always true independenty of
  # the value of presense of KMS. Famous "computed values in count" bug...
  attach_cloudwatch_logs_policy = false
  attach_policy_json            = true
  policy_json                   = try(data.aws_iam_policy_document.lambda[0].json, "")

  use_existing_cloudwatch_log_group = true
  attach_network_policy             = var.lambda_function_vpc_subnet_ids != null

  allowed_triggers = {
    AllowExecutionFromSNS = {
      principal  = "sns.amazonaws.com"
      source_arn = local.sns_topic_arn
    }
  }

  store_on_s3 = var.lambda_function_store_on_s3
  s3_bucket   = var.lambda_function_s3_bucket

  vpc_subnet_ids         = var.lambda_function_vpc_subnet_ids
  vpc_security_group_ids = var.lambda_function_vpc_security_group_ids

  tags = merge(var.tags, var.lambda_function_tags)

  depends_on = [
    aws_cloudwatch_log_group.this,
    null_resource.this
  ]
}
