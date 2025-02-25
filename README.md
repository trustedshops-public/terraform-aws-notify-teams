<!-- BEGIN_TF_DOCS -->
# AWS Notify Teams Terraform module
[![GitHub License](https://img.shields.io/badge/license-Apache--2-lightgrey.svg)](https://github.com/trustedshops-public/terraform-aws-notify-teams/blob/main/LICENSE)

---
> ℹ️ This project is forked and based on [terraform-aws-modules/terraform-aws-notify-slack](https://github.com/terraform-aws-modules/terraform-aws-notify-slack). It has the same license and
> contains some tweaks we made to improve the tool in general or make it work better with our infrastructure.
>
> Feel free to use it, fork it or base your own work on it.
---

This module creates an SNS topic (or uses an existing one) and an AWS Lambda function that sends notifications to Teams using the [incoming webhooks API](https://api.teams.com/incoming-webhooks).

Start by setting up an [incoming webhook integration](https://my.teams.com/services/new/incoming-webhook/) in your Teams workspace.

Doing serverless with Terraform? Check out [serverless.tf framework](https://serverless.tf), which aims to simplify all operations when working with the serverless in Terraform.

## Supported Features

- AWS Lambda runtime Python 3.8
- Create new SNS topic or use existing one
- Support plaintext and encrypted version of Teams webhook URL
- Most of Teams message options are customizable
- Various event types are supported, even generic messages:
  - AWS CloudWatch Alarms
  - AWS CloudWatch LogMetrics Alarms
  - AWS GuardDuty Findings

## Usage

```hcl
module "notify_teams" {
  source  = "git::https://github.com/trustedshops/terraform-aws-notify-teams.git?ref=v5.0.0"

  sns_topic_name = "teams-topic"

  teams_webhook_url = "https://hooks.teams.com/services/AAA/BBB/CCC"
}
```

## Using with Terraform Cloud Agents

[Terraform Cloud Agents](https://www.terraform.io/docs/cloud/workspaces/agent.html) are a paid feature, available as part of the Terraform Cloud for Business upgrade package.

This module requires Python 3.8. You can customize [tfc-agent](https://hub.docker.com/r/hashicorp/tfc-agent) to include Python using this sample `Dockerfile`:

```
FROM hashicorp/tfc-agent:latest
RUN apt-get -y update && apt-get -y install python3.8 python3-pip
ENTRYPOINT ["/bin/tfc-agent"]
```

## Use existing SNS topic or create new

If you want to subscribe the AWS Lambda Function created by this module to an existing SNS topic you should specify `create_sns_topic = false` as an argument and specify the name of existing SNS topic name in `sns_topic_name`.

## Examples

- [notify-teams-simple](https://github.com/terraform-aws-modules/terraform-aws-notify-teams/tree/master/examples/notify-teams-simple) - Creates SNS topic which sends messages to Teams channel.
- [cloudwatch-alerts-to-teams](https://github.com/terraform-aws-modules/terraform-aws-notify-teams/tree/master/examples/cloudwatch-alerts-to-teams) - End to end example which shows how to send AWS Cloudwatch alerts to Teams channel and use KMS to encrypt webhook URL.

## Local Development and Testing

See the [functions](https://github.com/terraform-aws-modules/terraform-aws-notify-teams/tree/master/functions) for further details.

# Module documentation

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.13.1 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 5.0 |
| <a name="requirement_null"></a> [null](#requirement\_null) | ~> 3.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.31.0 |
| <a name="provider_null"></a> [null](#provider\_null) | 3.2.2 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_lambda"></a> [lambda](#module\_lambda) | terraform-aws-modules/lambda/aws | 6.5.0 |

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_sns_topic.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_subscription.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |
| [null_resource.this](https://registry.terraform.io/providers/hashicorp/null/latest/docs/resources/resource) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_cloudwatch_log_group_kms_key_id"></a> [cloudwatch\_log\_group\_kms\_key\_id](#input\_cloudwatch\_log\_group\_kms\_key\_id) | The ARN of the KMS Key to use when encrypting log data for Lambda | `string` | `null` | no |
| <a name="input_cloudwatch_log_group_retention_in_days"></a> [cloudwatch\_log\_group\_retention\_in\_days](#input\_cloudwatch\_log\_group\_retention\_in\_days) | Specifies the number of days you want to retain log events in log group for Lambda. | `number` | `0` | no |
| <a name="input_cloudwatch_log_group_tags"></a> [cloudwatch\_log\_group\_tags](#input\_cloudwatch\_log\_group\_tags) | Additional tags for the Cloudwatch log group | `map(string)` | `{}` | no |
| <a name="input_create"></a> [create](#input\_create) | Whether to create all resources | `bool` | `true` | no |
| <a name="input_create_sns_topic"></a> [create\_sns\_topic](#input\_create\_sns\_topic) | Whether to create new SNS topic | `bool` | `true` | no |
| <a name="input_iam_policy_path"></a> [iam\_policy\_path](#input\_iam\_policy\_path) | Path of policies to that should be added to IAM role for Lambda Function | `string` | `null` | no |
| <a name="input_iam_role_boundary_policy_arn"></a> [iam\_role\_boundary\_policy\_arn](#input\_iam\_role\_boundary\_policy\_arn) | The ARN of the policy that is used to set the permissions boundary for the role | `string` | `null` | no |
| <a name="input_iam_role_name_prefix"></a> [iam\_role\_name\_prefix](#input\_iam\_role\_name\_prefix) | A unique role name beginning with the specified prefix | `string` | `"lambda"` | no |
| <a name="input_iam_role_path"></a> [iam\_role\_path](#input\_iam\_role\_path) | Path of IAM role to use for Lambda Function | `string` | `null` | no |
| <a name="input_iam_role_tags"></a> [iam\_role\_tags](#input\_iam\_role\_tags) | Additional tags for the IAM role | `map(string)` | `{}` | no |
| <a name="input_kms_key_arn"></a> [kms\_key\_arn](#input\_kms\_key\_arn) | ARN of the KMS key used for decrypting teams webhook url | `string` | `""` | no |
| <a name="input_lambda_debug"></a> [lambda\_debug](#input\_lambda\_debug) | Enabled debug outputs | `bool` | `false` | no |
| <a name="input_lambda_description"></a> [lambda\_description](#input\_lambda\_description) | The description of the Lambda function | `string` | `null` | no |
| <a name="input_lambda_function_ephemeral_storage_size"></a> [lambda\_function\_ephemeral\_storage\_size](#input\_lambda\_function\_ephemeral\_storage\_size) | Amount of ephemeral storage (/tmp) in MB your Lambda Function can use at runtime. Valid value between 512 MB to 10,240 MB (10 GB). | `number` | `512` | no |
| <a name="input_lambda_function_name"></a> [lambda\_function\_name](#input\_lambda\_function\_name) | The name of the Lambda function to create | `string` | `"notify_teams"` | no |
| <a name="input_lambda_function_s3_bucket"></a> [lambda\_function\_s3\_bucket](#input\_lambda\_function\_s3\_bucket) | S3 bucket to store artifacts | `string` | `null` | no |
| <a name="input_lambda_function_store_on_s3"></a> [lambda\_function\_store\_on\_s3](#input\_lambda\_function\_store\_on\_s3) | Whether to store produced artifacts on S3 or locally. | `bool` | `false` | no |
| <a name="input_lambda_function_tags"></a> [lambda\_function\_tags](#input\_lambda\_function\_tags) | Additional tags for the Lambda function | `map(string)` | `{}` | no |
| <a name="input_lambda_function_vpc_security_group_ids"></a> [lambda\_function\_vpc\_security\_group\_ids](#input\_lambda\_function\_vpc\_security\_group\_ids) | List of security group ids when Lambda Function should run in the VPC. | `list(string)` | `null` | no |
| <a name="input_lambda_function_vpc_subnet_ids"></a> [lambda\_function\_vpc\_subnet\_ids](#input\_lambda\_function\_vpc\_subnet\_ids) | List of subnet ids when Lambda Function should run in the VPC. Usually private or intra subnets. | `list(string)` | `null` | no |
| <a name="input_lambda_role"></a> [lambda\_role](#input\_lambda\_role) | IAM role attached to the Lambda Function.  If this is set then a role will not be created for you. | `string` | `""` | no |
| <a name="input_log_events"></a> [log\_events](#input\_log\_events) | Boolean flag to enabled/disable logging of incoming events | `bool` | `false` | no |
| <a name="input_recreate_missing_package"></a> [recreate\_missing\_package](#input\_recreate\_missing\_package) | Whether to recreate missing Lambda package if it is missing locally or not | `bool` | `true` | no |
| <a name="input_reserved_concurrent_executions"></a> [reserved\_concurrent\_executions](#input\_reserved\_concurrent\_executions) | The amount of reserved concurrent executions for this lambda function. A value of 0 disables lambda from being triggered and -1 removes any concurrency limitations | `number` | `-1` | no |
| <a name="input_sns_topic_kms_key_id"></a> [sns\_topic\_kms\_key\_id](#input\_sns\_topic\_kms\_key\_id) | ARN of the KMS key used for enabling SSE on the topic | `string` | `""` | no |
| <a name="input_sns_topic_name"></a> [sns\_topic\_name](#input\_sns\_topic\_name) | The name of the SNS topic to create | `string` | n/a | yes |
| <a name="input_sns_topic_tags"></a> [sns\_topic\_tags](#input\_sns\_topic\_tags) | Additional tags for the SNS topic | `map(string)` | `{}` | no |
| <a name="input_subscription_filter_policy"></a> [subscription\_filter\_policy](#input\_subscription\_filter\_policy) | (Optional) A valid filter policy that will be used in the subscription to filter messages seen by the target resource. | `string` | `null` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to add to all resources | `map(string)` | `{}` | no |
| <a name="input_teams_webhook_url"></a> [teams\_webhook\_url](#input\_teams\_webhook\_url) | The URL of Teams webhook | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_lambda_cloudwatch_log_group_arn"></a> [lambda\_cloudwatch\_log\_group\_arn](#output\_lambda\_cloudwatch\_log\_group\_arn) | The Amazon Resource Name (ARN) specifying the log group |
| <a name="output_lambda_iam_role_arn"></a> [lambda\_iam\_role\_arn](#output\_lambda\_iam\_role\_arn) | The ARN of the IAM role used by Lambda function |
| <a name="output_lambda_iam_role_name"></a> [lambda\_iam\_role\_name](#output\_lambda\_iam\_role\_name) | The name of the IAM role used by Lambda function |
| <a name="output_notify_teams_lambda_function_arn"></a> [notify\_teams\_lambda\_function\_arn](#output\_notify\_teams\_lambda\_function\_arn) | The ARN of the Lambda function |
| <a name="output_notify_teams_lambda_function_invoke_arn"></a> [notify\_teams\_lambda\_function\_invoke\_arn](#output\_notify\_teams\_lambda\_function\_invoke\_arn) | The ARN to be used for invoking Lambda function from API Gateway |
| <a name="output_notify_teams_lambda_function_last_modified"></a> [notify\_teams\_lambda\_function\_last\_modified](#output\_notify\_teams\_lambda\_function\_last\_modified) | The date Lambda function was last modified |
| <a name="output_notify_teams_lambda_function_name"></a> [notify\_teams\_lambda\_function\_name](#output\_notify\_teams\_lambda\_function\_name) | The name of the Lambda function |
| <a name="output_notify_teams_lambda_function_version"></a> [notify\_teams\_lambda\_function\_version](#output\_notify\_teams\_lambda\_function\_version) | Latest published version of your Lambda function |
| <a name="output_teams_topic_arn"></a> [teams\_topic\_arn](#output\_teams\_topic\_arn) | The ARN of the SNS topic from which messages will be sent to Teams |
| <a name="output_this_teams_topic_arn"></a> [this\_teams\_topic\_arn](#output\_this\_teams\_topic\_arn) | The ARN of the SNS topic from which messages will be sent to Teams (backward compatibility for version 4.x) |

## Development

### Development requirements

The listed tools are required to develop within this repository:
- [pre-commit](https://pre-commit.com/)
- [terraform-docs](https://github.com/terraform-docs/terraform-docs)
- [terraform](https://www.terraform.io/)
- [tfsec](https://tfsec.dev/)
- [tflint](https://github.com/terraform-linters/tflint)
- [tflint-ruleset-tps-codestyle](https://github.com/trustedshops/tflint-ruleset-tps-codestyle)

To easily install all of them in one step, you can use the instructions provided [here](https://github.com/trustedshops/aws-toolbox/blob/master/docs/docs/setting-up-awsume.md)

### Commit message format

We have very precise rules over how our Git commit messages must be formatted.

This format leads to **easier to read commit history** and the ability to create auomated reeleases with semantic-commit.

```
<type>(<scope>): <short summary>
  │       │             │
  │       │             └─⫸ Summary in present tense. Not capitalized. No period at the end.
  │       │
  │       └─⫸ Commit Scope: This is usually a ticket number, if available
  │
  └─⫸ Commit Type: build|ci|docs|feat|fix|perf|refactor|test
```

The `<type>` and `<summary>` fields are mandatory, the `(<scope>)` field is optional.

Example: `feat(TPSDO-1337): added option for additional environment variables`

#### Release type per commit message

| Commit message           | Release type     |
|--------------------------|------------------|
| fix(scope): summary      | Patch Release    |
| feat(scope): summary     | Feature Release  |
| perf(scope): summary     | Breaking Release |
| BREAKING CHANGE: summary | Breaking Release |

### README Header / Footer

- The header for the README is located in [.readme-header.md](.readme-header.md). If you change it, you also need to regenerate the README
- The footer for the README is located in [.readme-footer.md](.readme-footer.md). If you change it, you also need to regenerate the README
<!-- END_TF_DOCS -->