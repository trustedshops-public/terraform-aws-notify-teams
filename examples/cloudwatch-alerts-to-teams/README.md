<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.13.1 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.0 |
| <a name="requirement_random"></a> [random](#requirement\_random) | >= 3.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.31.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_notify_teams"></a> [notify\_teams](#module\_notify\_teams) | ../../ | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_metric_alarm.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_kms_ciphertext.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_ciphertext) | resource |
| [aws_kms_key.this](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |

## Inputs

No inputs.

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_lambda_iam_role_arn"></a> [lambda\_iam\_role\_arn](#output\_lambda\_iam\_role\_arn) | The ARN of the IAM role used by Lambda function |
| <a name="output_lambda_iam_role_name"></a> [lambda\_iam\_role\_name](#output\_lambda\_iam\_role\_name) | The name of the IAM role used by Lambda function |
| <a name="output_notify_teams_lambda_function_arn"></a> [notify\_teams\_lambda\_function\_arn](#output\_notify\_teams\_lambda\_function\_arn) | The ARN of the Lambda function |
| <a name="output_notify_teams_lambda_function_invoke_arn"></a> [notify\_teams\_lambda\_function\_invoke\_arn](#output\_notify\_teams\_lambda\_function\_invoke\_arn) | The ARN to be used for invoking Lambda function from API Gateway |
| <a name="output_notify_teams_lambda_function_last_modified"></a> [notify\_teams\_lambda\_function\_last\_modified](#output\_notify\_teams\_lambda\_function\_last\_modified) | The date Lambda function was last modified |
| <a name="output_notify_teams_lambda_function_name"></a> [notify\_teams\_lambda\_function\_name](#output\_notify\_teams\_lambda\_function\_name) | The name of the Lambda function |
| <a name="output_notify_teams_lambda_function_version"></a> [notify\_teams\_lambda\_function\_version](#output\_notify\_teams\_lambda\_function\_version) | Latest published version of your Lambda function |
| <a name="output_sns_topic_arn"></a> [sns\_topic\_arn](#output\_sns\_topic\_arn) | The ARN of the SNS topic from which messages will be sent to Teams |
<!-- END_TF_DOCS -->