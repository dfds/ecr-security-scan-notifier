# resource "aws_iam_role" "lambda_role" {
#   name_prefix = var.function_name

#   assume_role_policy = <<EOF
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Action": "sts:AssumeRole",
#       "Principal": {
#         "Service": "lambda.amazonaws.com"
#       },
#       "Effect": "Allow",
#       "Sid": ""
#     }
#   ]
# }
# EOF
# }

resource "aws_lambda_function" "ecr_to_slack" {
  filename      = "lambda_function_payload.zip"
  function_name = var.function_name
  role          = var.function_role
  handler       = "lambda_function.lambda_handler"

  #source_code_hash = filebase64sha256("lambda_function_payload.zip")

  runtime = "python3.7"
  timeout = "120"

  environment {
    variables = {
      slackChannel = var.slack_channel
      BOT_TOKEN    = var.bot_token
    }
  }
}


resource "aws_cloudwatch_event_rule" "ecr_scans_trigger" {
  name        = "ecr_scans_trigger"
  description = "Trigger lambda on each ECR scan"

  event_pattern = <<PATTERN
{
  "source": [
    "aws.ecr"
  ],
  "detail-type": [
    "ECR Image Scan"
  ]
}
PATTERN
}

resource "aws_lambda_permission" "ecr_to_slack" {
  statement_id  = "AllowExecutionFromEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ecr_to_slack.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ecr_scans_trigger.arn
}

# resource "aws_iam_role_policy" "ecr_permissions" {
#   name = "ecr_permissions"
#   role = aws_iam_role.lambda_role.id

#   policy = <<EOF
# {
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Effect": "Allow",
#             "Action": [
#                 "ecr:DescribeImageScanFindings"
#             ],
#             "Resource": "*"
#         }
#     ]
# }
# EOF
# }

resource "aws_cloudwatch_event_target" "lambda" {
  target_id = "Lambda"
  rule      = aws_cloudwatch_event_rule.ecr_scans_trigger.name
  arn       = aws_lambda_function.ecr_to_slack.arn
}

data "archive_file" "init" {
  type        = "zip"
  source_dir = "${path.module}/lambda_function"
  output_path = "${path.module}/lambda_function_payload.zip"
}
