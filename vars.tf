variable "aws_region" {
  type = string
  default = "eu-central-1"
}

## notifier
variable "function_name" {
    type    =   string
    default =   "ecr_findings_to_slack"
}

variable "slack_channel" {
    type    = string
    default = "#ecr-scans"
}

variable "bot_token" {
    type    = string
}

variable "function_role" {
    type    = string
}
