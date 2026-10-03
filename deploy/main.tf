# Test deployment: a CloudTrail trail plus both detection paths.
#
#   CloudTrail -> CloudWatch Logs -> metric filters -> alarms -> SNS (cloudwatch topic)
#   CloudTrail -> EventBridge rules -------------------------> SNS (eventbridge topic)
#
# Destroy it after testing: terraform destroy

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# -----------------------------------------------------------------------------
# VARIABLES
# -----------------------------------------------------------------------------

variable "region" {
  description = "Project Region. All resources are created here."
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address for alerts. Set it in terraform.tfvars (ignored by Git)."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "detection-test"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "${var.name_prefix}-trail"
  trail_arn  = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
}

# -----------------------------------------------------------------------------
# S3 BUCKET FOR CLOUDTRAIL LOG FILES
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "trail" {
  bucket        = "${var.name_prefix}-trail-${local.account_id}"
  force_destroy = true # lets terraform destroy delete the log files too
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

# -----------------------------------------------------------------------------
# CLOUDWATCH LOG GROUP AND ROLE FOR CLOUDTRAIL
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "trail" {
  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = 1
}

data "aws_iam_policy_document" "trail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_iam_role" "trail_to_logs" {
  name               = "${var.name_prefix}-trail-to-logs"
  assume_role_policy = data.aws_iam_policy_document.trail_assume.json
}

data "aws_iam_policy_document" "trail_to_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.trail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "trail_to_logs" {
  name   = "write-to-log-group"
  role   = aws_iam_role.trail_to_logs.id
  policy = data.aws_iam_policy_document.trail_to_logs.json
}

# -----------------------------------------------------------------------------
# CLOUDTRAIL TRAIL
# -----------------------------------------------------------------------------

resource "aws_cloudtrail" "this" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.trail_to_logs.arn

  depends_on = [aws_s3_bucket_policy.trail, aws_iam_role_policy.trail_to_logs]
}

# -----------------------------------------------------------------------------
# SNS TOPICS (one per path, so neither topic policy can block the other path)
# -----------------------------------------------------------------------------

resource "aws_sns_topic" "eventbridge" {
  name = "${var.name_prefix}-eventbridge-alerts"
}

resource "aws_sns_topic" "cloudwatch" {
  name = "${var.name_prefix}-cloudwatch-alerts"
}

resource "aws_sns_topic_subscription" "eventbridge_email" {
  topic_arn = aws_sns_topic.eventbridge.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_subscription" "cloudwatch_email" {
  topic_arn = aws_sns_topic.cloudwatch.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# -----------------------------------------------------------------------------
# DETECTION RULES (the two modules in this repo)
# -----------------------------------------------------------------------------

module "cloudwatch_rules" {
  source = "../cloudwatch"

  cloudtrail_log_group_name = aws_cloudwatch_log_group.trail.name
  sns_topic_arn             = aws_sns_topic.cloudwatch.arn
}

module "eventbridge_rules" {
  source = "../eventbridge"

  sns_topic_arn = aws_sns_topic.eventbridge.arn
}

# -----------------------------------------------------------------------------
# OUTPUTS
# -----------------------------------------------------------------------------

output "trail_name" {
  value = aws_cloudtrail.this.name
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.trail.name
}
