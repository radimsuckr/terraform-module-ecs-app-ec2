resource "aws_cloudwatch_log_group" "application_logs" {
  name              = local.name
  retention_in_days = var.log_retention
  tags              = var.tags
}

output "cloudwatch_log_group_arn" {
  value = aws_cloudwatch_log_group.application_logs.arn
}
