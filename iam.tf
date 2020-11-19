// task execution role
data "aws_iam_policy" "ecs_task_execution" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_task_execution" {
  name               = "${local.name_underscore}_ecs_task_execution_role"
  assume_role_policy = data.aws_iam_policy.ecs_task_execution.json
  tags               = local.tags
}

// ecr access (if ecr is created)
data "aws_iam_policy" "ecr_access" {
  statement {
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetAuthorizationToken",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ecr_access" {
  count = var.image == "" ? 1 : 0

  name        = "${local.name}-ecr"
  path        = "/"
  description = "Policy for service ${local.name}-${var.name}"
  policy      = data.aws_iam_policy.ecr_access.json
}

resource "aws_iam_role_policy_attachment" "ecr_repository" {
  count = var.image == "" ? 1 : 0

  role       = aws_iam_role.ecs_task_execution.id
  policy_arn = aws_iam_policy.ecr_access.arn
}

// cloudwatch logs access
data "aws_iam_policy" "logs_policy" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_policy" "logs_policy" {
  name        = "${local.name}-logs"
  path        = "/"
  description = "Policy for service ${local.name}-${var.name}"
  policy      = data.aws_iam_policy.logs_policy.json
}

resource "aws_iam_role_policy_attachment" "application_logs" {
  role       = aws_iam_role.ecs_task_execution.id
  policy_arn = aws_iam_policy.logs_policy.arn
}

// custom policy
resource "aws_iam_policy" "service_policy" {
  count = var.policy == "" ? 0 : 1

  name        = "${local.name}-${var.name}"
  path        = "/"
  description = "Policy for service ${local.name}-${var.name}"
  policy      = var.policy
}

resource "aws_iam_role_policy_attachment" "service_policy" {
  count = var.policy == "" ? 0 : 1

  role       = aws_iam_role.ecs_task_execution.id
  policy_arn = aws_iam_policy.service_policy.arn
}
