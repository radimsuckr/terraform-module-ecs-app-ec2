data "aws_iam_policy_document" "example" {
  statement {
    actions   = ["ssm:GetParameters"]
    resources = ["arn:aws:ssm:*:*:parameter/*"]
    effect    = "Allow"
  }

  statement {
    actions = ["s3:*"]

    resources = [
      "arn:aws:s3:::*",
      "arn:aws:s3:::*/*",
    ]

    effect = "Allow"
  }
}

module "example" {
  source = "git::https://github.com/trebidav/terraform-module-ecs-app-ec2/"

  # naming
  project = var.project
  app     = var.app
  stage   = var.stage
  name    = "example"

  # network
  vpc_id  = module.vpc.vpc_id
  alb_arn = aws_lb.alb.arn

  private_subnet_ids = [module.vpc.private_subnets]

  # global port
  port = 8000

  # container
  environment = [
    {
      name  = "EXAMPLE_VARIABLE"
      value = "example"
    },
  ]

  secrets = [
    {
      # example secret variable - ssm parameter reference
      name      = "EXAMPLE_SECRET"
      valueFrom = aws_ssm_parameter.EXAMPLE_SECRET.arn
    },
  ]

  # task 0 = no reservation
  memory = 256
  cpu    = 0

  # service
  cluster_name = module.ec2-cluster.ecs_cluster_name
  min_healthy  = 100
  max_healthy  = 200

  # healthcheck
  healthcheck_path                = "/healthcheck/"
  healthcheck_interval            = 30
  healthcheck_timeout             = 10
  healthcheck_healthy_threshold   = 3
  healthcheck_unhealthy_threshold = 5
  healthcheck_matcher             = "200"
  healthcheck_grace               = 180

  # alb listener
  priority = 10
  url      = "example.com"

  # autoscaling is off

  # access
  policy = data.aws_iam_policy_document.example.json
  # logs
  log_retention = 90
}

output "ecr_example" {
  value = module.example.ecr_repository
}
