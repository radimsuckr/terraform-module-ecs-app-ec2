# ECS App (EC2)

This module creates resources for a containarized ECS application.

## EC2

This is a version for EC2 backed ECS cluster.

The service is behind a load balancer which means it is exposed. A HTTP healthcheck is required.

## Required resources

- ECS cluster
- VPC
- VPC subnets
- Application Load Balancer (ALB)

## Creates resources

- ECS service
- ECS task definition
- Container definition (using Cloudposse module)
- ECR repository
- IAM task execution role
- Custom policy attachment
- CloudWatch log group
- Security group
- ALB target group
- ALB listener rule

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 0.13 |

## Providers

| Name | Version |
|------|---------|
| aws | n/a |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| alb\_arn | application load balancer under which target group and services will be registered | `any` | n/a | yes |
| app | app name | `any` | n/a | yes |
| cluster\_name | ecs cluster name where the services will be registered | `any` | n/a | yes |
| cooldown | n/a | `number` | `60` | no |
| cpu | CPU reservation for the task | `number` | `256` | no |
| deregistration\_delay | n/a | `number` | `30` | no |
| environment | n/a | `list` | `[]` | no |
| healthcheck\_grace | n/a | `number` | `0` | no |
| healthcheck\_healthy\_threshold | n/a | `number` | `3` | no |
| healthcheck\_interval | n/a | `number` | `60` | no |
| healthcheck\_matcher | n/a | `string` | `"200"` | no |
| healthcheck\_path | n/a | `string` | `"/"` | no |
| healthcheck\_timeout | n/a | `number` | `5` | no |
| healthcheck\_unhealthy\_threshold | n/a | `number` | `3` | no |
| image | override image - disables creating ecr repository | `string` | `""` | no |
| load\_balancing\_algorithm\_type | n/a | `string` | `"least_outstanding_requests"` | no |
| log\_retention | for how many days to keep app logs | `number` | `30` | no |
| max\_capacity | n/a | `number` | `1` | no |
| max\_healthy | n/a | `number` | `200` | no |
| memory | MEM reservation for the task | `number` | `256` | no |
| memory\_limit | MEM hard limit for the task | `number` | `0` | no |
| min\_capacity | n/a | `number` | `1` | no |
| min\_healthy | n/a | `number` | `50` | no |
| name | name of this specific service | `any` | n/a | yes |
| placement\_constraint\_expression | n/a | `string` | `"agentConnected==true"` | no |
| placement\_constraint\_type | n/a | `string` | `"memberOf"` | no |
| policy | IAM Policy heredoc to use with task | `string` | `""` | no |
| port | port on which the service listens | `number` | `80` | no |
| priority | listener rule priority - must be unique to each ecs-app (module) | `any` | n/a | yes |
| private\_subnet\_ids | list of private subnets where to provision services | `list` | n/a | yes |
| project | project name | `any` | n/a | yes |
| scale\_down | n/a | `number` | `30` | no |
| scale\_up | n/a | `number` | `80` | no |
| scheduling\_strategy | n/a | `string` | `"REPLICA"` | no |
| secrets | n/a | `list` | `[]` | no |
| stage | stage name | `any` | n/a | yes |
| tags | n/a | `map` | `{}` | no |
| url | url for the alb listener | `any` | n/a | yes |
| vpc\_id | vpc id - used in target group, security group etc | `any` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| cloudwatch\_log\_group\_arn | n/a |
| ecr\_repository | n/a |
