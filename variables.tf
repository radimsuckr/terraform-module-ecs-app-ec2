variable "project" {
  description = "project name"
}

variable "stage" {
  description = "stage name"
}

variable "app" {
  description = "app name"
}

variable "name" {
  description = "name of this specific service"
}

variable "url" {
  description = "url for the alb listener"
}

variable "vpc_id" {
  description = "vpc id - used in target group, security group etc"
}

variable "alb_arn" {
  description = "application load balancer under which target group and services will be registered"
}

variable "private_subnet_ids" {
  description = "list of private subnets where to provision services"
  type        = list
}

variable "port" {
  description = "port on which the service listens"
  default     = 80
  type        = number
}

variable "environment" {
  default = []
  type    = list
}

variable "secrets" {
  default = []
  type    = list
}

variable "cpu" {
  description = "CPU reservation for the task"
  default     = 256
}

variable "memory" {
  description = "MEM reservation for the task"
  default     = 256
}

variable "memory_limit" {
  description = "MEM hard limit for the task"
  default     = 0
}

variable "cluster_name" {
  description = "ecs cluster name where the services will be registered"
}

variable "priority" {
  description = "listener rule priority - must be unique to each ecs-app (module)"
}

variable "image" {
  description = "override image - disables creating ecr repository"
  default     = ""
}

variable "log_retention" {
  description = "for how many days to keep app logs"
  default     = 30
}

variable "tags" {
  default = {}
}

variable "min_healthy" {
  default = 50
}

variable "max_healthy" {
  default = 200
}

variable "policy" {
  description = "IAM Policy heredoc to use with task"
  default     = ""
}

variable "max_capacity" {
  default = 1
}

variable "min_capacity" {
  default = 1
}

variable "scale_down" {
  default = 30
}

variable "scale_up" {
  default = 80
}

variable "cooldown" {
  default = 60
}

variable "healthcheck_path" {
  default = "/"
}

variable "healthcheck_interval" {
  default = 60
}

variable "healthcheck_timeout" {
  default = 5
}

variable "healthcheck_healthy_threshold" {
  default = 3
}

variable "healthcheck_unhealthy_threshold" {
  default = 3
}

variable "healthcheck_matcher" {
  default = "200"
}

variable "healthcheck_grace" {
  default = 0
}

variable "scheduling_strategy" {
  default = "REPLICA"
}

variable "deregistration_delay" {
  default = 30
}

variable "load_balancing_algorithm_type" {
  default = "least_outstanding_requests"
}

variable "placement_constraint_type" {
  default = "memberOf"
}

variable "placement_constraint_expression" {
  default = "agentConnected==true"
}
