resource "aws_lb_target_group" "application" {
  name                          = replace(local.name, "/(.{0,31})(.*)/", "$1")
  port                          = var.port
  protocol                      = "HTTP"
  target_type                   = "instance"
  vpc_id                        = var.vpc_id
  deregistration_delay          = var.deregistration_delay
  load_balancing_algorithm_type = var.load_balancing_algorithm_type

  health_check {
    interval            = var.healthcheck_interval
    timeout             = var.healthcheck_timeout
    healthy_threshold   = var.healthcheck_healthy_threshold
    unhealthy_threshold = var.healthcheck_unhealthy_threshold
    path                = var.healthcheck_path
    matcher             = var.healthcheck_matcher
  }

  tags = local.tags
}

data "aws_lb_listener" "selected443" {
  load_balancer_arn = var.alb_arn
  port              = 443
}

resource "aws_lb_listener_rule" "admin" {
  listener_arn = data.aws_lb_listener.selected443.arn
  priority     = var.priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.application.arn
  }

  condition {
    host_header {
      values = [var.url]
    }
  }

  depends_on = [aws_lb_target_group.application]
}
