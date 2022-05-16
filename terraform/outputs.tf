output "guacamole-login-url" {
  value       = "http://${aws_instance.guac-server.public_ip}:8080/guacamole"
  description = "URL of Guacamole Dashboard. Access this at <ip-address:8080/guacamole>"
}
output "timestamp" {
  value = formatdate("hh:mm", timestamp())
}