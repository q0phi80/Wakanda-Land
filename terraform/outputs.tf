output "Guacamole-Dashboard-Access" {
  value       = "http://${aws_instance.guac-server.public_ip}:8080/guacamole"
  description = "URL of Guacamole Dashboard. Access this at <ip-address:8080/guacamole>"
}

output "Guacozy-Dashboard-Access" {
  value       = "https://${aws_instance.guac-server.public_ip}"
  description = "URL of Guacozy Dashboard. Access this at <https:ip-address>"
}

output "timestamp" {
  value = formatdate("hh:mm", timestamp())
}