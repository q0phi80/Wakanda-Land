output "guac-server_ip" {
  value       = "http://${aws_instance.guac-server.public_ip}:8080/guacamole"
  description = "URL of Guacamole Dashboard. Access this at <ip-address:8080/guacamole>"
}
output "systems_count" {
  description = "Number of systems provisioned"
  value       = length(ec2_instances.instance_ids)
}