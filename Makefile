.PHONY: help up-fresh down logs clean

# Default target
help:
	@echo "SSH Reverse Tunnel - Docker Management"
	@echo ""
	@echo "Available commands:"
	@echo "  up-fresh  - Rebuild and start all services"
	@echo "  down      - Stop all services"
	@echo "  logs      - Show logs for all services"
	@echo "  clean     - Stop and remove all containers, networks, and volumes"

# Rebuild and start all services
up-fresh:
	docker compose build --no-cache
	docker compose up -d

# Stop all services
down:
	docker compose down

# Show logs
logs:
	docker compose logs

# Clean everything
clean:
	docker compose down -v --rmi all 