.PHONY: help up-fresh down logs clean proxy gateway full

# Default target
help:
	@echo "SSH Reverse Tunnel - Docker Management"
	@echo ""
	@echo "Available commands:"
	@echo "  proxy     - Start proxy service only"
	@echo "  gateway   - Start gateway services only (requires proxy to be running)"
	@echo "  full      - Start all services (proxy + gateways)"
	@echo "  up-fresh  - Rebuild and start all services (same as full)"
	@echo "  down      - Stop all services"
	@echo "  logs      - Show logs for all services"
	@echo "  clean     - Stop and remove all containers, networks, and volumes"

# Start proxy service only
proxy:
	docker compose build --no-cache --pull
	docker compose --profile proxy-only up -d --force-recreate

# Start gateway services only (requires proxy to be running)
gateway:
	docker compose build --no-cache --pull
	docker compose --profile gateway-only up -d --force-recreate

# Start all services (proxy + gateways)
full:
	docker compose build --no-cache --pull
	docker compose --profile full up -d --force-recreate

# Rebuild and start all services (same as full)
up-fresh:
	docker compose build --no-cache --pull
	docker compose --profile full up -d --force-recreate

# Stop all services
down:
	docker compose down

# Show logs
logs:
	docker compose logs

# Clean everything
clean:
	docker compose down -v --rmi all 