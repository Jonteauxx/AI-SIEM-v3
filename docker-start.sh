#!/bin/bash
# AI-SIEM v3 - Docker Quick Start Script

set -e

echo "=============================================="
echo "AI-SIEM v3 - Docker Quick Start"
echo "=============================================="

# Check for required tools
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || command -v docker compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed. Aborting." >&2; exit 1; }

# Use docker compose v2 if available
if command -v docker compose &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

# Copy .env if not exists
if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo "IMPORTANT: Edit .env to configure your deployment!"
fi

# Parse command line arguments
case "${1:-start}" in
    start)
        echo "Starting AI-SIEM services..."
        $COMPOSE_CMD up -d
        ;;
    start-all)
        echo "Starting AI-SIEM services with Nginx (production profile)..."
        $COMPOSE_CMD --profile production up -d
        ;;
    stop)
        echo "Stopping AI-SIEM services..."
        $COMPOSE_CMD down
        ;;
    restart)
        echo "Restarting AI-SIEM services..."
        $COMPOSE_CMD restart
        ;;
    logs)
        echo "Showing logs..."
        $COMPOSE_CMD logs -f ${2:-}
        ;;
    build)
        echo "Building AI-SIEM images..."
        $COMPOSE_CMD build --no-cache
        ;;
    pull-model)
        echo "Pulling Ollama model..."
        docker exec -it siem-ollama ollama pull ${2:-mistral:7b}
        ;;
    status)
        echo "Checking service status..."
        $COMPOSE_CMD ps
        ;;
    health)
        echo "Checking health..."
        curl -s http://localhost:8000/health | python3 -m json.tool
        ;;
    shell)
        echo "Opening shell in siem-api container..."
        docker exec -it siem-api /bin/bash
        ;;
    clean)
        echo "Stopping and removing all containers and volumes..."
        $COMPOSE_CMD down -v
        ;;
    *)
        echo "Usage: $0 {start|start-all|stop|restart|logs|build|pull-model|status|health|shell|clean}"
        echo ""
        echo "Commands:"
        echo "  start      - Start core services (default)"
        echo "  start-all  - Start all services including Nginx"
        echo "  stop       - Stop all services"
        echo "  restart    - Restart all services"
        echo "  logs       - Show logs (optionally specify service name)"
        echo "  build      - Build Docker images"
        echo "  pull-model - Pull Ollama model (default: mistral:7b)"
        echo "  status     - Show service status"
        echo "  health     - Check SIEM health endpoint"
        echo "  shell      - Open shell in siem-api container"
        echo "  clean      - Remove all containers and volumes"
        exit 1
        ;;
esac

echo ""
echo "=============================================="
echo "Services:"
echo "  - SIEM Dashboard: http://localhost:8000"
echo "  - Grafana:        http://localhost:3000"
echo "  - Prometheus:     http://localhost:9090"
echo "  - OpenSearch:     http://localhost:9200"
echo "  - OS Dashboards:  http://localhost:5601"
echo "=============================================="
