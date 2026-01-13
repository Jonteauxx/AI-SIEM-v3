# AI-SIEM v3 - AI-Powered Security Information and Event Management

An intelligent SIEM system that leverages Large Language Models (LLMs) to automatically analyze, classify, and provide actionable insights on security logs in real-time.

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.9+-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-teal)
![License](https://img.shields.io/badge/license-MIT-yellow)

## Features

### Core Capabilities
- **AI-Powered Log Analysis**: Uses Ollama (Mistral 7B) for intelligent log classification
- **Real-Time Processing**: Background threads process logs as they arrive
- **Automated Severity Classification**: Categorizes logs as Low, Medium, High, or Critical
- **Continuous Learning**: AI learns from user feedback to improve accuracy
- **Pattern Recognition**: Caches learned patterns for instant classification
- **Interactive Dashboard**: Modern web interface with live metrics
- **AI SOC Assistant**: Built-in chatbot for security analysis queries
- **Multi-Source Support**: Ingests logs via FluentD (TCP/msgpack)

### Technical Features
- **Fast API Backend**: Asynchronous Python web framework
- **Dual Storage**: SQLite for metadata + OpenSearch for log search (optional)
- **Rate Limiting**: Protection against API abuse
- **Health Monitoring**: Comprehensive health checks for all components
- **Graceful Degradation**: Continues operating when optional services are down
- **Retry Logic**: Exponential backoff for failed operations

## Architecture

```
┌─────────────────┐
│  Log Sources    │ (Servers, Firewalls, Apps)
└────────┬────────┘
         │
    ┌────▼────┐
    │ FluentD │ (Log Collector)
    └────┬────┘
         │ TCP/msgpack (Port 5046)
         │
┌────────▼─────────────────────────────────────────┐
│              AI-SIEM Application                  │
│                                                   │
│  ┌──────────────┐      ┌────────────────┐        │
│  │   Ingestor   │─────▶│   Processor    │        │
│  │  (TCP/5046)  │      │  (AI Analysis) │        │
│  └──────────────┘      └────────┬───────┘        │
│                                  │                │
│  ┌──────────────┐      ┌────────▼───────┐        │
│  │    Ollama    │◀─────│   Knowledge    │        │
│  │  (Mistral)   │      │      Base      │        │
│  └──────────────┘      └────────────────┘        │
│                                  │                │
│  ┌──────────────┐      ┌────────▼───────┐        │
│  │  OpenSearch  │◀─────│    SQLite      │        │
│  │  (Optional)  │      │   (Primary)    │        │
│  └──────────────┘      └────────────────┘        │
│                                  │                │
│         ┌────────────────────────▼──────┐         │
│         │   FastAPI REST API            │         │
│         │   (Port 8000)                 │         │
│         └────────────────────┬──────────┘         │
└──────────────────────────────┼────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Web Dashboard     │
                    │  (HTML/JS/CSS)      │
                    └─────────────────────┘
```

## Prerequisites

### Required
- **Python 3.9+**
- **Ollama** with Mistral 7B model
  ```bash
  # Install Ollama from https://ollama.ai
  ollama pull mistral:7b
  ```

### Optional
- **OpenSearch/Elasticsearch** for advanced log search
- **FluentD** for log collection

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/AI-SIEM-v3.git
cd AI-SIEM-v3
```

### 2. Set Up Python Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure Environment
```bash
cp .env.example .env
# Edit .env with your configuration
```

### 4. Start Ollama
```bash
ollama serve
# In another terminal:
ollama pull mistral:7b
```

### 5. Run the Application
```bash
python main.py
```

### 6. Access the Dashboard
Open your browser to: http://localhost:8000

## Configuration

### Environment Variables

Create a `.env` file (see `.env.example` for all options):

```env
# Essential Configuration
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=mistral:7b
API_PORT=8000
LISTEN_PORT=5046

# Optional: OpenSearch
ES_HOSTS=http://localhost:9200
ES_INDEX=ai-analyzed-logs

# Optional: Database
DB_NAME=ai_agent_logs.db
```

### FluentD Configuration

To forward logs to AI-SIEM, add this to your FluentD config:

```xml
<match syslog.**>
  @type forward
  <server>
    host localhost
    port 5046
  </server>
  <buffer>
    flush_interval 5s
  </buffer>
</match>
```

## Usage

### Dashboard Overview

The dashboard provides 7 key metrics:
1. **Total Logs**: All logs ingested
2. **Pending**: Logs awaiting analysis
3. **Processed**: Logs analyzed by AI
4. **Active Alerts**: High/Critical severity events
5. **Threats Blocked**: Detected attack patterns
6. **AI Learned Patterns**: User-corrected classifications
7. **System Status**: Health of LLM, API, and OpenSearch

### Analyzing Logs

1. Click any log row to view details
2. Review AI analysis and recommended actions
3. Correct severity if needed (AI learns from corrections)
4. Chat with AI assistant for deeper analysis

### Teaching the AI

When the AI misclassifies a log:
1. Open the log detail modal
2. Select the correct severity button
3. AI automatically learns the pattern
4. Future similar logs will be classified correctly

### API Endpoints

#### Health Check
```bash
curl http://localhost:8000/health
```

#### Get Dashboard Metrics
```bash
curl http://localhost:8000/api/dashboard-metrics
```

#### Get All Logs
```bash
curl http://localhost:8000/api/logs-all
```

#### Chat with AI
```bash
curl -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the top threats today?"}'
```

#### Teach AI (Correct Severity)
```bash
curl -X POST http://localhost:8000/api/learn \
  -H "Content-Type: application/json" \
  -d '{
    "log_id": 123,
    "new_severity": "High",
    "reason": "This is actually a brute force attempt"
  }'
```

## Project Structure

```
AI-SIEM-v3/
├── main.py                 # Core application (FastAPI + processing logic)
├── templates/
│   └── dashboard.html      # Web dashboard UI
├── requirements.txt        # Python dependencies
├── .env.example           # Configuration template
├── .gitignore             # Git ignore rules
├── CODE_REVIEW.md         # Detailed code analysis
├── README.md              # This file
├── ai_agent_logs.db       # SQLite database (created at runtime)
└── soc_agent.log          # Application logs (created at runtime)
```

## Development

### Running Tests
```bash
# Install dev dependencies
pip install pytest pytest-asyncio

# Run tests
pytest
```

### Code Quality
```bash
# Format code
black main.py

# Lint code
flake8 main.py

# Type checking
mypy main.py
```

## Deployment

### Production Recommendations

See `CODE_REVIEW.md` for comprehensive deployment guidance. Key recommendations:

1. **Security**
   - Implement authentication (JWT/OAuth2)
   - Use HTTPS/TLS
   - Restrict CORS origins
   - Encrypt database at rest

2. **Scalability**
   - Migrate to PostgreSQL
   - Use connection pooling
   - Deploy on multiple instances
   - Implement load balancing

3. **Reliability**
   - Set up automated backups
   - Implement log retention policies
   - Add alerting (email/Slack/PagerDuty)
   - Monitor with Prometheus + Grafana

4. **Docker Deployment**
   ```bash
   # Coming soon: Docker Compose configuration
   docker-compose up -d
   ```

## Troubleshooting

### Ollama Connection Failed
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Restart Ollama
ollama serve
```

### Database Locked Errors
```bash
# Stop application
# Delete database (data will be lost)
rm ai_agent_logs.db
# Restart application
python main.py
```

### Dashboard Not Loading
```bash
# Check if templates directory exists
ls templates/dashboard.html

# Verify API is running
curl http://localhost:8000/health
```

### Logs Not Being Processed
```bash
# Check processor thread status
tail -f soc_agent.log

# Verify database has pending logs
sqlite3 ai_agent_logs.db "SELECT COUNT(*) FROM raw_logs WHERE status='PENDING';"
```

## Roadmap

### Version 2.1 (Planned)
- [ ] Authentication & authorization
- [ ] Email/Slack alerting
- [ ] Log export (CSV/JSON/PDF)
- [ ] Advanced filtering (date ranges, severity, host)
- [ ] Freshdesk ticket integration

### Version 3.0 (Future)
- [ ] Multi-tenancy support
- [ ] Custom LLM fine-tuning
- [ ] Automated incident response playbooks
- [ ] Integration with SOAR platforms
- [ ] Machine learning-based anomaly detection
- [ ] Mobile application

## Performance

### Benchmarks (Single Instance)
- **Log Ingestion**: 500-1000 logs/minute
- **AI Processing**: 10-20 logs/minute (depends on LLM speed)
- **API Response Time**: <100ms (cached queries)
- **Dashboard Load Time**: <2 seconds

### Scalability
- **SQLite**: Up to 100K logs efficiently
- **PostgreSQL**: Millions of logs
- **OpenSearch**: Billions of logs with proper sharding

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Known Issues

See `CODE_REVIEW.md` for detailed issue tracking.

Critical issues have been fixed in v2.0.0:
- Database schema mismatch (FIXED)
- Template path error (FIXED)

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Support

For issues and questions:
- Check `CODE_REVIEW.md` for common problems
- Review the troubleshooting section above
- Open a GitHub issue

## Acknowledgments

- **Ollama** for providing local LLM inference
- **FastAPI** for the excellent web framework
- **OpenSearch** for powerful log search capabilities
- **FluentD** for flexible log collection

## Authors

- **AXS ICT** - Initial work

## Version History

### v2.0.0 (2026-01-13)
- AI-powered log analysis with Ollama
- Interactive web dashboard
- Real-time processing
- Knowledge base learning system
- Fixed critical database schema bug
- Fixed template path issue
- Added comprehensive documentation

### v1.0.0 (Previous)
- Basic log collection
- Manual analysis

---

**Made with by AXS ICT SOC Team**
