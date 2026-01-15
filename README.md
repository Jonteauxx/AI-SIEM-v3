# AXS ICT Hybrid SOC Agent v2.0

AI-aangedreven Beveiligingslog Analyse Platform met Machine Learning mogelijkheden.

## Functies

- **Real-time Log Analyse** - Analyseert beveiligingslogs met behulp van Ollama LLM
- **Lerend Systeem** - Leert van gebruikersfeedback om nauwkeurigheid te verbeteren
- **Live Dashboard** - Real-time statistieken en log visualisatie
- **Auto-Indexering** - Indexeert geanalyseerde logs automatisch naar OpenSearch
- **Dreigingsdetectie** - Identificeert beveiligingsdreigingen en anomalieën
- **Patroonherkenning** - Onthoudt en hergebruikt geleerde logpatronen

## Architectuur

```
Fluentd/Logs → TCP Ingestor (Poort 5046)
                    ↓
              SQLite Wachtrij (PENDING)
                    ↓
              AI Processor (Ollama LLM)
                    ↓
         OpenSearch/Elasticsearch (Geïndexeerd)
                    ↓
            FastAPI Dashboard (Poort 8000)
```

## Vereisten

1. **Python 3.9+**
2. **Ollama** - [Installeren via ollama.ai](https://ollama.ai)
3. **OpenSearch/Elasticsearch** - Draaiende instantie
4. **Fluentd** (optioneel) - Voor log doorsturen

## Installatie

### 1. Klonen en Opzetten

```bash
# Kloon de repository
git clone <jouw-repo>
cd soc-agent

# Maak virtuele omgeving aan
python -m venv venv
source venv/bin/activate  # Op Windows: venv\Scripts\activate

# Installeer afhankelijkheden
pip install -r requirements.txt
```

### 2. Omgeving Configureren

```bash
# Kopieer voorbeeld omgevingsbestand
cp .env.example .env

# Bewerk .env met jouw instellingen
nano .env
```

### 3. Ollama Model Installeren

```bash
# Installeer het Mistral 7B model (of jouw voorkeurmodel)
ollama pull mistral:7b

# Controleer of het werkt
ollama list
```

### 4. OpenSearch/Elasticsearch Opzetten

Zorg ervoor dat je OpenSearch/Elasticsearch instantie draait en bereikbaar is:

```bash
# Test verbinding
curl http://10.10.200.105:9201
```

## Applicatie Starten

### Start de SOC Agent

```bash
python main.py
```

Je zou moeten zien:
```
INFO - Starting AXS ICT Hybrid SOC Agent v2.0.0
INFO - Configuration validated successfully
INFO - Database initialized successfully
INFO - Created index: ai-analyzed-logs
INFO - TCP Ingestor listening on 0.0.0.0:5046
INFO - Processor loop started
INFO - Starting API server on 0.0.0.0:8000
```

### Toegang tot het Dashboard

Open je browser naar: **http://localhost:8000**

## API Eindpunten

### Gezondheidscontrole
```bash
GET /health
```

### Dashboard Statistieken
```bash
GET /api/dashboard-metrics
```

### Logs Ophalen
```bash
GET /api/logs?panel=Active%20Alerts
```

Panelen: `Total Logs`, `Active Alerts`, `Threats Blocked`

### Leren van Feedback
```bash
POST /api/learn
Content-Type: application/json

{
  "log_id": 123,
  "new_severity": "High",
  "reason": "Dit is eigenlijk een brute force poging"
}
```

### Kennisbank Bekijken
```bash
GET /api/knowledge-base
```

## Logs Versturen naar de Agent

### Met Fluentd

Configureer Fluentd om logs door te sturen:

```xml
<match **>
  @type forward
  <server>
    host 127.0.0.1
    port 5046
  </server>
</match>
```

### Met Python Script

```python
import socket
import msgpack

def send_log(message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 5046))

    data = msgpack.packb([
        "tag.name",
        [[time.time(), {"message": message}]]
    ])

    sock.send(data)
    sock.close()

# Verstuur een test log
send_log("Gebruiker login mislukt vanaf IP 192.168.1.100")
```

## Monitoring

### Systeemgezondheid Controleren

```bash
curl http://localhost:8000/health
```

Respons:
```json
{
  "status": "healthy",
  "timestamp": "2024-12-17T10:30:00",
  "checks": {
    "database": true,
    "opensearch": true,
    "ollama": true,
    "ingestor": true
  }
}
```

### Logs Bekijken

```bash
# Bekijk applicatie logs
tail -f soc_agent.log

# Controleer verwerkte logs aantal
curl http://localhost:8000/api/analysis-status
```

## Configuratie Opties

### Omgevingsvariabelen

| Variabele | Standaard | Beschrijving |
|-----------|-----------|--------------|
| `ES_HOSTS` | `http://10.10.200.105:9201` | OpenSearch URL |
| `ES_INDEX` | `ai-analyzed-logs` | Index naam |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API URL |
| `OLLAMA_MODEL` | `mistral:7b` | Te gebruiken LLM model |
| `LISTEN_PORT` | `5046` | TCP poort voor log ingestie |
| `API_PORT` | `8000` | Web dashboard poort |
| `MAX_RETRIES` | `3` | OpenSearch herhaalpogingen |

### Aanbevolen Modellen

- **mistral:7b** - Snel, goede balans (standaard)
- **llama2:13b** - Betere nauwkeurigheid, langzamer
- **codellama:7b** - Goed voor technische logs
- **mixtral:8x7b** - Beste kwaliteit, vereist meer bronnen

## Probleemoplossing

### Ollama Verbinding Mislukt

```bash
# Controleer of Ollama draait
curl http://localhost:11434/api/version

# Herstart Ollama
ollama serve
```

### OpenSearch Verbindingsproblemen

```bash
# Controleer connectiviteit
curl -X GET "http://10.10.200.105:9201/_cluster/health"

# Controleer index
curl -X GET "http://10.10.200.105:9201/ai-analyzed-logs/_search?size=1"
```

### Geen Logs Worden Verwerkt

1. Controleer of logs worden ontvangen:
   ```bash
   sqlite3 ai_agent_logs.db "SELECT COUNT(*) FROM raw_logs WHERE status='PENDING'"
   ```

2. Controleer processor logs:
   ```bash
   grep "PROCESSOR" soc_agent.log
   ```

3. Verifieer dat Ollama reageert:
   ```bash
   ollama run mistral:7b "Test bericht"
   ```

### Hoog CPU Gebruik

- Overweeg een kleiner model te gebruiken (bijv. `mistral:7b` in plaats van `mixtral:8x7b`)
- Verklein de batch grootte in processor (verander LIMIT in query)
- Voeg vertragingen toe tussen verwerkingsbatches

## Beveiligingsoverwegingen

1. **Wijzig standaard poorten** in productie
2. **Schakel authenticatie in** op API eindpunten
3. **Configureer CORS** correct in `main.py`
4. **Gebruik HTTPS** met reverse proxy (nginx/traefik)
5. **Beperk netwerktoegang** tot OpenSearch
6. **Regelmatige backups** van SQLite database

## Ontwikkeling

### Draaien in Ontwikkelmodus

```bash
# Schakel debug logging in
export LOG_LEVEL=DEBUG
python main.py
```

### Tests Uitvoeren

```bash
pytest tests/
```

## Prestatie Optimalisatie

### Database Optimalisatie

```sql
-- Voeg indexen toe voor snellere queries
CREATE INDEX idx_status ON raw_logs(status);
CREATE INDEX idx_timestamp ON raw_logs(timestamp);
```

### OpenSearch Optimalisatie

```bash
# Verhoog verversingsinterval
PUT /ai-analyzed-logs/_settings
{
  "index": {
    "refresh_interval": "30s"
  }
}
```

## Bijdragen

1. Fork de repository
2. Maak een feature branch (`git checkout -b feature/geweldige-feature`)
3. Commit wijzigingen (`git commit -m 'Voeg geweldige feature toe'`)
4. Push naar branch (`git push origin feature/geweldige-feature`)
5. Open een Pull Request


