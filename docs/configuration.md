# Configuratie

Dit document beschrijft alle configuratie-opties voor de AXS ICT Hybrid SOC Agent.

## Omgevingsvariabelen

Configureer de applicatie via een `.env` bestand of systeemomgevingsvariabelen.

```bash
# Kopieer het voorbeeldbestand
cp .env.example .env

# Bewerk met je eigen instellingen
nano .env
```

### Beschikbare Variabelen

| Variabele | Standaard | Beschrijving |
|-----------|-----------|--------------|
| `DB_NAME` | `ai_agent_logs.db` | SQLite database bestandsnaam |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API URL |
| `OLLAMA_MODEL` | `mistral:7b` | Te gebruiken LLM model |
| `LISTEN_PORT` | `5046` | TCP poort voor log ingestie |
| `API_PORT` | `8000` | Web dashboard poort |
| `HOST_IP` | `0.0.0.0` | IP adres om op te luisteren |
| `MAX_RETRIES` | `3` | Herhaalpogingen bij fouten |
| `LOG_LEVEL` | `INFO` | Logging niveau (DEBUG, INFO, WARNING, ERROR) |

## AI Model Configuratie

### Aanbevolen Modellen

| Model | Snelheid | Nauwkeurigheid | Geheugen | Aanbevolen voor |
|-------|----------|----------------|----------|-----------------|
| `mistral:7b` | Snel | Goed | ~4GB | Standaard gebruik |
| `llama2:13b` | Medium | Zeer goed | ~8GB | Hogere nauwkeurigheid |
| `codellama:7b` | Snel | Goed | ~4GB | Technische logs |
| `mixtral:8x7b` | Langzaam | Uitstekend | ~26GB | Maximale kwaliteit |

### Model Installeren

```bash
# Installeer gewenst model
ollama pull mistral:7b

# Controleer beschikbare modellen
ollama list

# Test het model
ollama run mistral:7b "Test bericht"
```

## Database Configuratie

### SQLite Database

De applicatie gebruikt SQLite voor alle data opslag. De database wordt automatisch aangemaakt bij eerste start.

**Database bestand:** `ai_agent_logs.db` (configureerbaar via `DB_NAME`)

### Database Tabellen

| Tabel | Beschrijving |
|-------|--------------|
| `raw_logs` | Alle ontvangen en verwerkte logs |
| `ai_knowledge` | Geleerde patronen van gebruikersfeedback |
| `processing_errors` | Fouten tijdens verwerking |
| `alert_enrichment` | Verrijkte alert informatie |
| `hosts` | Bekende hosts en hun risicoscores |
| `incidents` | Aangemaakt incidenten |
| `correlation_rules` | Correlatie regels voor detectie |
| `correlated_events` | Gecorreleerde gebeurtenissen |

### Database Optimalisatie

Indexen worden automatisch aangemaakt. Voor extra optimalisatie:

```sql
-- Vacuüm de database (comprimeren)
VACUUM;

-- Analyseer voor query optimalisatie
ANALYZE;
```

### Database Backup

```bash
# Maak een backup
cp ai_agent_logs.db ai_agent_logs.db.backup

# Of met sqlite3
sqlite3 ai_agent_logs.db ".backup 'backup.db'"
```

## Netwerk Configuratie

### Poorten

| Poort | Service | Beschrijving |
|-------|---------|--------------|
| 5046 | TCP Ingestor | Ontvangt logs van Fluent Bit |
| 8000 | Web Dashboard | API en webinterface |
| 11434 | Ollama | LLM API (extern) |

### Firewall Regels

```bash
# Sta log ingestie toe
sudo ufw allow 5046/tcp

# Sta dashboard toegang toe (optioneel, alleen intern)
sudo ufw allow from 10.0.0.0/8 to any port 8000
```

## Beveiligingsconfiguratie

### Productie Aanbevelingen

1. **Wijzig standaard poorten** - Gebruik niet-standaard poorten in productie
2. **HTTPS inschakelen** - Gebruik een reverse proxy (nginx/traefik)
3. **CORS configureren** - Beperk toegestane origins in `main.py`
4. **Netwerktoegang beperken** - Firewall regels instellen
5. **Authenticatie toevoegen** - Implementeer API authenticatie
6. **Database backup** - Regelmatige backups van SQLite database

### Voorbeeld Nginx Reverse Proxy

```nginx
server {
    listen 443 ssl;
    server_name soc.example.com;

    ssl_certificate /etc/ssl/certs/soc.crt;
    ssl_certificate_key /etc/ssl/private/soc.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Logging Configuratie

### Log Niveaus

```bash
# Debug modus (uitgebreide logging)
export LOG_LEVEL=DEBUG
python main.py

# Productie modus (alleen waarschuwingen en fouten)
export LOG_LEVEL=WARNING
python main.py
```

### Log Bestanden

| Bestand | Inhoud |
|---------|--------|
| `soc_agent.log` | Applicatie logs |
| `ai_agent_logs.db` | SQLite database met alle log data |
