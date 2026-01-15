# Gebruikershandleiding

Deze handleiding beschrijft hoe je de AXS ICT Hybrid SOC Agent installeert, configureert en gebruikt.

## Inhoudsopgave

1. [Vereisten](#vereisten)
2. [Installatie](#installatie)
3. [Applicatie Starten](#applicatie-starten)
4. [Logs Versturen](#logs-versturen)
5. [Dashboard Gebruiken](#dashboard-gebruiken)
6. [Monitoring](#monitoring)
7. [Probleemoplossing](#probleemoplossing)

## Vereisten

Voordat je begint, zorg dat je het volgende hebt:

- **Python 3.9+** - [python.org](https://python.org)
- **Ollama** - [ollama.ai](https://ollama.ai)
- **Fluent Bit** (optioneel) - Voor log doorsturen

## Installatie

### Stap 1: Repository Klonen

```bash
git clone <jouw-repo>
cd soc-agent
```

### Stap 2: Python Omgeving Opzetten

```bash
# Maak virtuele omgeving aan
python -m venv venv

# Activeer de omgeving
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Installeer afhankelijkheden
pip install -r requirements.txt
```

### Stap 3: Configuratie

```bash
# Kopieer voorbeeldconfiguratie
cp .env.example .env

# Bewerk met je eigen instellingen
nano .env
```

Zie [Configuratie](configuration.md) voor alle opties.

### Stap 4: Ollama Installeren

```bash
# Installeer Ollama (Linux)
curl -fsSL https://ollama.ai/install.sh | sh

# Download het AI model
ollama pull mistral:7b

# Controleer installatie
ollama list
```

## Applicatie Starten

### Basis Starten

```bash
python main.py
```

Succesvolle output:
```
INFO - Starting AXS ICT Hybrid SOC Agent v2.0.0
INFO - Configuration validated successfully
INFO - Database initialized successfully with all feature tables
INFO - TCP Ingestor listening on 0.0.0.0:5046
INFO - Processor loop started
INFO - Starting API server on 0.0.0.0:8000
```

### Starten met Debug Logging

```bash
export LOG_LEVEL=DEBUG
python main.py
```

### Als Achtergrond Service

```bash
nohup python main.py > /var/log/soc-agent.log 2>&1 &
```

## Logs Versturen

### Met Fluent Bit

Configureer Fluent Bit om logs door te sturen naar de SOC Agent.

#### Fluent Bit Configuratie (`fluent-bit.conf`)

```ini
[SERVICE]
    Flush        1
    Log_Level    info

[INPUT]
    Name         tail
    Path         /var/log/syslog
    Tag          syslog

[INPUT]
    Name         tail
    Path         /var/log/auth.log
    Tag          auth

[OUTPUT]
    Name         forward
    Match        *
    Host         127.0.0.1
    Port         5046
```

#### Fluent Bit Starten

```bash
fluent-bit -c /etc/fluent-bit/fluent-bit.conf
```

#### Fluent Bit als Service

```bash
sudo systemctl enable fluent-bit
sudo systemctl start fluent-bit
```

### Met Python Script

```python
import socket
import time
import msgpack

def send_log(message):
    """Verstuur een log bericht naar de SOC Agent."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 5046))

    data = msgpack.packb([
        "security.logs",
        [[time.time(), {"message": message}]]
    ])

    sock.send(data)
    sock.close()

# Voorbeelden
send_log("Gebruiker login mislukt vanaf IP 192.168.1.100")
send_log("SSH brute force poging gedetecteerd")
send_log("Firewall regel overtreding: poort 22")
```

### Test Logs Versturen

```bash
# Eenvoudige test met netcat
echo '["test", [[1234567890, {"message": "Test log bericht"}]]]' | nc localhost 5046
```

## Dashboard Gebruiken

### Toegang

Open je browser naar: **http://localhost:8000**

### Functies

1. **Real-time Statistieken** - Bekijk totaal logs, actieve alerts en geblokkeerde dreigingen
2. **Log Overzicht** - Filter en zoek door geanalyseerde logs
3. **Kennisbank** - Bekijk geleerde patronen
4. **Feedback Geven** - Corrigeer AI analyses om het systeem te verbeteren

### Feedback Geven

Als de AI een verkeerde classificatie maakt:

1. Klik op de log entry in het dashboard
2. Selecteer de correcte ernst (Low/Medium/High/Critical)
3. Voeg een reden toe
4. Klik op "Leren"

Het systeem onthoudt deze correctie voor toekomstige analyses.

## Monitoring

### Systeemgezondheid Controleren

```bash
curl http://localhost:8000/health
```

Verwachte output:
```json
{
  "status": "healthy",
  "timestamp": "2024-12-17T10:30:00",
  "checks": {
    "database": true,
    "ollama": true,
    "ingestor": true
  }
}
```

### Log Statistieken Bekijken

```bash
# Dashboard metrics
curl http://localhost:8000/api/dashboard-metrics

# Analyse status
curl http://localhost:8000/api/analysis-status
```

### Applicatie Logs Volgen

```bash
tail -f soc_agent.log
```

### Database Status Controleren

```bash
# Aantal wachtende logs
sqlite3 ai_agent_logs.db "SELECT COUNT(*) FROM raw_logs WHERE status='PENDING'"

# Aantal verwerkte logs
sqlite3 ai_agent_logs.db "SELECT COUNT(*) FROM raw_logs WHERE status='PROCESSED'"

# Totaal aantal logs
sqlite3 ai_agent_logs.db "SELECT COUNT(*) FROM raw_logs"
```

## Probleemoplossing

### Ollama Verbinding Mislukt

**Symptoom:** `Connection refused` bij Ollama

**Oplossing:**
```bash
# Controleer of Ollama draait
curl http://localhost:11434/api/version

# Start Ollama opnieuw
ollama serve

# Of als service
sudo systemctl restart ollama
```

### Geen Logs Worden Verwerkt

**Symptoom:** Dashboard toont geen nieuwe logs

**Checklist:**

1. Controleer of logs worden ontvangen:
   ```bash
   sqlite3 ai_agent_logs.db "SELECT COUNT(*) FROM raw_logs WHERE status='PENDING'"
   ```

2. Controleer processor logs:
   ```bash
   grep "PROCESSOR" soc_agent.log
   ```

3. Verifieer Ollama reageert:
   ```bash
   ollama run mistral:7b "Test"
   ```

4. Controleer Fluent Bit status:
   ```bash
   sudo systemctl status fluent-bit
   ```

### Hoog CPU/Geheugen Gebruik

**Oplossingen:**

1. Gebruik een kleiner model:
   ```bash
   # In .env
   OLLAMA_MODEL=mistral:7b  # in plaats van mixtral:8x7b
   ```

2. Verklein batch grootte in de code

3. Voeg vertraging toe tussen verwerkingen

### Fluent Bit Stuurt Geen Logs

**Controleer:**

1. Fluent Bit service status:
   ```bash
   sudo systemctl status fluent-bit
   ```

2. Fluent Bit logs:
   ```bash
   sudo journalctl -u fluent-bit -f
   ```

3. Test handmatige verbinding:
   ```bash
   nc -zv localhost 5046
   ```

4. Controleer configuratie syntax:
   ```bash
   fluent-bit -c /etc/fluent-bit/fluent-bit.conf --dry-run
   ```

### Database Problemen

**Symptoom:** Database locked of corrupt

**Oplossing:**
```bash
# Stop de applicatie eerst!

# Controleer database integriteit
sqlite3 ai_agent_logs.db "PRAGMA integrity_check"

# Repareer indien nodig
sqlite3 ai_agent_logs.db ".recover" | sqlite3 recovered.db
mv recovered.db ai_agent_logs.db
```
