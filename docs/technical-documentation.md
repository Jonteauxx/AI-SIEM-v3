# AI-SIEM v3 - Technische Documentatie

**Versie:** 3.0
**Laatst bijgewerkt:** Januari 2026
**Auteur:** SOC Development Team

---

## Inhoudsopgave

1. [Introductie](#1-introductie)
2. [Systeemarchitectuur](#2-systeemarchitectuur)
3. [Technologiestack](#3-technologiestack)
4. [Kerncomponenten](#4-kerncomponenten)
5. [Database Schema](#5-database-schema)
6. [API Referentie](#6-api-referentie)
7. [AI/ML Integratie](#7-aiml-integratie)
8. [Dataflow & Verwerking](#8-dataflow--verwerking)
9. [Beveiliging](#9-beveiliging)
10. [Deployment](#10-deployment)
11. [Monitoring & Logging](#11-monitoring--logging)
12. [Uitbreidingsmogelijkheden](#12-uitbreidingsmogelijkheden)

---

## 1. Introductie

### 1.1 Projectoverzicht

AI-SIEM v3 is een Security Information and Event Management (SIEM) platform dat kunstmatige intelligentie inzet voor de analyse en classificatie van beveiligingslogboeken. Het systeem combineert traditionele SIEM-functionaliteit met moderne AI-gestuurde log-analyse via lokale Large Language Models (LLMs).

### 1.2 Kernfunctionaliteiten

| Functionaliteit | Beschrijving |
|-----------------|--------------|
| **Real-time Log Ingestie** | TCP-gebaseerde log ontvangst via msgpack protocol |
| **AI-gestuurde Analyse** | Automatische classificatie en severity-bepaling via Ollama LLM |
| **Patroonherkenning** | Zelflerend systeem dat patronen opslaat voor snellere verwerking |
| **Alert Enrichment** | Threat scoring, MITRE ATT&CK mapping, en geolokalisatie |
| **Incident Management** | Volledige incident lifecycle ondersteuning |
| **Compliance Reporting** | Geautomatiseerde compliance rapportages en metrics |

### 1.3 Doelgroep

Dit systeem is ontworpen voor:
- Security Operations Centers (SOC)
- IT Security Teams
- Managed Security Service Providers (MSSPs)
- Organisaties die hun beveiligingsmonitoring willen automatiseren

---

## 2. Systeemarchitectuur

### 2.1 High-Level Architectuur

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              EXTERNE BRONNEN                                │
├─────────────────────────────────────────────────────────────────────────────┤
│  Fluent Bit  │  FluentD  │  Syslog  │  Custom Agents  │  Cloud Services    │
└──────────────┴───────────┴──────────┴─────────────────┴────────────────────┘
                                    │
                                    ▼ (msgpack/TCP:5046)
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TCP LOG INGESTOR                                  │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │  Socket Server  │───▶│  MsgPack Parser │───▶│  Queue Manager  │         │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SQLite DATABASE                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   raw_logs   │  │ ai_knowledge │  │    hosts     │  │  incidents   │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         PROCESSING ENGINE                                   │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐         │
│  │  Host Extractor │───▶│  Rule Matcher   │───▶│  LLM Analyzer   │         │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘         │
│                                                         │                   │
│                                                         ▼                   │
│                              ┌─────────────────────────────────────┐        │
│                              │         OLLAMA LLM SERVICE          │        │
│                              │    (Mistral 7B / Llama2 / Mixtral)  │        │
│                              └─────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       ALERT ENRICHMENT ENGINE                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │Threat Scoring│  │ MITRE Mapper │  │  GeoIP (opt) │  │ Correlation  │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          FastAPI REST API                                   │
│                            (Port 8000)                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  Dashboard   │  │  Log APIs    │  │ Incident API │  │  Chat API    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                        ┌───────────┴───────────┐
                        ▼                       ▼
              ┌─────────────────┐     ┌─────────────────┐
              │  Web Dashboard  │     │  External Tools │
              │   (HTML/JS)     │     │   (API Clients) │
              └─────────────────┘     └─────────────────┘
```

### 2.2 Componentinteractie

```
                    ┌──────────────────────────────────────┐
                    │            User Request              │
                    └──────────────────────────────────────┘
                                      │
                                      ▼
                    ┌──────────────────────────────────────┐
                    │           FastAPI Router             │
                    │        (Rate Limited: slowapi)       │
                    └──────────────────────────────────────┘
                                      │
            ┌─────────────────────────┼─────────────────────────┐
            ▼                         ▼                         ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Log Endpoints  │     │  Learn Endpoints │     │ Incident Endpoints│
│  /api/logs-*     │     │  /api/learn      │     │  /api/incidents   │
└──────────────────┘     └──────────────────┘     └──────────────────┘
            │                         │                         │
            └─────────────────────────┼─────────────────────────┘
                                      ▼
                    ┌──────────────────────────────────────┐
                    │         SQLite Database              │
                    │       (Thread-safe connections)      │
                    └──────────────────────────────────────┘
```

---

## 3. Technologiestack

### 3.1 Backend

| Component | Technologie | Versie | Functie |
|-----------|-------------|--------|---------|
| Web Framework | FastAPI | 0.109.0 | REST API en routing |
| ASGI Server | Uvicorn | 0.27.0 | High-performance server |
| Database | SQLite3 | Built-in | Persistente opslag |
| Validatie | Pydantic | 2.5.3 | Data validatie en serialisatie |
| Rate Limiting | slowapi | 0.1.9 | API rate limiting |
| Serialisatie | msgpack | 1.0.7 | Binary log protocol |
| Monitoring | psutil | 5.9.8 | Systeemmetrics |
| Config | python-dotenv | 1.0.0 | Environment configuratie |

### 3.2 AI/ML Stack

| Component | Technologie | Beschrijving |
|-----------|-------------|--------------|
| LLM Runtime | Ollama | Lokale LLM hosting |
| Primair Model | Mistral 7B | Standaard analysemodel (4GB VRAM) |
| Alternatief | Llama2 13B | Hogere nauwkeurigheid (8GB VRAM) |
| High-end | Mixtral 8x7B | Maximum kwaliteit (26GB VRAM) |

### 3.3 Optionele Integraties

| Component | Technologie | Functie |
|-----------|-------------|---------|
| Search Engine | Elasticsearch 8.x / OpenSearch | Distributed log search |
| Threat Intel | VirusTotal, AbuseIPDB | IOC verificatie |
| Notificaties | Slack, Email (SMTP) | Alerting |
| Ticketing | Freshdesk | Incident escalatie |

### 3.4 Frontend

| Component | Technologie | Beschrijving |
|-----------|-------------|--------------|
| UI | HTML5/CSS3/JavaScript | Single-page dashboard |
| Rendering | Server-side (Jinja2) | Template rendering |
| Styling | Custom CSS | Responsive design |
| Charts | JavaScript Libraries | Data visualisatie |

---

## 4. Kerncomponenten

### 4.1 TCP Log Ingestor

**Locatie:** `main.py` - `TCPServer` class

**Functionaliteit:**
- Luistert op poort 5046 (configureerbaar)
- Accepteert msgpack-gecodeerde logberichten
- Multi-threaded ontwerp voor hoge throughput
- Non-blocking I/O

**Technische details:**
```python
class TCPServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.running = False

    def handle_connection(self, conn, addr):
        # Msgpack unpacker voor streaming data
        unpacker = msgpack.Unpacker(raw=False)
        while self.running:
            data = conn.recv(4096)
            unpacker.feed(data)
            for log_entry in unpacker:
                self.store_log(log_entry)
```

**Configuratie:**
```bash
LISTEN_PORT=5046
HOST_IP=0.0.0.0
```

### 4.2 Processing Engine

**Locatie:** `main.py` - `process_pending_logs()`

**Verwerkingsstappen:**
1. Ophalen van PENDING logs (batch van 5)
2. Host- en IP-extractie uit log content
3. Controle tegen conditional rules
4. Controle tegen knowledge base
5. LLM analyse indien geen match
6. Alert enrichment toevoegen
7. Status update naar PROCESSED

**Retry Mechanisme:**
```python
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconden, exponentieel verhoogd

for attempt in range(MAX_RETRIES):
    try:
        result = analyze_log(log)
        break
    except Exception as e:
        if attempt < MAX_RETRIES - 1:
            time.sleep(RETRY_DELAY * (2 ** attempt))
        else:
            mark_as_error(log, str(e))
```

### 4.3 AI Analysis Engine

**Locatie:** `main.py` - `analyze_with_ollama()`

**Prompt Template:**
```
Je bent een SOC-analist die security logs analyseert.
Analyseer de volgende log entry en geef je analyse in JSON formaat:

Log: {log_content}

Geef exact dit JSON formaat terug:
{
    "severity": "Low|Medium|High|Critical",
    "event_type": "<beschrijvend event type>",
    "summary": "<korte samenvatting van het event>"
}
```

**Response Parsing:**
```python
def parse_llm_response(response: str) -> dict:
    # Zoek JSON in response
    json_match = re.search(r'\{[^{}]*\}', response)
    if json_match:
        return json.loads(json_match.group())
    # Fallback naar defaults
    return {
        "severity": "Medium",
        "event_type": "Unknown",
        "summary": "Kon niet worden geanalyseerd"
    }
```

### 4.4 Knowledge Base System

**Patroon Hashing:**
```python
def create_pattern_hash(log_content: str) -> str:
    # Normaliseer log (verwijder timestamps, IPs, etc.)
    normalized = normalize_log(log_content)
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]
```

**Conditional Rules Schema:**
```python
@dataclass
class ConditionalRule:
    pattern_hash: str
    original_severity: str
    corrected_severity: str
    reason: str
    host_filter: Optional[str] = None      # Alleen voor specifieke hosts
    ip_filter: Optional[str] = None        # Alleen voor specifieke IPs
    exclude_hosts: Optional[str] = None    # Uitsluiten van hosts
    expires_at: Optional[datetime] = None  # Tijdelijke regel
```

### 4.5 Alert Enrichment Engine

**Enrichment Data:**
```python
@dataclass
class AlertEnrichment:
    log_id: int
    threat_score: int                    # 0-100
    mitre_attack_tactic: str            # TA0001-TA0043
    mitre_attack_technique: str         # T1000-T1999
    source_ip: Optional[str]
    geo_country: Optional[str]
    geo_city: Optional[str]
    is_known_threat: bool
    similar_incidents_count: int        # Laatste 24 uur
    time_to_detection_ms: int
```

**Threat Score Berekening:**
```python
def calculate_threat_score(log: dict, enrichment: dict) -> int:
    score = 0

    # Base score op severity
    severity_scores = {"Low": 10, "Medium": 30, "High": 60, "Critical": 80}
    score += severity_scores.get(log["severity"], 20)

    # Modifiers
    if enrichment.get("is_known_threat"):
        score += 20
    if enrichment.get("similar_incidents_count", 0) > 5:
        score += 10
    if log.get("host_criticality") == "critical":
        score += 10

    return min(score, 100)
```

---

## 5. Database Schema

### 5.1 Entity Relationship Diagram

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│    raw_logs     │       │ alert_enrichment│       │     hosts       │
├─────────────────┤       ├─────────────────┤       ├─────────────────┤
│ id (PK)         │──────▶│ log_id (FK)     │       │ hostname (PK)   │
│ timestamp       │       │ threat_score    │       │ ip_address      │
│ raw_log         │       │ mitre_tactic    │       │ criticality     │
│ status          │       │ mitre_technique │       │ risk_score      │
│ severity        │       │ source_ip       │       │ total_alerts    │
│ event_type      │       │ geo_country     │       │ first_seen      │
│ ai_summary      │       │ geo_city        │       │ last_seen       │
│ host            │───────│ similar_count   │       └─────────────────┘
│ processing_ms   │       └─────────────────┘
│ analyzed_by     │
└─────────────────┘
        │
        │       ┌─────────────────┐       ┌─────────────────────────┐
        │       │   incidents     │       │    ai_knowledge         │
        │       ├─────────────────┤       ├─────────────────────────┤
        └──────▶│ id (PK)         │       │ pattern_hash (PK)       │
                │ title           │       │ corrected_severity      │
                │ severity        │       │ reason                  │
                │ status          │       │ created_at              │
                │ assigned_to     │       │ updated_at              │
                │ primary_log_id  │       └─────────────────────────┘
                │ related_log_ids │
                │ mitre_tactics   │       ┌─────────────────────────┐
                └─────────────────┘       │ ai_knowledge_conditions │
                        │                 ├─────────────────────────┤
                        ▼                 │ id (PK)                 │
                ┌─────────────────┐       │ pattern_hash            │
                │ response_actions│       │ original_severity       │
                ├─────────────────┤       │ corrected_severity      │
                │ id (PK)         │       │ host_filter             │
                │ log_id          │       │ ip_filter               │
                │ incident_id(FK) │       │ exclude_hosts           │
                │ action_type     │       │ expires_at              │
                │ status          │       └─────────────────────────┘
                │ result          │
                │ executed_at     │
                └─────────────────┘
```

### 5.2 Tabelspecificaties

#### raw_logs
```sql
CREATE TABLE raw_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    raw_log TEXT NOT NULL,
    status TEXT DEFAULT 'PENDING',     -- PENDING, PROCESSED, ERROR
    severity TEXT,                      -- Low, Medium, High, Critical
    event_type TEXT,
    ai_summary TEXT,
    host TEXT,
    source_ip TEXT,
    processing_time_ms INTEGER,
    analyzed_by TEXT                    -- 'llm', 'knowledge_base', 'conditional_rule'
);

CREATE INDEX idx_raw_logs_status ON raw_logs(status);
CREATE INDEX idx_raw_logs_timestamp ON raw_logs(timestamp);
CREATE INDEX idx_raw_logs_severity ON raw_logs(severity);
CREATE INDEX idx_raw_logs_host ON raw_logs(host);
```

#### ai_knowledge_conditions
```sql
CREATE TABLE ai_knowledge_conditions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_hash TEXT NOT NULL,
    original_severity TEXT,
    corrected_severity TEXT NOT NULL,
    reason TEXT,
    host_filter TEXT,                   -- JSON array of hostnames
    ip_filter TEXT,                     -- JSON array of IPs/CIDRs
    exclude_hosts TEXT,                 -- JSON array of excluded hosts
    expires_at DATETIME,
    is_active BOOLEAN DEFAULT 1,
    times_applied INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_conditions_pattern ON ai_knowledge_conditions(pattern_hash);
CREATE INDEX idx_conditions_active ON ai_knowledge_conditions(is_active);
```

#### incidents
```sql
CREATE TABLE incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,             -- Low, Medium, High, Critical
    status TEXT DEFAULT 'open',         -- open, investigating, resolved, closed
    assigned_to TEXT,
    primary_log_id INTEGER,
    related_log_ids TEXT,               -- JSON array
    mitre_tactics TEXT,                 -- JSON array
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved_at DATETIME,
    FOREIGN KEY (primary_log_id) REFERENCES raw_logs(id)
);

CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
```

### 5.3 Query Optimalisatie

**Veelgebruikte queries met indexes:**

```sql
-- Dashboard metrics (zeer frequent)
SELECT severity, COUNT(*) FROM raw_logs
WHERE status = 'PROCESSED'
GROUP BY severity;
-- Gebruikt: idx_raw_logs_status

-- Recent alerts
SELECT * FROM raw_logs
WHERE status = 'PROCESSED' AND severity IN ('High', 'Critical')
ORDER BY timestamp DESC LIMIT 50;
-- Gebruikt: idx_raw_logs_status, idx_raw_logs_timestamp

-- Host-specifieke logs
SELECT * FROM raw_logs WHERE host = ? ORDER BY timestamp DESC;
-- Gebruikt: idx_raw_logs_host
```

---

## 6. API Referentie

### 6.1 Endpoint Overzicht

| Categorie | Endpoints | Rate Limit |
|-----------|-----------|------------|
| Health & Metrics | 5 | 120/min |
| Log Management | 8 | 100/min |
| AI Learning | 6 | 10-20/min |
| Incidents | 4 | 50/min |
| Enrichment | 2 | 50/min |
| Export | 1 | 10/min |

### 6.2 Health & Monitoring

#### GET /health
```json
// Response 200 OK
{
    "status": "healthy",
    "components": {
        "database": "connected",
        "ollama": "connected",
        "tcp_ingestor": "running",
        "elasticsearch": "connected"  // of "not_configured"
    },
    "version": "3.0.0",
    "uptime_seconds": 86400
}
```

#### GET /api/dashboard-metrics
```json
// Response 200 OK
{
    "total_logs": 15420,
    "pending_logs": 23,
    "processed_logs": 15397,
    "severity_distribution": {
        "Critical": 124,
        "High": 892,
        "Medium": 5621,
        "Low": 8760
    },
    "events_last_24h": 2341,
    "ai_learning_progress": {
        "patterns_learned": 156,
        "rules_active": 43,
        "relearned_percentage": 28.5
    }
}
```

#### GET /api/system-metrics
```json
// Response 200 OK
{
    "cpu_percent": 23.5,
    "memory_percent": 45.2,
    "memory_used_gb": 7.2,
    "memory_total_gb": 16.0,
    "disk_percent": 62.1,
    "disk_used_gb": 124.2,
    "disk_total_gb": 200.0
}
```

### 6.3 Log Management

#### GET /api/logs
**Query Parameters:**
| Parameter | Type | Beschrijving |
|-----------|------|--------------|
| panel | string | Filter: "active_alerts", "threats_blocked", "all" |
| limit | int | Max results (default: 100) |
| offset | int | Pagination offset |

```json
// Response 200 OK
{
    "logs": [
        {
            "id": 15420,
            "timestamp": "2026-01-17T14:32:15Z",
            "raw_log": "Jan 17 14:32:15 web-server sshd[12345]: Failed password...",
            "status": "PROCESSED",
            "severity": "High",
            "event_type": "Brute Force Attempt",
            "ai_summary": "Meerdere mislukte SSH login pogingen vanaf 192.168.1.100",
            "host": "web-server",
            "processing_time_ms": 1523
        }
    ],
    "total": 892,
    "offset": 0,
    "limit": 100
}
```

#### GET /api/logs-search
**Query Parameters:**
| Parameter | Type | Beschrijving |
|-----------|------|--------------|
| q | string | Zoekterm in raw_log en ai_summary |
| severity | string | Filter op severity |
| host | string | Filter op hostname |
| event_type | string | Filter op event type |
| start_date | datetime | Begin datum (ISO 8601) |
| end_date | datetime | Eind datum (ISO 8601) |
| limit | int | Max results |

### 6.4 AI Learning

#### POST /api/learn
**Request Body:**
```json
{
    "log_id": 15420,
    "corrected_severity": "Medium",
    "reason": "Dit is normaal gedrag voor dit systeem"
}
```

**Response 200 OK:**
```json
{
    "success": true,
    "pattern_hash": "a1b2c3d4e5f67890",
    "message": "Patroon opgeslagen, zal worden toegepast op vergelijkbare logs"
}
```

#### POST /api/learn-conditional
**Request Body:**
```json
{
    "log_id": 15420,
    "corrected_severity": "Low",
    "reason": "Backup job op deze server",
    "host_filter": ["backup-server-01", "backup-server-02"],
    "ip_filter": null,
    "exclude_hosts": null,
    "expires_at": "2026-02-17T00:00:00Z"
}
```

#### GET /api/knowledge-base
```json
// Response 200 OK
{
    "patterns": [
        {
            "pattern_hash": "a1b2c3d4e5f67890",
            "corrected_severity": "Low",
            "reason": "Normale backup activiteit",
            "times_matched": 234,
            "created_at": "2026-01-10T08:00:00Z"
        }
    ],
    "total_patterns": 156
}
```

### 6.5 Incident Management

#### POST /api/create-incident
**Request Body:**
```json
{
    "log_id": 15420,
    "title": "Brute Force Attack op Web Server",
    "description": "Meerdere mislukte login pogingen gedetecteerd",
    "severity": "High",
    "assigned_to": "security-team"
}
```

**Response 201 Created:**
```json
{
    "incident_id": 42,
    "status": "open",
    "created_at": "2026-01-17T14:35:00Z"
}
```

#### GET /api/incidents
**Query Parameters:**
| Parameter | Type | Beschrijving |
|-----------|------|--------------|
| status | string | Filter: "open", "investigating", "resolved", "closed" |

### 6.6 Alert Enrichment

#### GET /api/alert-enrichment/{log_id}
```json
// Response 200 OK
{
    "log_id": 15420,
    "threat_score": 75,
    "mitre_attack_tactic": "TA0006",
    "mitre_attack_tactic_name": "Credential Access",
    "mitre_attack_technique": "T1110",
    "mitre_attack_technique_name": "Brute Force",
    "source_ip": "192.168.1.100",
    "geo_country": "Netherlands",
    "geo_city": "Amsterdam",
    "is_known_threat": false,
    "similar_incidents_count": 3,
    "time_to_detection_ms": 2341
}
```

#### GET /api/remediation/{log_id}
```json
// Response 200 OK
{
    "log_id": 15420,
    "severity": "High",
    "event_type": "Brute Force Attempt",
    "remediation_steps": [
        {
            "step": 1,
            "action": "Blokkeer het bron IP-adres",
            "command": "iptables -A INPUT -s 192.168.1.100 -j DROP",
            "priority": "immediate"
        },
        {
            "step": 2,
            "action": "Analyseer login logs voor compromised accounts",
            "command": "grep 'Failed password' /var/log/auth.log | grep 192.168.1.100",
            "priority": "high"
        },
        {
            "step": 3,
            "action": "Implementeer rate limiting",
            "command": null,
            "priority": "medium"
        }
    ],
    "generated_at": "2026-01-17T14:36:00Z"
}
```

---

## 7. AI/ML Integratie

### 7.1 Ollama Configuratie

**Vereisten:**
- Ollama server draaiend op `http://localhost:11434`
- Minimaal 4GB VRAM voor Mistral 7B
- CPU fallback beschikbaar maar trager

**Environment Configuratie:**
```bash
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=mistral:7b
```

**Ondersteunde Modellen:**
| Model | VRAM | Snelheid | Nauwkeurigheid | Use Case |
|-------|------|----------|----------------|----------|
| mistral:7b | 4GB | Snel | Goed | Standaard analyse |
| llama2:13b | 8GB | Medium | Zeer goed | Complexe logs |
| codellama:7b | 4GB | Snel | Goed | Technische logs |
| mixtral:8x7b | 26GB | Langzaam | Excellent | Kritieke analyse |

### 7.2 Analyse Pipeline

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Raw Log   │────▶│ Preprocessor│────▶│Pattern Hash │
└─────────────┘     └─────────────┘     └─────────────┘
                                               │
                    ┌──────────────────────────┼──────────────────────────┐
                    ▼                          ▼                          ▼
           ┌─────────────┐            ┌─────────────┐            ┌─────────────┐
           │ Conditional │            │  Knowledge  │            │   Ollama    │
           │   Rules     │            │    Base     │            │    LLM      │
           └─────────────┘            └─────────────┘            └─────────────┘
                    │                          │                          │
                    └──────────────────────────┼──────────────────────────┘
                                               ▼
                                    ┌─────────────────────┐
                                    │   Analysis Result   │
                                    │ (severity, type,    │
                                    │  summary)           │
                                    └─────────────────────┘
```

### 7.3 Learning Mechanisme

**Feedback Loop:**
1. Analist ziet geanalyseerde log
2. Analist corrigeert severity indien nodig
3. Systeem berekent pattern hash
4. Patroon wordt opgeslagen in knowledge base
5. Volgende vergelijkbare logs gebruiken opgeslagen patroon

**Pattern Normalisatie:**
```python
def normalize_log(log: str) -> str:
    """Verwijder variabele delen voor consistente hashing"""
    # Verwijder timestamps
    log = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', '[TIMESTAMP]', log)
    # Verwijder IP adressen
    log = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '[IP]', log)
    # Verwijder UUIDs
    log = re.sub(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '[UUID]', log)
    # Verwijder getallen
    log = re.sub(r'\b\d+\b', '[NUM]', log)
    return log.lower().strip()
```

### 7.4 MITRE ATT&CK Mapping

**Automatische Tactiek Detectie:**
```python
MITRE_KEYWORDS = {
    "TA0001": {  # Initial Access
        "name": "Initial Access",
        "keywords": ["exploit", "phishing", "drive-by", "supply chain"]
    },
    "TA0003": {  # Persistence
        "name": "Persistence",
        "keywords": ["cron", "scheduled task", "registry", "startup"]
    },
    "TA0006": {  # Credential Access
        "name": "Credential Access",
        "keywords": ["brute force", "password", "credential", "hash"]
    },
    # ... meer tactieken
}
```

---

## 8. Dataflow & Verwerking

### 8.1 Log Ingestie Flow

```
Fluent Bit/FluentD
    │
    │ msgpack over TCP
    ▼
┌─────────────────────────────────────┐
│         TCP Socket (5046)           │
│   ┌─────────────────────────────┐   │
│   │    Connection Handler       │   │
│   │    (Multi-threaded)         │   │
│   └─────────────────────────────┘   │
│              │                      │
│              ▼                      │
│   ┌─────────────────────────────┐   │
│   │    MsgPack Unpacker         │   │
│   │    (Streaming)              │   │
│   └─────────────────────────────┘   │
│              │                      │
│              ▼                      │
│   ┌─────────────────────────────┐   │
│   │    INSERT raw_logs          │   │
│   │    status='PENDING'         │   │
│   └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

### 8.2 Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        PROCESSING LOOP (10s interval)                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Step 1: Fetch Batch                                                    │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │  SELECT * FROM raw_logs WHERE status='PENDING' LIMIT 5         │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                              │                                           │
│                              ▼                                           │
│   Step 2: Extract Metadata                                              │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │  - Parse hostname from log                                      │    │
│   │  - Extract source IP addresses                                  │    │
│   │  - Calculate pattern hash                                       │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                              │                                           │
│                              ▼                                           │
│   Step 3: Rule Matching (fast path)                                     │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │  IF conditional_rule matches:                                   │    │
│   │      → Apply rule, set analyzed_by='conditional_rule'           │    │
│   │  ELIF knowledge_base matches:                                   │    │
│   │      → Apply pattern, set analyzed_by='knowledge_base'          │    │
│   │  ELSE:                                                          │    │
│   │      → Continue to LLM                                          │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                              │                                           │
│                              ▼                                           │
│   Step 4: LLM Analysis (slow path)                                      │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │  - Build prompt with log content                                │    │
│   │  - Send to Ollama API                                           │    │
│   │  - Parse JSON response                                          │    │
│   │  - Set analyzed_by='llm'                                        │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                              │                                           │
│                              ▼                                           │
│   Step 5: Enrichment                                                    │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │  - Calculate threat score                                       │    │
│   │  - Map to MITRE ATT&CK                                          │    │
│   │  - Count similar incidents                                      │    │
│   │  - Store in alert_enrichment table                              │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                              │                                           │
│                              ▼                                           │
│   Step 6: Update & Index                                                │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │  - UPDATE raw_logs SET status='PROCESSED'                       │    │
│   │  - Optional: Index to Elasticsearch                             │    │
│   │  - Update host statistics                                       │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 8.3 Performance Metrics

| Metric | Waarde | Beschrijving |
|--------|--------|--------------|
| Batch Size | 5 logs | Logs per processing cycle |
| Cycle Interval | 10 sec | Tijd tussen processing cycles |
| LLM Latency | 500-3000ms | Ollama response tijd |
| KB Lookup | <10ms | Knowledge base query |
| Throughput | ~30 logs/min | Met LLM analyse |
| Throughput (cached) | ~300 logs/min | Met knowledge base |

---

## 9. Beveiliging

### 9.1 API Beveiliging

**Rate Limiting:**
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.get("/api/dashboard-metrics")
@limiter.limit("120/minute")
async def dashboard_metrics(request: Request):
    ...
```

**CORS Configuratie:**
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configureer voor productie
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 9.2 Input Validatie

**Pydantic Models:**
```python
from pydantic import BaseModel, Field, validator

class LearnRequest(BaseModel):
    log_id: int = Field(..., gt=0)
    corrected_severity: str = Field(..., pattern="^(Low|Medium|High|Critical)$")
    reason: str = Field(..., min_length=5, max_length=500)

    @validator('reason')
    def sanitize_reason(cls, v):
        # Voorkom SQL injection
        return v.replace("'", "''").replace(";", "")
```

### 9.3 Database Beveiliging

**Parameterized Queries:**
```python
# Correct - Parameterized
cursor.execute(
    "SELECT * FROM raw_logs WHERE id = ?",
    (log_id,)
)

# FOUT - SQL Injection kwetsbaar
# cursor.execute(f"SELECT * FROM raw_logs WHERE id = {log_id}")
```

### 9.4 Gevoelige Data

**Niet Opgeslagen:**
- Wachtwoorden in plain text
- API keys in database
- PII wordt niet geïndexeerd

**Configuratie (.env):**
```bash
# .env wordt NIET gecommit naar git
# Gebruik .env.example als template
ES_PASSWORD=***
SLACK_WEBHOOK=***
```

---

## 10. Deployment

### 10.1 Systeemvereisten

| Component | Minimum | Aanbevolen |
|-----------|---------|------------|
| CPU | 2 cores | 4+ cores |
| RAM | 8 GB | 16+ GB |
| Storage | 20 GB | 100+ GB SSD |
| GPU VRAM | 4 GB | 8+ GB |
| OS | Linux (Ubuntu 22.04+) | Linux |
| Python | 3.10+ | 3.11+ |

### 10.2 Installatie

```bash
# 1. Clone repository
git clone https://github.com/your-org/ai-siem-v3.git
cd ai-siem-v3

# 2. Virtuele omgeving
python -m venv venv
source venv/bin/activate

# 3. Dependencies
pip install -r requirements.txt

# 4. Configuratie
cp .env.example .env
nano .env  # Pas configuratie aan

# 5. Ollama installatie
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mistral:7b

# 6. Start applicatie
python main.py
```

### 10.3 Systemd Service

```ini
# /etc/systemd/system/ai-siem.service
[Unit]
Description=AI-SIEM v3 Security Platform
After=network.target ollama.service

[Service]
Type=simple
User=soc
Group=soc
WorkingDirectory=/opt/soc-agent
Environment="PATH=/opt/soc-agent/venv/bin"
ExecStart=/opt/soc-agent/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Service activeren
sudo systemctl daemon-reload
sudo systemctl enable ai-siem
sudo systemctl start ai-siem
```

### 10.4 Docker Deployment (Concept)

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5046 8000

CMD ["python", "main.py"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  ai-siem:
    build: .
    ports:
      - "5046:5046"
      - "8000:8000"
    volumes:
      - ./data:/app/data
    environment:
      - OLLAMA_URL=http://ollama:11434
    depends_on:
      - ollama

  ollama:
    image: ollama/ollama
    volumes:
      - ollama_data:/root/.ollama
    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: 1
              capabilities: [gpu]

volumes:
  ollama_data:
```

### 10.5 Fluent Bit Configuratie

```ini
# /etc/fluent-bit/fluent-bit.conf
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
    Name         tcp
    Match        *
    Host         ai-siem-server
    Port         5046
    Format       msgpack
```

---

## 11. Monitoring & Logging

### 11.1 Applicatie Logs

**Log Locatie:** `soc_agent.log`

**Log Formaat:**
```
2026-01-17 14:32:15,234 - INFO - Processing batch of 5 logs
2026-01-17 14:32:16,789 - INFO - Log 15420 analyzed by llm (1523ms)
2026-01-17 14:32:16,790 - WARNING - Ollama slow response (>2000ms)
2026-01-17 14:32:17,001 - ERROR - Failed to index to Elasticsearch
```

**Log Levels:**
| Level | Gebruik |
|-------|---------|
| DEBUG | Gedetailleerde debugging |
| INFO | Normale operaties |
| WARNING | Potentiële problemen |
| ERROR | Fouten die actie vereisen |
| CRITICAL | Systeemfalen |

### 11.2 Health Endpoints

**GET /health Response:**
```json
{
    "status": "healthy",
    "checks": {
        "database": {
            "status": "ok",
            "latency_ms": 2
        },
        "ollama": {
            "status": "ok",
            "model": "mistral:7b",
            "latency_ms": 45
        },
        "tcp_ingestor": {
            "status": "running",
            "connections": 3
        },
        "elasticsearch": {
            "status": "ok",
            "cluster": "green"
        }
    }
}
```

### 11.3 Metrics

**Beschikbare Metrics (GET /api/soc-metrics):**
```json
{
    "mttd_seconds": 45,        // Mean Time To Detect
    "mttr_seconds": 3600,      // Mean Time To Respond
    "mtta_seconds": 120,       // Mean Time To Acknowledge
    "events_per_hour": 156,
    "false_positive_rate": 0.12,
    "automation_rate": 0.73
}
```

### 11.4 Alerting Setup (Optioneel)

```python
# Slack webhook configuratie
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

async def send_alert(message: str, severity: str):
    if severity in ["High", "Critical"] and SLACK_WEBHOOK_URL:
        payload = {
            "text": f":warning: *{severity} Alert*\n{message}",
            "channel": "#soc-alerts"
        }
        async with httpx.AsyncClient() as client:
            await client.post(SLACK_WEBHOOK_URL, json=payload)
```

---

## 12. Uitbreidingsmogelijkheden

### 12.1 Geplande Features

| Feature | Status | Prioriteit |
|---------|--------|------------|
| PostgreSQL ondersteuning | Gepland | Hoog |
| JWT Authenticatie | Framework klaar | Hoog |
| Webhook notificaties | Framework klaar | Medium |
| SOAR integratie | Gepland | Medium |
| Machine Learning anomaly detection | Onderzoek | Laag |
| Multi-tenant ondersteuning | Gepland | Laag |

### 12.2 Plugin Architectuur (Toekomstig)

```python
# Voorbeeld plugin interface
class ThreatIntelPlugin:
    async def check_indicator(self, indicator: str, indicator_type: str) -> dict:
        """Check indicator tegen threat intel bron"""
        raise NotImplementedError

class VirusTotalPlugin(ThreatIntelPlugin):
    def __init__(self, api_key: str):
        self.api_key = api_key

    async def check_indicator(self, indicator: str, indicator_type: str) -> dict:
        # Implementatie
        ...
```

### 12.3 Schaalbaarheid

**Verticaal:**
- Meer RAM voor grotere batches
- Snellere GPU voor LLM
- SSD storage voor database

**Horizontaal (toekomstig):**
- PostgreSQL voor multi-instance
- Redis voor job queue
- Load balancer voor API

### 12.4 API Extensies

**Custom Endpoints Toevoegen:**
```python
# In main.py of aparte module
@app.get("/api/custom/my-endpoint")
async def custom_endpoint():
    """Custom endpoint voor specifieke use case"""
    return {"data": "custom response"}
```

---

## Appendix A: Environment Variabelen

| Variabele | Standaard | Beschrijving |
|-----------|-----------|--------------|
| `DB_NAME` | ai_agent_logs.db | SQLite database bestand |
| `LISTEN_PORT` | 5046 | TCP ingestor poort |
| `API_PORT` | 8000 | REST API poort |
| `HOST_IP` | 0.0.0.0 | Bind adres |
| `OLLAMA_URL` | http://localhost:11434 | Ollama server URL |
| `OLLAMA_MODEL` | mistral:7b | LLM model |
| `ES_HOSTS` | - | Elasticsearch hosts (optioneel) |
| `ES_INDEX` | security-logs | Elasticsearch index |
| `MAX_RETRIES` | 3 | Max retry attempts |
| `LOG_LEVEL` | INFO | Logging niveau |

## Appendix B: Troubleshooting

| Probleem | Mogelijke Oorzaak | Oplossing |
|----------|-------------------|-----------|
| Logs blijven PENDING | Ollama niet bereikbaar | Check `ollama serve` status |
| Hoge CPU | Te veel pending logs | Verhoog batch size |
| Out of memory | LLM model te groot | Gebruik kleiner model |
| Trage API | Database niet geïndexeerd | Run `CREATE INDEX` statements |
| TCP connection refused | Poort bezet | Check `netstat -tlnp | grep 5046` |

## Appendix C: Versiegeschiedenis

| Versie | Datum | Wijzigingen |
|--------|-------|-------------|
| 3.0.0 | Jan 2026 | AI remediation, processing time stats, log search |
| 2.5.0 | Dec 2025 | Dashboard v4, floating chatbot |
| 2.0.0 | Nov 2025 | Knowledge base, conditional rules |
| 1.0.0 | Okt 2025 | Initiële release |

---

*Dit document is gegenereerd voor AI-SIEM v3. Voor de meest recente informatie, raadpleeg de GitHub repository.*
