# API Referentie

Deze documentatie beschrijft alle beschikbare API eindpunten van de AXS ICT Hybrid SOC Agent.

## Base URL

```
http://localhost:8000
```

## Eindpunten

### Gezondheidscontrole

Controleer of alle componenten correct functioneren.

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-12-17T10:30:00",
  "checks": {
    "database": true,
    "ollama": true,
    "ingestor": true
  },
  "version": "2.0.0"
}
```

**Status codes:**
- `200` - Systeem gezond
- `503` - Een of meer componenten niet beschikbaar

---

### Dashboard Statistieken

Haal real-time statistieken op voor het dashboard.

```http
GET /api/dashboard-metrics
```

**Response:**
```json
{
  "total_logs": 1542,
  "pending": 12,
  "processed": 1530,
  "active_alerts": 23,
  "threats_blocked": 7,
  "relearned_logs": 15,
  "llm_status": "ONLINE",
  "api_status": "ONLINE"
}
```

---

### Analyse Status

Bekijk de huidige verwerkingsstatus.

```http
GET /api/analysis-status
```

**Response:**
```json
{
  "progress": 85.5,
  "total": 1542,
  "processed": 1320,
  "pending": 222
}
```

---

### Logs Ophalen

Haal geanalyseerde logs op, gefilterd per paneel.

```http
GET /api/logs
```

**Query Parameters:**

| Parameter | Type | Beschrijving |
|-----------|------|--------------|
| `panel` | string | Filter op paneel type |

**Beschikbare panelen:**
- `Active Alerts` - Logs met hoge/kritieke ernst
- `Threats Blocked` - Geblokkeerde dreigingen

**Voorbeeld:**
```bash
curl "http://localhost:8000/api/logs?panel=Active%20Alerts"
```

**Response:**
```json
[
  {
    "TLID": 123,
    "Raw Log": "Failed SSH login from 192.168.1.100",
    "Timestamp": "2024-12-17T10:30:00",
    "Processed At": "2024-12-17T10:30:05",
    "Severity": "High",
    "Event Type": "Authentication",
    "HOST": "192.168.1.100",
    "AI Summary": "Mogelijke brute force aanval gedetecteerd"
  }
]
```

---

### Alle Logs

Haal alle logs op (verwerkt en pending).

```http
GET /api/logs-all
```

**Response:** Array van log objecten (max 200)

---

### Verwerkte Logs

Haal alleen verwerkte logs op.

```http
GET /api/logs-processed
```

**Response:** Array van verwerkte log objecten (max 100)

---

### Wachtende Logs

Haal logs op die wachten op verwerking.

```http
GET /api/logs-pending
```

**Response:** Array van pending log objecten (max 100)

---

### Geleerde Logs

Haal logs op die door de kennisbank zijn geanalyseerd.

```http
GET /api/relearned-logs
```

**Response:** Array van logs geanalyseerd via geleerde patronen (max 100)

---

### Leren van Feedback

Geef feedback op een analyse om het systeem te trainen.

```http
POST /api/learn
```

**Request Body:**
```json
{
  "log_id": 123,
  "new_severity": "High",
  "reason": "Dit is eigenlijk een brute force poging"
}
```

**Parameters:**

| Parameter | Type | Verplicht | Beschrijving |
|-----------|------|-----------|--------------|
| `log_id` | integer | Ja | ID van de log entry |
| `new_severity` | string | Ja | Nieuwe ernst classificatie |
| `reason` | string | Ja | Reden voor de correctie (min 5 karakters) |

**Geldige severity waarden:**
- `Low`
- `Medium`
- `High`
- `Critical`

**Response:**
```json
{
  "status": "success",
  "message": "AI knowledge base updated",
  "pattern_hash": "a1b2c3d4..."
}
```

---

### Kennisbank Bekijken

Bekijk alle geleerde patronen.

```http
GET /api/knowledge-base
```

**Response:**
```json
[
  {
    "pattern_hash": "a1b2c3d4e5f6...",
    "severity": "High",
    "reason": "Brute force poging",
    "created_at": "2024-12-10T14:20:00",
    "updated_at": "2024-12-15T09:30:00"
  }
]
```

---

### AI Chat

Chat met de AI over beveiligingslogs.

```http
POST /api/chat
```

**Request Body:**
```json
{
  "query": "Wat zijn de meest voorkomende dreigingen vandaag?"
}
```

**Response:**
```json
{
  "response": "Op basis van de recente logs zie ik..."
}
```

---

### Alert Verrijking

Haal verrijkte informatie op voor een specifieke alert.

```http
GET /api/alert-enrichment/{log_id}
```

**Response:**
```json
{
  "log_id": 123,
  "threat_score": 85,
  "mitre_tactic": "Initial Access",
  "mitre_technique": "T1110 - Brute Force",
  "source_ip": "192.168.1.100",
  "is_known_threat": false,
  "similar_incidents_count": 5
}
```

---

### AI Leerstatistieken

Haal statistieken op over AI leervoortgang.

```http
GET /api/ai-learning-stats
```

**Response:**
```json
{
  "total_patterns": 45,
  "kb_analyzed_logs": 230,
  "recent_corrections_24h": 3,
  "top_corrections": [
    {"severity": "High", "count": 15},
    {"severity": "Critical", "count": 8}
  ]
}
```

---

### Hosts

Haal alle gemonitorde hosts op.

```http
GET /api/hosts
```

**Response:**
```json
[
  {
    "id": 1,
    "hostname": "webserver-01",
    "ip_address": "192.168.1.10",
    "criticality": "High",
    "risk_score": 75,
    "total_alerts": 23,
    "last_seen": "2024-12-17T10:30:00"
  }
]
```

---

### Host Details

Haal gedetailleerde informatie op voor een specifieke host.

```http
GET /api/hosts/{hostname}
```

**Response:**
```json
{
  "host_info": {
    "hostname": "webserver-01",
    "risk_score": 75,
    "total_alerts": 23
  },
  "recent_alerts": [...]
}
```

---

### Incidenten

Haal alle incidenten op.

```http
GET /api/incidents
```

**Query Parameters:**

| Parameter | Type | Beschrijving |
|-----------|------|--------------|
| `status` | string | Filter op status (Open, Closed, etc.) |

---

### Incident Aanmaken

Maak een nieuw incident aan.

```http
POST /api/create-incident
```

**Request Body:**
```json
{
  "log_id": 123,
  "title": "Brute Force Attack Detected",
  "assigned_to": "security-team"
}
```

---

### Gecorreleerde Events

Haal gecorreleerde beveiligingsevents op.

```http
GET /api/correlated-events
```

---

### Dreigingsstatistieken

Haal statistieken op voor visualisaties.

```http
GET /api/threat-statistics
```

**Response:**
```json
{
  "severity_distribution": {
    "Critical": 5,
    "High": 23,
    "Medium": 45,
    "Low": 120
  },
  "top_event_types": [...],
  "most_targeted_hosts": [...],
  "hourly_trend": {...}
}
```

---

### Compliance Dashboard

Haal compliance metrics op.

```http
GET /api/compliance-dashboard
```

---

### Logs Exporteren

Exporteer logs naar CSV formaat.

```http
POST /api/export-logs
```

**Response:** CSV bestand download

---

### Playbooks

Haal beschikbare incident response playbooks op.

```http
GET /api/playbooks
```

---

## Rate Limiting

De API heeft rate limiting per eindpunt:

| Eindpunt | Limiet |
|----------|--------|
| `/api/dashboard-metrics` | 120/minuut |
| `/api/logs*` | 100/minuut |
| `/api/learn` | 10/minuut |
| `/api/chat` | 20/minuut |
| `/api/export-logs` | 10/minuut |

## Foutcodes

| Code | Beschrijving |
|------|--------------|
| `200` | Succes |
| `400` | Ongeldige request parameters |
| `404` | Resource niet gevonden |
| `429` | Rate limit overschreden |
| `500` | Interne server fout |

## Authenticatie

De API heeft momenteel geen authenticatie. Voor productie wordt aanbevolen om authenticatie toe te voegen via een reverse proxy of custom middleware.
