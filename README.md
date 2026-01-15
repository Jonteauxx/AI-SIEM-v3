# AXS ICT Hybrid SOC Agent v2.0

AI-aangedreven Beveiligingslog Analyse Platform met Machine Learning mogelijkheden.

## Functies

- **Real-time Log Analyse** - Analyseert beveiligingslogs met behulp van Ollama LLM
- **Lerend Systeem** - Leert van gebruikersfeedback om nauwkeurigheid te verbeteren
- **Live Dashboard** - Real-time statistieken en log visualisatie
- **SQLite Database** - Lokale opslag van alle logs en analyses
- **Dreigingsdetectie** - Identificeert beveiligingsdreigingen en anomalieën
- **Patroonherkenning** - Onthoudt en hergebruikt geleerde logpatronen

## Architectuur

```
Fluent Bit/Logs → TCP Ingestor (Poort 5046)
                      ↓
                SQLite Database (Wachtrij)
                      ↓
                AI Processor (Ollama LLM)
                      ↓
                SQLite Database (Geanalyseerd)
                      ↓
              FastAPI Dashboard (Poort 8000)
```

## Quick Start

```bash
# Kloon en setup
git clone <jouw-repo>
cd soc-agent
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configureer
cp .env.example .env
nano .env

# Start
python main.py
```

Open het dashboard: **http://localhost:8000**

## Documentatie

| Document | Beschrijving |
|----------|--------------|
| [Configuratie](docs/configuration.md) | Alle configuratie-opties en omgevingsvariabelen |
| [Gebruikershandleiding](docs/user-guide.md) | Installatie, gebruik en probleemoplossing |
| [API Referentie](docs/api-reference.md) | Volledige API documentatie |

## Vereisten

- Python 3.9+
- [Ollama](https://ollama.ai) met een LLM model
- Fluent Bit (optioneel, voor log doorsturen)

## Bijdragen

1. Fork de repository
2. Maak een feature branch (`git checkout -b feature/geweldige-feature`)
3. Commit wijzigingen (`git commit -m 'Voeg geweldige feature toe'`)
4. Push naar branch (`git push origin feature/geweldige-feature`)
5. Open een Pull Request

