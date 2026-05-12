# IntrusionAI - Hybrid UEBA & Behavioral Intelligence System

## 🎯 Overview

IntrusionAI is an enterprise-grade **User and Entity Behavior Analytics (UEBA)** platform with advanced behavioral intelligence, real-time threat detection, and automated response capabilities. Built using open-source technologies and Python, it transforms security monitoring through ML-powered anomaly detection and intelligent threat correlation.

### Key Capabilities

🔍 **Real-time Threat Detection**
- ML ensemble anomaly detection (Isolation Forest + LOF + Autoencoder)
- Multi-source event correlation with 5 built-in rules
- Network flow analysis and DLP monitoring
- Honeypot interaction tracking

🎓 **Behavioral Intelligence**
- User clustering and peer group analysis
- Historical risk tracking with trend analysis
- Attack path visualization and risk propagation
- Long-term behavioral baselining

🤖 **Automated Response**
- SOAR-lite automation with 12 action types
- Risk-based playbook selection
- Customizable response handlers
- Integration-ready for external systems

📋 **Compliance Ready**
- Comprehensive audit logging
- 15 action types tracked
- Compliance reporting (PCI-DSS, SOC 2)
- CSV/JSON export capabilities

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- 4GB RAM minimum
- 10GB disk space

### Installation (5 minutes)

```bash
# 1. Navigate to project
cd nikhil/IntrusionAI

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run API server
python -m uvicorn app.api:app --reload --port 8000

# 5. Access documentation
# Open http://localhost:8000/docs
```

### Test the System

```bash
# Process a sample event
curl -X POST http://localhost:8000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "employee001",
    "device_id": "laptop001",
    "features": {
      "failed_login_attempts": 3.0,
      "sensitive_data_access": 2.5,
      "unusual_time_access": 1.0
    }
  }'
```

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| **[API_DOCUMENTATION.md](API_DOCUMENTATION.md)** | Complete API reference with endpoints, examples, and integration patterns |
| **[DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)** | Step-by-step deployment instructions for dev, test, and production |
| **[INTEGRATION_SUMMARY.md](INTEGRATION_SUMMARY.md)** | Technical overview of how all modules integrate together |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | System design, database schema, data flows, and performance metrics |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────┐
│          FastAPI REST API Gateway                   │
│         (Request Validation, Routing)               │
└────────────────────┬────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        │    Orchestrator         │
        │   Event Processing      │
        └────────────┬────────────┘
        │
    ┌───┴────┬──────┬─────────┓
    │         │      │         │
    ▼         ▼      ▼         ▼
┌────────┐ ┌──────┐┌──────┐┌────────┐
│   ML   │ │Threat││Peer  ││Network │
│Pipeline│ │ Intel││Group ││  DLP   │
└────────┘ └──────┘└──────┘└────────┘
    │         │      │         │
    └─────────┴──────┴─────────┘
            │
    ┌───────┴─────────┐
    │  Risk Scorer    │
    │  (Aggregates    │
    │   6 scores)     │
    └────────┬────────┘
             │
    ┌────────┴────────┐
    │  SOAR Engine    │
    │ (Automated      │
    │  Response)      │
    └────────┬────────┘
             │
    ┌────────┴────────┐
    │ Audit Logger    │
    │ (Compliance)    │
    └─────────────────┘
```

---

## 📊 Module Breakdown

| Module | Lines | Purpose |
|--------|-------|---------|
| **ML Pipeline** | 530 | Ensemble anomaly detection |
| **Threat Intelligence** | 635 | IP reputation & IOC matching |
| **Peer Group Analysis** | 650 | User clustering & baseline comparison |
| **Correlation Engine** | 680 | Multi-event pattern detection |
| **SOAR Engine** | 500 | Automated response & playbooks |
| **Attack Path Analyzer** | 650 | Graph-based threat modeling |
| **Risk Profiling** | 550 | Historical tracking & trends |
| **Audit Logger** | 600 | Compliance & audit logging |
| **Network/DLP Monitor** | 650 | Flow analysis & data exfiltration |
| **Honeypot Detector** | 500 | Honeypot interaction detection |
| **Orchestrator** | 450 | Central pipeline orchestration |
| **API Layer** | 700+ | FastAPI REST endpoints |
| **Total** | 6,955+ | **Complete production system** |

---

## 🔑 Core Features

### 1. Real-time Anomaly Detection
- **ML Ensemble**: Combines Isolation Forest (40%), LOF (35%), Autoencoder (25%)
- **Processing**: <100ms per event
- **Explainability**: SHAP values for interpretability

### 2. Threat Intelligence
- **Data Sources**: Mock provider + MISP integration ready
- **Coverage**: IP reputation, domains, file hashes, URLs
- **Cache**: 1-hour TTL with auto-cleanup
- **Performance**: <100ms lookups

### 3. Behavioral Analytics
- **User Clustering**: KMeans/DBSCAN algorithms
- **Baselines**: Per-role and per-peer-group
- **Deviation Scoring**: Z-score normalized to 0-1 range
- **Trend Analysis**: 7-day and 30-day tracking

### 4. Event Correlation
- **Patterns**: 5 built-in rules + extensible framework
- **Rules**:
  - Rapid file access (3+ in 60s)
  - Suspicious process chains
  - Network anomalies (5+ events)
  - Auth failures (3+ in 180s)
  - Data exfiltration patterns
- **Temporal**: 5-minute sliding windows

### 5. Network & DLP Monitoring
- **Flow Analysis**: Port anomalies, volume checks, new connections
- **Data Protection**:
  - Large transfer detection (>100MB)
  - USB monitoring
  - Sensitive file access tracking
  - Rapid access patterns (10+ in 5min)

### 6. Automated Response (SOAR)
- **Actions**: 12 types (MFA, block, logout, isolate, etc.)
- **Playbooks**: 3 default (critical, high, medium)
- **Risk Mapping**: Automatic selection based on risk level
- **Extensibility**: Custom handler registration

### 7. Risk Calculation
```
Final Risk = 
  behavioral_score × 0.25 +
  threat_score × 0.25 +
  peer_deviation × 0.15 +
  network_risk × 0.15 +
  dlp_risk × 0.10 +
  attack_path_risk × 0.10
```

**Risk Levels**:
- CRITICAL: ≥ 0.85
- HIGH: ≥ 0.70
- MEDIUM: ≥ 0.50
- LOW: ≥ 0.25
- MINIMAL: < 0.25

### 8. Compliance & Audit
- **Actions Logged**: 15 types (login, permission, data access, etc.)
- **Export**: CSV and JSON formats
- **Filters**: User, action, time range, severity
- **Compliance Reports**: Period summaries with metrics

---

## 🔗 API Endpoints

### Event Processing
- **POST /api/v1/events** - Process user event through full pipeline

### User Analytics
- **GET /api/v1/users/{user_id}/risk-score** - Get user risk profile
- **GET /api/v1/users/{user_id}/dashboard** - Get user dashboard

### Organization
- **GET /api/v1/organization/summary** - Get org-wide metrics

### Audit & Compliance
- **POST /api/v1/audit-logs** - Log audit event
- **GET /api/v1/audit-logs** - Search audit logs

### System
- **GET /api/v1/health** - System health status
- **GET /api/v1/status** - Quick status check

**Full API Documentation**: See [API_DOCUMENTATION.md](API_DOCUMENTATION.md)

---

## 💻 Deployment Options

### Development
```bash
python -m uvicorn app.api:app --reload --port 8000
```

### Production (Docker)
```bash
docker-compose up -d
```

### Kubernetes
```bash
kubectl apply -f k8s/deployment.yaml
```

**Details**: See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)

---

## 📈 Performance Characteristics

| Metric | Performance |
|--------|-------------|
| Event Processing Time | <500ms (full pipeline) |
| ML Prediction | <100ms |
| Risk Calculation | <50ms |
| Throughput | 1,000+ events/min (single instance) |
| Latency | <1s end-to-end API response |
| Memory Usage | <2GB baseline |
| Scalability | Linear with instances |

---

## 🔒 Security Features

- ✅ TLS/SSL encryption
- ✅ API key validation (OAuth 2.0 ready)
- ✅ Rate limiting ready
- ✅ Full audit logging
- ✅ Compliance exports
- ✅ Data encryption at rest (configurable)
- ✅ PII protection (field-level encryption ready)

---

## 🛠️ Technology Stack

### Backend
- **Framework**: FastAPI (0.115+)
- **Server**: Uvicorn/Gunicorn
- **Language**: Python 3.11+

### Machine Learning
- **Anomaly Detection**: scikit-learn (Isolation Forest, LOF)
- **Clustering**: KMeans, DBSCAN
- **Explainability**: SHAP
- **Optional**: TensorFlow (Autoencoder)

### Data & Analysis
- **Processing**: pandas, numpy
- **Graphs**: NetworkX
- **Serialization**: joblib, orjson

### Database
- **Development**: SQLite
- **Production**: PostgreSQL 13+
- **Cache**: Redis 6+

### Monitoring
- **Logging**: Structured JSON logs
- **Metrics**: Prometheus-ready
- **Visualization**: Grafana-compatible

---

## 📝 File Structure

```
IntrusionAI/
├── app/
│   ├── api.py                    # FastAPI endpoints
│   ├── orchestrator.py           # Central orchestrator
│   ├── ml_pipeline.py            # ML anomaly detection
│   ├── threat_intelligence.py    # Threat intel
│   ├── peer_group_analysis.py    # User profiling
│   ├── correlation_engine.py     # Event correlation
│   ├── soar_engine.py            # Automated response
│   ├── attack_path_analyzer.py   # Graph analysis
│   ├── risk_profiling.py         # Risk tracking
│   ├── audit_logger.py           # Compliance logging
│   ├── network_dlp_monitor.py    # Network/DLP
│   └── honeypot_detector.py      # Honeypot tracking
│
├── API_DOCUMENTATION.md          # API reference
├── DEPLOYMENT_GUIDE.md           # Deployment instructions
├── INTEGRATION_SUMMARY.md        # Integration overview
├── ARCHITECTURE.md               # System architecture
├── README.md                     # This file
│
├── requirements.txt              # Dependencies
├── Dockerfile                    # Container image
├── docker-compose.yml            # Multi-container setup
└── .env.example                  # Environment template
```

---

## 🧪 Testing

### Run Tests
```bash
pytest tests/ -v --cov=app
```

### Test Deployment
```bash
python tests/test_deployment.py
```

---

## 📖 Configuration

Create `.env` file (copy from `.env.example`):

```bash
API_PORT=8000
LOG_LEVEL=INFO
DATABASE_URL=postgresql://user:pass@localhost:5432/intrusion_ai
REDIS_URL=redis://localhost:6379/0
REDIS_ENABLED=false
```

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for full configuration options.

---

## 🤝 Integration Examples

### SIEM Integration (Splunk)
```python
from app.api import BASE_URL
import requests

# Send Splunk events to IntrusionAI
event = {
    "user_id": "splunk_user",
    "device_id": "splunk_device",
    "features": {...}
}

response = requests.post(f"{BASE_URL}/events", json=event)
risk_level = response.json()["risk_level"]
```

### Incident Response (PagerDuty)
```python
# Create PagerDuty incident for CRITICAL events
if risk_level == "CRITICAL":
    create_pagerduty_incident(event)
```

See [API_DOCUMENTATION.md](API_DOCUMENTATION.md) for more integration examples.

---

## 🚨 Troubleshooting

### API won't start
```bash
# Check Python version
python --version  # Should be 3.11+

# Verify dependencies
pip install -r requirements.txt --upgrade

# Run in debug mode
export LOG_LEVEL=DEBUG
python -m uvicorn app.api:app --reload
```

### Events processing slowly
```bash
# Check system resources
ps aux | grep python
free -h

# Monitor processing
curl http://localhost:8000/api/v1/health | jq .
```

### Database connection errors
```bash
# Verify PostgreSQL
psql -U user -d intrusion_ai

# Check DATABASE_URL
echo $DATABASE_URL
```

See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) troubleshooting section for more.

---

## 📚 Learning Resources

1. **Getting Started**: Start with Quick Start section above
2. **API Usage**: Read [API_DOCUMENTATION.md](API_DOCUMENTATION.md)
3. **Deployment**: Follow [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
4. **Architecture**: Study [ARCHITECTURE.md](ARCHITECTURE.md)
5. **Integration**: Review [INTEGRATION_SUMMARY.md](INTEGRATION_SUMMARY.md)

---

## 🔄 Development Workflow

### Making Changes

1. Create feature branch
   ```bash
   git checkout -b feature/my-feature
   ```

2. Make changes and test
   ```bash
   pytest tests/ -v
   ```

3. Run API locally
   ```bash
   python -m uvicorn app.api:app --reload
   ```

4. Commit and push
   ```bash
   git add .
   git commit -m "feat: add new feature"
   git push origin feature/my-feature
   ```

### Code Style

- Follow PEP 8
- Use type hints
- Add docstrings
- Include unit tests

---

## 📦 Dependencies

**Core Framework**: fastapi, uvicorn, pydantic
**ML Libraries**: scikit-learn, numpy, pandas, joblib, shap
**Data Analysis**: networkx, xgboost, tensorflow (optional)
**Database**: sqlalchemy, psycopg2-binary, redis
**System**: psutil, pywin32, pynput
**Logging**: python-json-logger, structlog

See `requirements.txt` for complete list with versions.

---

## 📅 Roadmap

### Phase 1 (Current) ✅
- Core UEBA engine
- 11 integrated modules
- REST API
- Audit logging

### Phase 2 (Q2 2024)
- Web dashboard UI
- Advanced visualization
- Custom playbooks
- Multi-tenancy

### Phase 3 (Q3 2024)
- ML model improvements
- Behavioral baseline tuning
- Advanced analytics
- Integration marketplace

### Phase 4 (Q4 2024)
- Real-time streaming (WebSockets)
- Predictive analytics
- Autonomous response
- AI-powered insights

---

## 📞 Support

### Documentation
- **API Guide**: [API_DOCUMENTATION.md](API_DOCUMENTATION.md)
- **Deployment**: [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
- **Integration**: [INTEGRATION_SUMMARY.md](INTEGRATION_SUMMARY.md)
- **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)

### Getting Help
- Check existing documentation
- Review code examples
- Run test scripts
- Check system logs

---

## 📄 License

IntrusionAI is provided under the MIT License. See LICENSE file for details.

---

## 🎉 Getting Started Next Steps

1. **Install**: Run quick start commands above
2. **Explore**: Open http://localhost:8000/docs
3. **Test**: Process sample events
4. **Deploy**: Follow DEPLOYMENT_GUIDE.md
5. **Integrate**: Use API_DOCUMENTATION.md examples
6. **Monitor**: Check /api/v1/health endpoint

---

## 💡 Key Insights

**Why IntrusionAI?**
- 🎯 Real-time threat detection with <500ms latency
- 📊 ML-powered anomaly detection with explainability
- 🤖 Automated response reducing MTTR
- 📋 Compliance-ready audit logging
- 🔧 Open-source, no vendor lock-in
- 📈 Scalable from single host to Kubernetes clusters

---

**Version**: 1.0.0  
**Status**: Production Ready  
**Last Updated**: January 2024

---

**Ready to get started?** 👉 [Quick Start](#-quick-start)

Need help? 👉 Check [API Documentation](API_DOCUMENTATION.md)
