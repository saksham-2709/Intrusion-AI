# IntrusionAI - Hybrid UEBA + Behavioral Intelligence System
## Comprehensive Architecture & Implementation Guide

---

## 1. SYSTEM OVERVIEW

### Vision
Transform IntrusionAI into a production-grade User and Entity Behavior Analytics (UEBA) system with threat intelligence, real-time correlation, and automated response capabilities.

### Core Pipeline
```
Data Collection → Feature Engineering → ML Anomaly Detection → Risk Scoring → 
Threat Intelligence → Peer Group Comparison → Correlation → Automated Response
```

### Tech Stack
- **Language**: Python 3.11+
- **API Framework**: FastAPI
- **Database**: PostgreSQL (primary), SQLite (local cache), Redis (real-time)
- **Message Queue**: Kafka (optional, for high throughput)
- **ML Libraries**: scikit-learn, XGBoost, SHAP, TensorFlow (Autoencoder optional)
- **Visualization**: Plotly, Grafana-ready
- **Monitoring**: ELK Stack (Elasticsearch, Logstash, Kibana)

---

## 2. SYSTEM ARCHITECTURE DIAGRAM

```
┌─────────────────────────────────────────────────────────────────────┐
│                      DATA INGESTION LAYER                           │
├─────────────────────────────────────────────────────────────────────┤
│  Keyboard/Mouse  │  Process Logs  │  Network Logs  │  File Activity │
└────────┬──────────┴────────┬───────┴────────┬───────┴────────┬──────┘
         │                  │                │                │
         └──────────────────┼────────────────┼────────────────┘
                            │
         ┌──────────────────▼───────────────────┐
         │  EVENT BUFFER & STREAM PROCESSOR     │
         │  (Real-time windowing, normalization)│
         └──────────────────┬───────────────────┘
                            │
         ┌──────────────────▼───────────────────────────────┐
         │      FEATURE ENGINEERING & ENRICHMENT            │
         │  - Keystroke dynamics                            │
         │  - Mouse behavior                                │
         │  - System resource usage                         │
         │  - Network characteristics                       │
         │  - Application context                           │
         └──────────┬──────────────┬──────────────┬──────────┘
                    │              │              │
      ┌─────────────▼┐  ┌──────────▼─┐  ┌────────▼──────┐
      │ THREAT       │  │ PEER GROUP  │  │ MULTI-SOURCE  │
      │ INTELLIGENCE │  │ ANALYSIS    │  │ CORRELATION   │
      │ Integration  │  │ (KMeans)    │  │ Engine        │
      └─────────────┬┘  └──────────┬─┘  └────────┬───────┘
                    │              │             │
         ┌──────────▼──────────────▼─────────────▼──────────┐
         │     ANOMALY DETECTION (ML Pipeline)              │
         │  ┌─────────────────────────────────────────┐    │
         │  │ Isolation Forest                         │    │
         │  │ Local Outlier Factor (LOF)               │    │
         │  │ Autoencoder (optional, deep learning)    │    │
         │  │ XGBoost Classifier                       │    │
         │  └─────────────────────────────────────────┘    │
         └──────────┬──────────────────────────────────────┘
                    │
         ┌──────────▼────────────────────────────┐
         │  RISK SCORING & AGGREGATION            │
         │  - Behavioral risk score               │
         │  - Threat intelligence score           │
         │  - Peer deviation score                │
         │  - Attack path risk                    │
         │  - Final risk = Weighted combination   │
         └──────────┬────────────────────────────┘
                    │
         ┌──────────▼────────────────────────────┐
         │  SOAR-LITE RESPONSE ENGINE             │
         │  - Rule-based automation               │
         │  - Playbook execution                  │
         │  - Alert generation                    │
         └──────────┬────────────────────────────┘
                    │
      ┌─────────────┼─────────────┐
      │             │             │
  ┌───▼──┐    ┌────▼─┐    ┌─────▼────┐
  │Alert │    │Logs  │    │Dashboard │
  │Store │    │(ELK) │    │(API+Web) │
  └──────┘    └──────┘    └──────────┘
```

---

## 3. MODULE BREAKDOWN

### Phase 1: Core Infrastructure
1. **ML Pipeline Module** (`ml_pipeline.py`)
   - Anomaly detection models
   - Feature normalization
   - Model training/inference
   - SHAP explainability

### Phase 2: Data Enrichment
2. **Threat Intelligence Module** (`threat_intelligence.py`)
   - IP reputation lookup
   - IOC matching
   - Mock API for testing

3. **Peer Group Analysis** (`peer_group_analysis.py`)
   - User clustering
   - Baseline calculation
   - Deviation detection

4. **Multi-Source Correlation** (`correlation_engine.py`)
   - Event aggregation
   - Cross-source correlation
   - Time-windowed analysis

### Phase 3: Advanced Features
5. **Network Monitoring** (`network_monitor.py`)
   - Connection tracking
   - Data exfiltration detection
   - Unusual flow detection

6. **Data Loss Prevention** (`dlp_monitor.py`)
   - File access tracking
   - USB monitoring
   - Large transfer detection

7. **Attack Path Analysis** (`attack_path_analyzer.py`)
   - Graph-based modeling
   - Process chain tracking
   - Privilege escalation detection

### Phase 4: Automation & Response
8. **SOAR Response Engine** (`soar_engine.py`)
   - Rule-based automation
   - Playbook management
   - Response execution

9. **Honeypot Integration** (`honeypot_detector.py`)
   - Honeypot interaction tracking
   - Immediate risk assignment

### Phase 5: Long-term Analytics
10. **Risk Profiling** (`risk_profiling.py`)
    - Historical tracking
    - Trend analysis
    - Trust score calculation

11. **Audit Logging** (`audit_logger.py`)
    - Structured logging
    - Compliance reporting
    - Data export

---

## 4. DATABASE SCHEMA

### PostgreSQL Tables

```sql
-- Users & Devices
CREATE TABLE users (
    user_id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(100) NOT NULL,
    department VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE devices (
    device_id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(user_id),
    device_name VARCHAR(255),
    os_type VARCHAR(50),
    mac_address VARCHAR(17) UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Events & Features
CREATE TABLE event_windows (
    id SERIAL PRIMARY KEY,
    device_id UUID REFERENCES devices(device_id),
    user_id UUID REFERENCES users(user_id),
    timestamp_utc TIMESTAMP NOT NULL,
    window_seconds INT NOT NULL,
    
    -- Keystroke dynamics
    wpm FLOAT, key_hold_mean FLOAT, key_flight_mean FLOAT,
    backspace_count INT, keystroke_count INT,
    
    -- Mouse dynamics
    mouse_distance FLOAT, mouse_avg_speed FLOAT,
    mouse_clicks INT, mouse_scrolls INT, mouse_accel_mean FLOAT,
    
    -- System metrics
    cpu_usage FLOAT, memory_usage FLOAT, process_count INT,
    session_idle_time FLOAT, battery_level FLOAT,
    
    -- Network & Location
    ip_address VARCHAR(45), geo_location VARCHAR(255),
    network_type VARCHAR(50), latitude FLOAT, longitude FLOAT,
    
    -- App context
    active_app_hash INT, active_window_title TEXT,
    
    -- Index for performance
    INDEX idx_user_time (user_id, timestamp_utc),
    INDEX idx_device_time (device_id, timestamp_utc)
);

-- Anomalies & Scores
CREATE TABLE anomaly_scores (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(user_id),
    device_id UUID REFERENCES devices(device_id),
    timestamp_utc TIMESTAMP NOT NULL,
    
    -- Individual scores
    behavioral_score FLOAT,
    threat_score FLOAT,
    peer_deviation_score FLOAT,
    network_risk_score FLOAT,
    dlp_risk_score FLOAT,
    attack_path_risk FLOAT,
    
    -- Final aggregate
    final_risk_score FLOAT NOT NULL,
    risk_level VARCHAR(20) CHECK (risk_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    
    -- Explanation
    primary_anomaly VARCHAR(255),
    anomaly_details JSONB,
    
    INDEX idx_user_risk_time (user_id, timestamp_utc, final_risk_score)
);

-- Peer Groups & Baselines
CREATE TABLE peer_groups (
    peer_group_id UUID PRIMARY KEY,
    group_name VARCHAR(255) NOT NULL,
    role VARCHAR(100),
    department VARCHAR(100),
    user_count INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_peer_membership (
    user_id UUID REFERENCES users(user_id),
    peer_group_id UUID REFERENCES peer_groups(peer_group_id),
    PRIMARY KEY (user_id, peer_group_id)
);

CREATE TABLE baseline_metrics (
    baseline_id UUID PRIMARY KEY,
    peer_group_id UUID REFERENCES peer_groups(peer_group_id),
    metric_name VARCHAR(255),
    mean_value FLOAT,
    stddev_value FLOAT,
    p95_value FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Threat Intelligence Cache
CREATE TABLE threat_intel_cache (
    ip_address VARCHAR(45) PRIMARY KEY,
    threat_score FLOAT,
    is_malicious BOOLEAN,
    iocs JSONB,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ttl_seconds INT DEFAULT 86400
);

-- Alert & Response
CREATE TABLE alerts (
    alert_id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(user_id),
    device_id UUID REFERENCES devices(device_id),
    timestamp_utc TIMESTAMP NOT NULL,
    risk_score FLOAT,
    alert_type VARCHAR(100),
    message TEXT,
    status VARCHAR(50) DEFAULT 'OPEN',
    assigned_to VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    INDEX idx_status_time (status, created_at)
);

CREATE TABLE response_actions (
    action_id UUID PRIMARY KEY,
    alert_id UUID REFERENCES alerts(alert_id),
    action_type VARCHAR(100),
    parameters JSONB,
    status VARCHAR(50) DEFAULT 'PENDING',
    executed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit Log
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp_utc TIMESTAMP NOT NULL,
    user_id UUID REFERENCES users(user_id),
    action VARCHAR(255),
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    details JSONB,
    severity VARCHAR(20) CHECK (severity IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    INDEX idx_timestamp (timestamp_utc),
    INDEX idx_severity_time (severity, timestamp_utc)
);

-- Risk Timeline
CREATE TABLE user_risk_timeline (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(user_id),
    date DATE NOT NULL,
    avg_daily_risk FLOAT,
    max_daily_risk FLOAT,
    alert_count INT,
    trust_score FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, date)
);
```

### Redis Keys (Real-time Data)
```
ueba:user:{user_id}:current_risk      - Current risk score
ueba:peer_group:{group_id}:baseline   - Baseline metrics (cached)
ueba:threat_cache:{ip}                - Threat score cache
ueba:session:{session_id}             - Active session tracking
ueba:alerts:queue                     - Alert queue (list)
```

---

## 5. API ENDPOINT DESIGN

### Threat Intelligence Endpoints
```
GET  /api/v1/threat-intel/score/{ip}
GET  /api/v1/threat-intel/iocs/{indicator}
POST /api/v1/threat-intel/check-batch
```

### Risk Scoring Endpoints
```
GET  /api/v1/users/{user_id}/risk-score
GET  /api/v1/users/{user_id}/risk-timeline
GET  /api/v1/devices/{device_id}/anomalies
```

### Peer Group Endpoints
```
GET  /api/v1/peer-groups
POST /api/v1/peer-groups
GET  /api/v1/peer-groups/{group_id}/members
GET  /api/v1/peers/{user_id}/baseline
```

### Alert & Response Endpoints
```
GET  /api/v1/alerts
POST /api/v1/alerts
PUT  /api/v1/alerts/{alert_id}/resolve
POST /api/v1/responses/{action_id}/execute
```

### Compliance Endpoints
```
GET  /api/v1/audit-logs
GET  /api/v1/reports/compliance
GET  /api/v1/reports/user-activity/{user_id}
```

---

## 6. DATA FLOW EXAMPLES

### Example 1: Risk Score Calculation
```
User Activity (Keystroke, Mouse, Network)
    ↓
[Feature Engineering] (30-second window)
    ↓
[ML Models]
  - Isolation Forest (behavioral anomaly)
  - LOF (density-based outlier)
  → Behavioral Score: 0.75 (1 = anomaly)
    ↓
[Threat Intel]
  - IP reputation lookup
  → Threat Score: 0.45
    ↓
[Peer Group Analysis]
  - Compare against role baseline
  → Peer Deviation Score: 0.60
    ↓
[Attack Path Analysis]
  - Check process/file/network chain
  → Attack Path Risk: 0.30
    ↓
[Final Aggregation]
  final_risk = (0.75 * 0.4) + (0.45 * 0.25) + (0.60 * 0.2) + (0.30 * 0.15)
            = 0.30 + 0.1125 + 0.12 + 0.045
            = 0.583 (MEDIUM-HIGH RISK)
    ↓
[Response Engine]
  IF final_risk > 0.7: Force MFA
  IF final_risk > 0.85: Force Logout
```

---

## 7. IMPLEMENTATION PHASES

### Phase 1: Foundation (Week 1)
- [ ] ML Pipeline setup
- [ ] Database schema
- [ ] Basic API structure

### Phase 2: Data Enrichment (Week 2)
- [ ] Threat Intelligence
- [ ] Peer Group Analysis
- [ ] Correlation Engine

### Phase 3: Advanced Features (Week 3)
- [ ] Network Monitoring
- [ ] DLP
- [ ] Attack Path Analysis

### Phase 4: Automation (Week 4)
- [ ] SOAR Engine
- [ ] Honeypot Integration
- [ ] Response Playbooks

### Phase 5: Analytics (Week 5)
- [ ] Risk Profiling
- [ ] Audit Logging
- [ ] Reporting & Dashboard

---

## 8. PERFORMANCE CONSIDERATIONS

### Scalability Strategy
1. **Windowing**: 30-second feature windows → ~2 windows per minute per user
2. **Model Inference**: Real-time predictions (~10ms per window)
3. **Database Indexing**: Time-series + user/device indices
4. **Caching**: Redis for threat intel, peer baselines
5. **Async Processing**: Kafka for correlation, risk profiling
6. **Batch Processing**: Nightly retraining, report generation

### Target Metrics
- **Latency**: <500ms for risk score calculation
- **Throughput**: Handle 1000 concurrent users
- **Storage**: ~10GB/month per 100 active users
- **Detection Accuracy**: >90% F1 score on known attacks

---

## 9. SECURITY & COMPLIANCE

### Data Privacy
- PII encryption at rest
- Role-based access control (RBAC)
- Data retention policies
- GDPR/CCPA compliance logging

### Audit Requirements
- All actions logged with user/timestamp
- Immutable audit trail
- Export capabilities (JSON/CSV)
- Real-time compliance monitoring

---

## 10. NEXT STEPS

1. Create ML pipeline module
2. Implement threat intelligence service
3. Build peer group analysis
4. Set up database & migrations
5. Implement correlation engine
6. Add SOAR automation
7. Create API layer
8. Deploy & monitor

---

This architecture provides a scalable, modular foundation for enterprise-grade UEBA.
Each module can be deployed independently and scales horizontally.
