# منصة التعداد السكاني الوطنية — وثيقة المعمارية الشاملة
# National Census & Demographic Survey Platform — Full Architecture Document

**Classification:** CONFIDENTIAL — Government Use Only  
**Version:** 1.0.0  
**Date:** 2026-05-25  
**Authors:** Principal Architecture Team  
**Compliance:** ISO 27001 | GDPR | UN Privacy Framework | NIST SP 800-63

---

## Executive Summary

تصمم هذه الوثيقة منصة تعداد سكاني وطنية عالية الموثوقية مصممة للعمل في بيئات:
- تعدد الأعراق والديانات
- بيئات سياسية وأمنية معقدة
- بنية تحتية ضعيفة أو غائبة
- اللاجئين وفاقدي الوثائق الرسمية

### المبادئ التأسيسية

| المبدأ | التطبيق |
|--------|---------|
| **Privacy by Design** | الهوية مفصولة تمامًا عن البيانات الديموغرافية |
| **Zero Trust Security** | كل طلب يُتحقق منه بشكل مستقل |
| **Offline First** | تعمل بدون إنترنت مستمر |
| **Inclusive Access** | تدعم بدون وثائق رسمية |
| **Political Neutrality** | لا يمكن ربط بيانات الفرد بهويته حتى للحكومة |

---

## 1. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CENSUS PLATFORM                              │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │   CITIZENS   │    │  FIELD AGENTS│    │   ADMIN / ANALYSTS   │  │
│  │  Web/Mobile  │    │  Offline App │    │   Secure Dashboard   │  │
│  └──────┬───────┘    └──────┬───────┘    └──────────┬───────────┘  │
│         │                  │                        │              │
│  ╔══════╧══════════════════╧═══════════╗            │              │
│  ║          API GATEWAY (Kong)         ║            │              │
│  ║    Rate Limiting | Auth | Routing   ║            │              │
│  ╚══════════════════════╤═════════════╝            │              │
│                         │                           │              │
│  ┌──────────────────────┼───────────────────────┐   │              │
│  │   MICROSERVICES LAYER│                       │   │              │
│  │  ┌────────────┐  ┌───┴──────────┐  ┌───────┐ │   │              │
│  │  │  Identity  │  │   Census     │  │ Audit │ │   │              │
│  │  │  Service   │  │   Service    │  │  Log  │ │   │              │
│  │  └─────┬──────┘  └──────┬───────┘  └───┬───┘ │   │              │
│  │        │                │               │     │   │              │
│  │  ┌─────┴──────┐  ┌──────┴───────┐       │     │   │              │
│  │  │    OTP     │  │  Demographic │       │     │   │              │
│  │  │   Face ID  │  │  Aggregation │       │     │   │              │
│  │  │    OCR     │  │   Engine     │       │     │   │              │
│  │  │  Fraud Det.│  └──────┬───────┘       │     │   │              │
│  │  └────────────┘         │               │     │   │              │
│  └─────────────────────────┼───────────────┘     │   │              │
│                            │                     │   │              │
│  ╔═════════════════════════╧═════════════════════╧═══╧════════════╗ │
│  ║                    DATA LAYER                                   ║ │
│  ║  ┌──────────────┐  ┌────────────────┐  ┌────────────────────┐  ║ │
│  ║  │  Identity DB │  │  Demographic   │  │   Audit Trail DB   │  ║ │
│  ║  │  (Encrypted) │  │  DB (Anon.)    │  │   (Immutable)      │  ║ │
│  ║  │  PostgreSQL  │  │  PostgreSQL    │  │   Apache Kafka     │  ║ │
│  ║  └──────────────┘  └────────────────┘  └────────────────────┘  ║ │
│  ╚═════════════════════════════════════════════════════════════════╝ │
│                                                                     │
│  ╔═════════════════════════════════════════════════════════════════╗ │
│  ║  ZKP LAYER — Zero Knowledge Proof Bridge (Linkage Prevention)  ║ │
│  ╚═════════════════════════════════════════════════════════════════╝ │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Security Model

### 2.1 Identity Verification Pipeline

```
CITIZEN ENROLLMENT FLOW:
─────────────────────────────────────────────────────────────────
Step 1: Device Registration
  └─► Device Fingerprint Generated (Browser/Mobile)
  └─► Device Risk Score Calculated
  └─► TLS 1.3 Channel Established

Step 2: Identity Proof (One of these paths)
  PATH A: Has National ID
    └─► OCR ID Document Scan (ML Model)
    └─► Face Match (Liveness Detection)
    └─► Database Cross-check (Deduplication)
  
  PATH B: Has Phone Number Only  
    └─► OTP via SMS/WhatsApp/Voice
    └─► Face Liveness Check (Selfie)
    └─► Trusted Witness Signature (Field Agent)
  
  PATH C: Refugee / No Documents
    └─► UNHCR Integration (if available)
    └─► Biometric Hash (facial geometry — NOT stored as image)
    └─► Community Leader Attestation

Step 3: ZKP Token Generation
  └─► Identity → Anonymous Token (ZKP)
  └─► Token stored separately from Identity
  └─► Token used for all census interactions

Step 4: Census Completion
  └─► Demographic data submitted with Token only
  └─► No direct link to Identity exists
  └─► Confirmation receipt issued
─────────────────────────────────────────────────────────────────
```

### 2.2 Zero Knowledge Proof Architecture

```
IDENTITY DATABASE          ZKP BRIDGE            CENSUS DATABASE
─────────────────         ──────────            ─────────────────
│ citizen_id    │         │ Prover  │            │ census_token  │
│ real_name     │ ──────► │ Circuit │ ──────►    │ ethnicity     │
│ id_number     │         │ Verifier│            │ religion      │
│ face_hash     │         │         │            │ language      │
│ phone_hash    │         └─────────┘            │ region        │
└───────────────┘                                └───────────────┘
        │                                               │
        │         MATHEMATICAL GUARANTEE:               │
        └──── No party can link these two sides ────────┘
              without breaking cryptographic assumptions
```

### 2.3 Encryption Strategy

| Layer | Algorithm | Key Management |
|-------|-----------|---------------|
| Data at Rest | AES-256-GCM | AWS KMS / HSM |
| Data in Transit | TLS 1.3 + HSTS | Let's Encrypt / Internal CA |
| Biometric Hash | SHA-3 + Salt | Per-citizen derived salt |
| ZKP Proof | Groth16 / PLONK | Public circuit, private witness |
| Database Columns | pgcrypto | Envelope encryption |
| Backup | ChaCha20-Poly1305 | Air-gapped key ceremony |

### 2.4 OTP Service Design

```
OTP Flow:
1. User requests OTP for phone +XXX-XXX-XXXX
2. System generates: TOTP(secret, window=5min, digits=6)
3. Delivery channels (in order of availability):
   a. SMS (Twilio/Africa's Talking)
   b. WhatsApp Business API
   c. Voice Call (IVR)
   d. Email (fallback)
4. Rate limiting: 3 attempts / 10 min / device
5. OTP stored as: bcrypt(otp_code, cost=12)
6. Post-verification: OTP deleted immediately
7. Success event written to audit log
```

### 2.5 Face Verification — Liveness Detection

```
Face Verification Pipeline:
┌─────────────────────────────────────────────────────┐
│  1. Capture: 3-second video clip OR photo           │
│  2. Liveness: Passive (texture analysis) +          │
│     Active (head movement instruction)              │
│  3. Quality Check: Resolution, lighting, blur       │
│  4. Face Detection: MTCNN / MediaPipe               │
│  5. Feature Extraction: FaceNet-512 embeddings      │
│  6. Deduplication: ANN search (FAISS index)         │
│  7. ID Match: Cosine similarity > 0.85              │
│  8. Hash Storage: SHA3(embedding + citizen_salt)    │
│     → Raw image NEVER stored                        │
└─────────────────────────────────────────────────────┘

Anti-Spoofing Measures:
- 3D depth map analysis (if device supports)
- IR texture analysis
- Micro-expression detection
- Background consistency check
- Video frame temporal analysis
```

### 2.6 OCR ID Verification

```
OCR Pipeline:
┌────────────────────────────────────────────────────────┐
│  Supported Documents:                                   │
│  - National ID Cards (50+ country formats)              │
│  - Passports (ICAO 9303 MRZ)                            │
│  - Residence Permits                                    │
│  - Refugee Documents (UNHCR)                            │
│  - Birth Certificates                                   │
│                                                         │
│  Processing Steps:                                      │
│  1. Document Classification (CNN model)                 │
│  2. Perspective Correction (OpenCV)                     │
│  3. MRZ Extraction (regex + ML)                         │
│  4. Field OCR (Tesseract + custom model)                │
│  5. Checksum Validation (ID algorithms)                 │
│  6. Hologram/Watermark Detection                        │
│  7. Tampering Detection (ELA analysis)                  │
│  8. Cross-reference with national DB (if available)     │
│                                                         │
│  Privacy: Document image deleted after 15 minutes       │
└────────────────────────────────────────────────────────┘
```

### 2.7 Device Fingerprinting

```javascript
Device Signals Collected:
{
  "hardware": {
    "screen_resolution": "1920x1080",
    "color_depth": 24,
    "hardware_concurrency": 8,
    "device_memory": 8,
    "gpu_renderer": "hashed_value"
  },
  "browser": {
    "user_agent": "parsed_components",
    "plugins": "hashed_list",
    "canvas_hash": "unique_per_browser",
    "webgl_hash": "gpu_signature",
    "audio_hash": "hardware_signature",
    "fonts_hash": "installed_fonts_signature"
  },
  "network": {
    "timezone": "UTC+3",
    "language": "ar-IQ",
    "connection_type": "4g"
  },
  "behavioral": {
    "typing_rhythm_hash": "keystroke_dynamics",
    "mouse_dynamics_hash": "movement_patterns"
  }
}

Risk Score = WeightedModel(signals) → [0.0, 1.0]
Block if score > 0.85 (high fraud probability)
```

### 2.8 Fraud Detection Engine

```
Multi-Layer Fraud Detection:

Layer 1: Real-time Rules (< 10ms)
  ├─ IP velocity: > 5 registrations/hour → BLOCK
  ├─ Device reuse: same fingerprint > 1 registration → REVIEW
  ├─ Geographic impossibility: 2 submissions 1000km apart in 1 hour → BLOCK
  └─ OTP sharing: same OTP used twice → BLOCK

Layer 2: ML Model (< 200ms)  
  ├─ Features: time patterns, behavioral signals, device signals
  ├─ Model: XGBoost ensemble + Isolation Forest
  └─ Threshold: P(fraud) > 0.7 → human review queue

Layer 3: Graph Analysis (async)
  ├─ Social network: detect coordinated fake registrations
  ├─ Phone number clusters: detect SIM farm attacks
  └─ Face similarity clusters: detect photo reuse attacks

Layer 4: Human Review Queue
  └─ Flagged cases → supervisor review within 24 hours
```

---

## 3. Database Design

### 3.1 Identity Database (Isolated — High Security Zone)

```sql
-- Identity DB: Stores ONLY what's needed for verification
-- NEVER joined with demographic data in production

CREATE TABLE citizens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_hash      BYTEA NOT NULL UNIQUE,   -- SHA3(phone + global_salt)
    face_hash       BYTEA UNIQUE,             -- SHA3(embeddings + citizen_salt)
    document_hash   BYTEA UNIQUE,             -- SHA3(doc_number + type + issuer)
    enrollment_path VARCHAR(20) NOT NULL,     -- 'document'|'phone'|'biometric'|'agent'
    device_id       UUID REFERENCES devices(id),
    zkp_token_id    UUID NOT NULL UNIQUE,     -- Link to ZKP table only
    enrollment_at   TIMESTAMPTZ DEFAULT NOW(),
    verification_level SMALLINT NOT NULL DEFAULT 1, -- 1=phone, 2=face, 3=document
    is_active       BOOLEAN DEFAULT TRUE,
    -- NO name, NO real ID number, NO address stored here
    CONSTRAINT valid_verification_level CHECK (verification_level BETWEEN 1 AND 3)
);

CREATE TABLE devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint_hash BYTEA NOT NULL,
    risk_score      NUMERIC(3,2) DEFAULT 0.0,
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    last_seen       TIMESTAMPTZ DEFAULT NOW(),
    registration_count SMALLINT DEFAULT 0,
    is_blocked      BOOLEAN DEFAULT FALSE,
    block_reason    VARCHAR(100)
);

CREATE TABLE otp_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_hash      BYTEA NOT NULL,
    otp_hash        BYTEA NOT NULL,          -- bcrypt(otp_code)
    expires_at      TIMESTAMPTZ NOT NULL,
    attempts        SMALLINT DEFAULT 0,
    verified        BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT max_attempts CHECK (attempts <= 3)
);

CREATE TABLE field_agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_code      VARCHAR(20) NOT NULL UNIQUE,
    region_code     VARCHAR(10) NOT NULL,
    public_key      TEXT NOT NULL,           -- For attestation signatures
    is_active       BOOLEAN DEFAULT TRUE,
    attestations_count INTEGER DEFAULT 0,
    max_daily_attestations INTEGER DEFAULT 50
);
```

### 3.2 ZKP Bridge Table (Minimal Cross-Reference)

```sql
-- This table holds ONLY anonymous tokens
-- The cryptographic proof ensures identity ↔ token link is unverifiable

CREATE TABLE zkp_tokens (
    token_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Proof that holder is verified citizen, without revealing who
    proof_data      BYTEA NOT NULL,
    circuit_version VARCHAR(10) NOT NULL,
    nullifier_hash  BYTEA NOT NULL UNIQUE,   -- Prevents double-use
    issued_at       TIMESTAMPTZ DEFAULT NOW(),
    census_used     BOOLEAN DEFAULT FALSE,
    census_used_at  TIMESTAMPTZ
);
```

### 3.3 Demographic Database (Anonymized — Analytical Zone)

```sql
-- Demographic DB: Contains NO identity information whatsoever
-- All data is anonymous by design

CREATE TABLE census_responses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_nullifier BYTEA NOT NULL UNIQUE,   -- Prevents double submission
    
    -- Geographic (coarsened for privacy — district level, not street)
    region_code     VARCHAR(10) NOT NULL,
    district_code   VARCHAR(10),
    is_urban        BOOLEAN,
    
    -- Demographic (self-reported)
    ethnicity_code  VARCHAR(20),
    language_code   VARCHAR(20),             -- ISO 639-3
    religion_code   VARCHAR(20),
    age_bracket     VARCHAR(10),             -- '18-24', '25-34', etc. NOT exact age
    gender_code     VARCHAR(10),
    household_size  SMALLINT,
    
    -- Socioeconomic indicators
    education_level VARCHAR(20),
    employment_status VARCHAR(20),
    housing_type    VARCHAR(20),
    
    -- Submission metadata (no IP, no device)
    submission_channel VARCHAR(20),         -- 'web'|'mobile'|'offline'|'agent'
    submission_region VARCHAR(10),          -- Approximate geographic region
    submitted_at    TIMESTAMPTZ DEFAULT NOW(),
    
    -- Data quality
    completion_rate NUMERIC(3,2),
    response_time_seconds INTEGER,
    
    CONSTRAINT valid_age_bracket CHECK (
        age_bracket IN ('under-18','18-24','25-34','35-44','45-54','55-64','65+')
    )
);

-- Reference tables (ethnicity/language/religion are configurable)
CREATE TABLE ethnicities (
    code            VARCHAR(20) PRIMARY KEY,
    name_local      VARCHAR(100) NOT NULL,
    name_en         VARCHAR(100) NOT NULL,
    is_active       BOOLEAN DEFAULT TRUE
);

CREATE TABLE languages (
    code            VARCHAR(20) PRIMARY KEY,  -- ISO 639-3
    name_local      VARCHAR(100) NOT NULL,
    name_en         VARCHAR(100) NOT NULL,
    script          VARCHAR(20)               -- 'arabic', 'latin', 'cyrillic', etc.
);

CREATE TABLE religions (
    code            VARCHAR(20) PRIMARY KEY,
    name_local      VARCHAR(100) NOT NULL,
    name_en         VARCHAR(100) NOT NULL,
    category        VARCHAR(50)
);

CREATE TABLE regions (
    code            VARCHAR(10) PRIMARY KEY,
    name_local      VARCHAR(100) NOT NULL,
    name_en         VARCHAR(100) NOT NULL,
    parent_code     VARCHAR(10) REFERENCES regions(code),
    level           SMALLINT NOT NULL,        -- 1=country, 2=province, 3=district
    population_min  INTEGER,                  -- For k-anonymity enforcement
    is_active       BOOLEAN DEFAULT TRUE
);
```

### 3.4 Audit Trail (Immutable)

```sql
-- Append-only audit log — no UPDATE or DELETE allowed
-- Stored in separate database with write-only connection string

CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    event_type      VARCHAR(50) NOT NULL,
    event_time      TIMESTAMPTZ DEFAULT NOW(),
    actor_type      VARCHAR(20),             -- 'citizen'|'agent'|'admin'|'system'
    actor_hash      BYTEA,                   -- Hashed identifier, not raw
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(50),
    outcome         VARCHAR(10) NOT NULL,    -- 'success'|'failure'|'blocked'
    risk_score      NUMERIC(3,2),
    metadata        JSONB,                   -- Additional context, no PII
    signature       BYTEA NOT NULL          -- HMAC of row content
);

-- Trigger: prevent any modification
CREATE RULE no_update_audit AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE no_delete_audit AS ON DELETE TO audit_log DO INSTEAD NOTHING;
```

---

## 4. Tech Stack

### 4.1 Backend

| Component | Technology | Justification |
|-----------|-----------|---------------|
| API Framework | FastAPI (Python 3.12) | Async, type-safe, OpenAPI auto-docs |
| Auth/Identity | Custom + Keycloak | Enterprise SSO for admin |
| Message Queue | Apache Kafka | Durable, auditable event streams |
| Cache | Redis Cluster | OTP sessions, rate limiting |
| Search/Dedup | Elasticsearch + FAISS | Full-text + vector similarity |
| ZKP | snarkjs + circom | Browser-compatible ZK proofs |
| ML Models | PyTorch + ONNX Runtime | Face verification, fraud detection |
| OCR | Tesseract + PaddleOCR | Multi-language, multi-script |

### 4.2 Frontend

| Component | Technology | Justification |
|-----------|-----------|---------------|
| Framework | Next.js 15 (React) | SSR, offline support, PWA |
| UI Library | Radix UI + Tailwind | Accessible, RTL support |
| Offline Sync | Workbox + IndexedDB | Service Workers for offline |
| Camera | WebRTC + MediaDevices API | Face capture |
| Crypto | SubtleCrypto API | Client-side ZKP verification |
| i18n | next-intl | Arabic, Kurdish, Turkmen, English |
| State | Zustand + TanStack Query | Offline-first state management |

### 4.3 Infrastructure

| Component | Technology | Justification |
|-----------|-----------|---------------|
| Container | Docker + Kubernetes (K8s) | Horizontal scaling |
| Service Mesh | Istio | mTLS between services |
| API Gateway | Kong | Rate limiting, auth, routing |
| Cloud | Multi-cloud (AWS + Azure) | Redundancy, sovereignty |
| CDN | Cloudflare | DDoS protection, edge caching |
| Monitoring | Prometheus + Grafana | Real-time alerting |
| Logging | ELK Stack (Elasticsearch) | Centralized, searchable |
| Secret Mgmt | HashiCorp Vault | HSM-backed key management |
| IaC | Terraform + Helm | Reproducible infrastructure |

---

## 5. Threat Model

### 5.1 Threat Actors

| Actor | Capability | Motivation |
|-------|-----------|-----------|
| Foreign State Actor | High (nation-state tools) | Manipulate census data |
| Domestic Political Group | Medium | Inflate ethnic/religious numbers |
| Criminal Organization | High (fraud) | SIM farms, fake registrations |
| Insider Threat | High (system access) | Data exfiltration, manipulation |
| Activist/Journalist | Low-Medium | Data exposure of vulnerable groups |
| Script Kiddie | Low | Opportunistic disruption |

### 5.2 Attack Vectors & Mitigations

```
ATTACK: Mass fake registration (SIM farm / synthetic identities)
MITIGATION: 
  ✓ Face liveness detection (defeats photo reuse)
  ✓ Face deduplication (defeats same-face multiple accounts)  
  ✓ Device fingerprinting (defeats same-device attempts)
  ✓ OTP rate limiting + SMS fraud detection
  ✓ Phone number reputation scoring

ATTACK: Data breach of demographic database
MITIGATION:
  ✓ ZKP separation (demographic DB has NO identity data)
  ✓ AES-256 encryption at rest
  ✓ Column-level encryption for sensitive fields
  ✓ Database network isolated (no direct internet access)
  ✓ k-Anonymity: suppress rows where group < 100 people

ATTACK: Insider data exfiltration
MITIGATION:
  ✓ Role-based access (need-to-know only)
  ✓ All queries logged to immutable audit trail
  ✓ Database query volume monitoring (alerts on bulk reads)
  ✓ Data masking for non-privileged analysts
  ✓ Dual-control for sensitive operations

ATTACK: Field agent fraud (adding fake respondents)
MITIGATION:
  ✓ Agent quota limits (max N per day)
  ✓ Geolocation validation (agent must be in assigned region)
  ✓ Random supervisor spot-checks
  ✓ Agent attestations require cryptographic signature
  ✓ Statistical outlier detection per agent

ATTACK: DDoS during census period
MITIGATION:
  ✓ Cloudflare DDoS protection (L3/L4/L7)
  ✓ Multi-region deployment
  ✓ Rate limiting at API gateway level
  ✓ Offline mode for continued collection during outages

ATTACK: Political manipulation of aggregate results
MITIGATION:
  ✓ Cryptographic commitment to raw data before analysis
  ✓ Independent auditor access to verify counts
  ✓ Differential privacy on published statistics
  ✓ Merkle tree of all responses (tamper-evident)
```

### 5.3 Political Neutrality Controls

```
CONTROL 1: Data Minimization
  - System collects ONLY what's needed for census
  - No surveillance capability built in
  - Automatic deletion schedule enforced

CONTROL 2: Independent Oversight
  - International observer access (read-only) to aggregate stats
  - Civil society audit tokens (verify counts, not individual data)
  - Parliamentary oversight committee dashboards

CONTROL 3: Cryptographic Integrity
  - Each census response gets Merkle inclusion proof
  - Root hash published publicly after census closes
  - Anyone can verify their submission was counted

CONTROL 4: No Post-Hoc Targeting
  - ZKP design makes it cryptographically impossible to 
    find "all Christians in District X" even for administrators
  - Only aggregate statistics queryable

CONTROL 5: Sunset Provisions
  - Identity database deleted 12 months after census
  - Demographic database retained 10 years (for research)
  - All deletion events logged and verified
```

---

## 6. Offline & Low-Infrastructure Support

### 6.1 Offline Operation Mode

```
OFFLINE FLOW:
1. Field agent downloads: encrypted form templates + reference data
2. Citizen completes census on device (no internet)
3. Responses encrypted with agent's public key + device key
4. Stored in local SQLite (encrypted with AES-256)
5. When connectivity restored: sync to server
6. Deduplication runs server-side after sync
7. Conflict resolution: flag for human review

SUPPORTED ENVIRONMENTS:
✓ 2G/EDGE connectivity (data minimized, compressed)
✓ SMS-only (USSD menu flow for feature phones)
✓ Paper → Digital (QR code batch entry)
✓ Satellite internet (Starlink integration for remote areas)
```

### 6.2 Accessibility Features

```
ACCESSIBILITY:
- Screen reader support (ARIA labels in Arabic/Kurdish)
- Large text mode
- Voice navigation
- Illiteracy support: icon-based UI + audio prompts
- Languages: Arabic, Kurdish (Sorani/Kurmanji), Turkmen, 
  Syriac, Armenian, English
- RTL layout fully supported
- Low-bandwidth mode (removes images, compresses assets)
```

---

## 7. Deployment Strategy

### 7.1 Multi-Region Architecture

```
PRIMARY REGION (National Data Center):
├─ Control plane (Kubernetes masters)
├─ Identity DB (primary)
├─ Real-time processing
└─ HSM (Hardware Security Module)

SECONDARY REGION (Disaster Recovery — 300km away):
├─ Kubernetes workers (standby)
├─ Identity DB (read replica → promote on failover)
├─ Cold standby: RTO < 4 hours, RPO < 15 minutes
└─ Air-gapped backup keys

EDGE NODES (Province Level — 18 nodes):
├─ Local API cache
├─ Offline sync queues
└─ 4G/satellite connectivity

CLOUD BURST (AWS/Azure — encrypted):
├─ Overflow capacity during peak census period
├─ Aggregate analytics workloads
└─ ML model training (on anonymized data only)
```

### 7.2 Scaling Plan

```
CENSUS PERIOD LOAD ESTIMATE (Country of 40M people):
- Expected submissions: ~8M households
- Peak period: 30 days
- Target: 300,000 submissions/day peak
- Concurrent users: ~12,000

SCALING TARGETS:
- API: 10,000 req/sec (horizontal pod autoscaling)
- DB: Read replicas x5, write primary x1 + PgBouncer
- Cache: Redis Cluster (6 nodes, 3 primary + 3 replica)
- Queue: Kafka (5 brokers, 30 partitions)

AUTO-SCALING TRIGGERS:
- CPU > 70%: scale out
- API latency p95 > 2s: scale out
- Queue depth > 10,000: scale consumers
```

---

## 8. Risk Assessment Matrix

| Risk | Likelihood | Impact | Mitigation Priority |
|------|-----------|--------|---------------------|
| Mass fake registrations | HIGH | CRITICAL | P0 — In design |
| Identity data breach | MEDIUM | CRITICAL | P0 — ZKP + encryption |
| Political manipulation of results | HIGH | CRITICAL | P0 — Crypto integrity |
| System downtime during census | MEDIUM | HIGH | P1 — Multi-region |
| Field agent fraud | HIGH | HIGH | P1 — Quotas + audit |
| Low adoption in conflict zones | HIGH | MEDIUM | P1 — Offline + agents |
| Foreign state interference | MEDIUM | HIGH | P1 — Air-gap + monitoring |
| Public distrust/boycott | MEDIUM | HIGH | P2 — Transparency |
| Accidental PII exposure | LOW | HIGH | P1 — DLP controls |
| ML model bias (face recognition) | MEDIUM | MEDIUM | P1 — Model audit |

---

## 9. Future Improvements

1. **Blockchain Audit Trail**: Move from PostgreSQL audit to permissioned blockchain (Hyperledger Fabric) for multi-party verification
2. **Homomorphic Encryption**: Enable computation on encrypted demographic data without decryption
3. **Federated Learning**: Train fraud detection ML models across edge nodes without centralizing raw data
4. **Self-Sovereign Identity**: W3C DID/Verifiable Credentials for citizen-owned identity
5. **Continuous Census**: Replace periodic census with privacy-preserving longitudinal tracking
6. **AI-Powered Field Support**: Real-time guidance for field agents via LLM assistant (local model, no internet required)
