# Zentry

**Zentry** is an automated, high-performance security posture scanner designed to evaluate web applications, exposed infrastructure, and attack surfaces. Built for security engineers, DevOps teams, and web administrators, Zentry delivers comprehensive defensive assessments by analyzing cryptographic configurations, HTTP security headers, open network ports, technology stacks, and passive domain footprints.

Rather than relying on invasive fuzzing or destructive exploits, Zentry emphasizes **non-intrusive, passive-first security inspection**, producing actionable intelligence, weighted risk scoring, and publication-ready executive PDF reports.

---

## Key Capabilities

### 1. SSL/TLS & Cryptographic Posture Analysis
- **X.509 Certificate Chain Inspection:** Validates certificate validity dates, subject alternative names (SANs), issuer authorities, and intermediate chains directly via native cryptographic primitives.
- **Proactive Expiration Monitoring:** Alerts on expiring certificates within a 30-day threshold to prevent service outages.
- **Key Strength & Algorithm Audits:** Assesses public key bit lengths (flagging RSA < 2048-bit and EC < 256-bit) and flags weak signature algorithms such as MD5 and SHA-1.
- **Protocol & Cipher Suite Audits:** Detects obsolete protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1) and warns against weak or legacy cipher configurations.

### 2. HTTP Security Headers & Cookie Integrity
- **Defensive Header Evaluation:** Inspects HTTP responses against modern web security standards, assessing policies including:
  - `Strict-Transport-Security` (HSTS): Evaluates `max-age`, `includeSubDomains`, and preload readiness.
  - `Content-Security-Policy` (CSP): Identifies missing or insecure policies susceptible to Cross-Site Scripting (XSS).
  - `X-Frame-Options`: Detects clickjacking vulnerabilities.
  - `X-Content-Type-Options`: Verifies MIME-type sniffing defenses (`nosniff`).
  - `Referrer-Policy`: Ensures sensitive URL paths are not leaked to external origins.
  - `Permissions-Policy`: Audits browser feature restrictions (camera, geolocation, microphones).
- **Session Cookie Hygiene:** Audits cookie security flags, detecting missing `Secure`, `HttpOnly`, and `SameSite` (`Strict`/`Lax`) directives.
- **Information Disclosure Detection:** Scans for server version banners and framework identifiers exposed via `Server` and `X-Powered-By` headers.

### 3. Network Attack Surface & Port Auditing
- **Asynchronous TCP Scanning:** Executes non-blocking TCP connect probing across standard and custom service ports.
- **Critical Service Exposure Alerts:** Identifies publicly exposed administrative and database ports that should never be reachable from the public internet, including:
  - Database engines: PostgreSQL (`5432`), MySQL (`3306`), Redis (`6379`)
  - Remote administration protocols: RDP (`3389`), Telnet (`23`), FTP (`21`), SMB (`445`)
- **Port State Categorization:** Accurately classifies surveyed ports as open, closed, or filtered.

### 4. Passive Technology Fingerprinting
- **Multi-Vector Signature Matching:** Combines header analysis and DOM inspection to detect frameworks, libraries, and server runtimes without active payload execution.
- **Broad Component Coverage:** Identifies:
  - Web servers & reverse proxies (Nginx, Apache, Cloudflare, Caddy, IIS)
  - Application frameworks (Django, FastAPI, Express, Spring, Rails, Next.js, Laravel)
  - Content Management Systems (WordPress, Drupal, Joomla, Ghost)
  - Client-side libraries & utilities (React, Vue, jQuery, Tailwind CSS, Bootstrap)
- **Attack Surface Minimization:** Flags legacy versions and large dependency footprints that expand potential vulnerability surfaces.

### 5. Passive Subdomain Discovery
- **Certificate Transparency (CT) Log Interrogation:** Queries public Certificate Transparency logs (via `crt.sh`) to uncover valid organizational subdomains.
- **Zero DNS Fingerprint:** Discovers related hostnames and environments without generating noisy DNS brute-force queries or alerting target intrusion detection systems.

---

## Architecture & System Design

Zentry is architected as an asynchronous, distributed scanning system capable of handling concurrent multi-target evaluations:

```
┌─────────────────────────────────────────────────────────────┐
│                       Zentry Web UI                         │
│             (React 19 + TypeScript + Tailwind CSS)           │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / REST
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                      FastAPI Gateway                        │
│          SSRF Validation • API Keys • Job Creation          │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼ DB State                     ▼ Dispatch Job
      ┌─────────────────┐            ┌─────────────────┐
      │   PostgreSQL    │            │  Redis Broker   │
      │   (SQLAlchemy)  │            └────────┬────────┘
      └─────────────────┘                     │
                                              ▼
                                     ┌─────────────────┐
                                     │  Celery Worker  │
                                     │ (asyncio tasks) │
                                     └────────┬────────┘
                                              │
                      ┌───────────────────────┴───────────────────────┐
                      ▼                       ▼                       ▼
               SSL / TLS Engine       HTTP Headers & Cookies     Port Scanner
                      ▼                       ▼                       ▼
              Tech Fingerprint        Passive Subdomains       PDF Generator
```

### Core Architecture Components

- **API Gateway (FastAPI):** High-throughput REST API managing scan lifecycles, target normalization, SSRF defenses, and authentication.
- **Distributed Task Queue (Celery + Redis):** Offloads long-running network operations to independent worker processes, ensuring non-blocking user interactions and linear horizontal scaling.
- **Concurrent Module Execution:** Worker tasks leverage Python's `asyncio` runtime to execute enabled scanning engines in parallel, minimizing total scan durations.
- **Relational Persistence (PostgreSQL):** Stores scan metadata, execution options, serialized finding payloads, and historical trends managed through declarative SQLAlchemy models and Alembic schema migrations.
- **Reporting Engine (WeasyPrint & Jinja2):** Compiles scan findings into structured, styled HTML documents and renders pixel-perfect PDF executive reports with zero external browser dependencies.
- **User Interface (React 19):** Modern, responsive interface featuring real-time polling with TanStack Query, interactive scan configuration, metric dashboards, and accessible dark-mode UI primitives.

---

## Risk Scoring Methodology

Zentry applies a deterministic, weighted scoring algorithm to evaluate overall target security risk on a scale from **0 to 100**:

$$\text{Raw Score} = \sum (\text{Count}_{\text{severity}} \times \text{Weight}_{\text{severity}})$$

$$\text{Risk Score} = \min(100, \text{Raw Score})$$

### Severity Weights

| Severity Level | Weight | Description |
|---|:---:|---|
| **Critical** | `25` | Immediate vulnerabilities requiring urgent remediation (e.g., exposed databases, Telnet, unauthenticated RDP). |
| **High** | `15` | Major security deficiencies (e.g., missing HSTS, expired TLS certificates, exposed Redis). |
| **Medium** | `8` | Notable configuration weaknesses (e.g., missing CSP, open FTP, clickjacking risks). |
| **Low** | `3` | Best-practice deviations (e.g., missing `X-Content-Type-Options`, missing Referrer Policy). |
| **Info** | `1` | Informational hardening observations (e.g., technology disclosures, feature policies). |

### Risk Classification Tiers

- **Critical Risk (75–100):** Severe exposures detected; immediate intervention required prior to production exposure.
- **High Risk (50–74):** Significant security gaps present; prioritize during the next hardening cycle.
- **Moderate Risk (25–49):** Baseline defenses intact, but configuration deficiencies require planned remediation.
- **Low Risk (1–24):** Strong overall posture; minor defensive hardening recommended.
- **Minimal Risk (0):** No adverse findings detected across all executed modules.

---

## Defensive Safeguards & Operational Security

Zentry enforces strict operational safeguards to protect both scanning infrastructure and target environments:

1. **SSRF (Server-Side Request Forgery) Mitigation:**
   - Every submitted target is parsed and validated prior to database insertion.
   - Hostnames are resolved against DNS to verify that underlying IPs do not reside within private, loopback, or link-local address spaces (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10`).
   - Internal scanning requests targeting infrastructure services (e.g., AWS metadata endpoint `169.254.169.254`, internal databases, local microservices) are rejected at the gateway.

2. **Non-Intrusive Scanning Only:**
   - No vulnerability exploitation, fuzzing payloads, brute-force dictionary attacks, or denial-of-service tests are performed.
   - Operations consist strictly of standard protocol handshakes, HTTP metadata retrieval, and passive log querying.

3. **Authentication & Multi-Tenant User Isolation:**
   - Secure user authentication powered by stateless JSON Web Tokens (JWT) signed with SHA-256 (`HS256`) and hashed passwords using `bcrypt`.
   - Complete multi-tenant data isolation: all scans, findings, and reports are strictly partitioned by authenticated user ID with role-based administrative access controls.
   - Backward-compatible support for legacy system API keys (`X-API-Key`).

4. **Network & Outbound Gateway Hardening:**
   - Centralized safe outbound networking (`SafeStreamReader`) enforcing DNS-rebinding protection, private IP blocking, connection timeouts, and hard byte streaming limits (default 5 MB).
   - Trusted reverse proxy validation ensuring client IP addresses are extracted securely from `X-Forwarded-For` without spoofing vulnerabilities.
   - Strict sliding-window rate limiting on authentication and scan submission endpoints.

5. **Operational Resilience & Resource Governance:**
   - Dedicated Celery worker concurrency limits, task prefetch controls, and child process recycling.
   - Database connection pooling with connect timeouts and automatic socket recycling.
   - Fail-fast production configuration validator preventing insecure defaults.
   - Fully isolated containerized network architecture running with a non-root system user.