# Safe Operating Rules and Scanning Boundaries

## 1. Purpose and Philosophy

Zentry is built exclusively for defensive security posture assessments, vulnerability visibility, and attack surface reduction. It operates on a **passive-first, non-intrusive** inspection model. It is designed to empower administrators and security practitioners with visibility into their own environments without degrading target availability, attempting intrusive exploitation, or generating hostile network traffic.

---

## 2. Target Authorization Requirements

1. **Explicit Permission Required:** Users may only initiate scans against domains, hostnames, IP addresses, or infrastructure that they **own**, **operate**, or have received **explicit written legal authorization** to inspect.
2. **Prohibited Targets:**
   - Public critical infrastructure, utilities, healthcare systems, or government domains without documented authority.
   - Third-party SaaS, shared hosting environments, or tenant instances without organizational scope approval.
   - Internal network infrastructure, cloud provider metadata endpoints (`169.254.169.254`), or private address ranges (`RFC 1918`).
3. **SSRF Guard Enforcement:** All target inputs are rigorously validated at the API boundary to block private IP spaces and loopback addresses. Attempts to circumvent target normalization or DNS resolution controls are logged and denied.

---

## 3. Operational Scanning Boundaries

Zentry scanning engines strictly observe the following technical constraints:

| Category | Permitted Operational Boundary | Prohibited Actions |
|---|---|---|
| **TLS/SSL Inspection** | Handshake negotiation, certificate chain inspection, cipher enumeration, expiration validation. | Exploitation of cryptographic defects, active MITM interception, key cracking. |
| **HTTP Headers** | Standard non-intrusive HTTP GET/HEAD requests, response header parsing, cookie flag auditing. | Payload fuzzing, SQL injection probes, XSS injection payloads, directory traversal attacks. |
| **Network Ports** | Non-blocking TCP connect probing against configured standard ports. | SYN-floods, packet crafting, connection exhaustion attacks, UDP port flooding. |
| **Technology Fingerprinting** | Passive HTML DOM parsing, meta tags, script source inspection, response header fingerprints. | Exploiting discovered software vulnerabilities, automated exploit kit deployment. |
| **Subdomain Discovery** | Querying public Certificate Transparency (CT) logs and passive certificate records. | Brute-force DNS queries, dictionary attacks, zone transfer attacks without permission. |

---

## 4. Rate Limiting and Service Impact Controls

To prevent accidental denial-of-service (DoS) or performance degradation on target infrastructure:
- **Connection Deadlines:** All outbound socket connections and HTTP requests enforce strict timeouts (default 5–10s).
- **Streaming Byte Bounds:** External response bodies are capped by `SafeStreamReader` at 5 MB to prevent memory exhaustion attacks.
- **Worker Concurrency Bounds:** Outbound requests are rate-limited and throttled per domain to prevent burst saturation.

---

## 5. Disclaimer of Liability

Zentry is distributed in good faith as a security assessment tool. The creators, contributors, and maintainers accept no liability for misuse, unauthorized scanning, disruption of service, or legal consequences resulting from actions conducted by users of this software.
