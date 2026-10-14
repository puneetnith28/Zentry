from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Final


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ModuleScanStatus(str, Enum):
    SUCCESS = "success"
    ERROR = "error"


CANONICAL_TITLES: Final[dict[str, str]] = {
    # Headers
    "MISSING_HSTS": "Missing Strict-Transport-Security (HSTS)",
    "HSTS_SHORT_MAX_AGE": "Short HSTS Max-Age Duration",
    "HSTS_MISSING_SUBDOMAINS": "HSTS Missing includeSubDomains Directive",
    "HSTS_DISABLED": "HSTS Explicitly Disabled",
    "MISSING_CSP": "Missing Content-Security-Policy (CSP)",
    "CSP_UNSAFE_INLINE": "CSP Contains 'unsafe-inline' Directive",
    "CSP_UNSAFE_EVAL": "CSP Contains 'unsafe-eval' Directive",
    "CSP_WILDCARD_SOURCE": "CSP Allows Wildcard Source",
    "MISSING_X_CONTENT_TYPE_OPTIONS": "Missing X-Content-Type-Options Header",
    "INVALID_X_CONTENT_TYPE_OPTIONS": "Invalid X-Content-Type-Options Directive",
    "MISSING_X_FRAME_OPTIONS": "Missing X-Frame-Options Header",
    "WEAK_X_FRAME_OPTIONS": "Weak or Deprecated X-Frame-Options Directive",
    "COOKIE_MISSING_SECURE": "Cookie Missing Secure Attribute",
    "COOKIE_MISSING_HTTPONLY": "Cookie Missing HttpOnly Attribute",
    "COOKIE_MISSING_SAMESITE": "Cookie Missing SameSite Attribute",
    "COOKIE_SAMESITE_NONE_INSECURE": "Cookie SameSite=None Without Secure Flag",
    "COOKIE_HOST_PREFIX_INVALID": "Cookie __Host- Prefix Misconfiguration",
    "COOKIE_SECURE_PREFIX_INVALID": "Cookie __Secure- Prefix Misconfiguration",
    # Ports
    "PORT_OPEN": "Exposed Network Port",
    "FTP_OPEN": "Open FTP Service (Port 21)",
    "TELNET_OPEN": "Open Telnet Service (Port 23)",
    "SMB_OPEN": "Open SMB Service (Port 445)",
    "RDP_OPEN": "Open RDP Service (Port 3389)",
    "REDIS_OPEN": "Open Redis Service (Port 6379)",
    "MYSQL_OPEN": "Open MySQL Service (Port 3306)",
    "POSTGRES_OPEN": "Open PostgreSQL Service (Port 5432)",
    "NO_HTTPS_PORT": "Port 80 Open Without HTTPS Port 443",
    # SSL / TLS
    "CERT_EXPIRED": "Expired TLS Certificate",
    "CHAIN_CERT_EXPIRED": "Expired Intermediate TLS Certificate",
    "CERT_NOT_YET_VALID": "TLS Certificate Not Yet Valid",
    "CERT_EXPIRING_SOON": "TLS Certificate Expiring Soon",
    "CERT_HOSTNAME_MISMATCH": "TLS Certificate Hostname Mismatch",
    "SELF_SIGNED_CERT": "Self-Signed TLS Certificate",
    "DEPRECATED_TLS_VERSION": "Deprecated TLS Protocol Version Supported",
    "WEAK_CIPHER_SUITE": "Weak or Deprecated Cipher Suite Supported",
    "SHORT_RSA_KEY": "Short RSA Key Length (< 2048 bits)",
    "SHA1_SIGNATURE": "Deprecated SHA-1 Signature Algorithm",
    "INSECURE_PORT_80": "Unencrypted HTTP Port 80 Open",
    # Technology
    "TECHNOLOGY_DISCLOSURE": "Software Version Disclosed via Headers",
    "CMS_DETECTED": "Content Management System (CMS) Detected",
    "LARGE_TECH_STACK": "Large Technology Stack Detected",
    # Subdomains
    "NO_SUBDOMAINS_DISCOVERED": "No Subdomains Discovered",
    "SUBDOMAINS_DISCOVERED": "Subdomains Discovered",
    "LARGE_ATTACK_SURFACE": "Large Attack Surface Discovered",
}

CANONICAL_REMEDIATIONS: Final[dict[str, str]] = {
    # Headers
    "MISSING_HSTS": "Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' on all HTTPS responses.",
    "HSTS_SHORT_MAX_AGE": "Increase HSTS max-age to at least 15552000 seconds (180 days), preferably 31536000 seconds (1 year).",
    "HSTS_MISSING_SUBDOMAINS": "Add 'includeSubDomains' to the HSTS header to ensure all subdomains inherit TLS protection.",
    "HSTS_DISABLED": "Remove 'max-age=0' and set a positive HSTS duration to re-enable connection security.",
    "MISSING_CSP": "Implement a robust Content-Security-Policy header restricting script, object, and style sources.",
    "CSP_UNSAFE_INLINE": "Remove 'unsafe-inline' from script-src and use nonces or cryptographic hashes instead.",
    "CSP_UNSAFE_EVAL": "Remove 'unsafe-eval' from script-src and avoid dynamic code evaluation.",
    "CSP_WILDCARD_SOURCE": "Replace wildcard '*' sources in CSP directives with explicit trusted hostnames.",
    "MISSING_X_CONTENT_TYPE_OPTIONS": "Configure 'X-Content-Type-Options: nosniff' to prevent MIME-confusion attacks.",
    "INVALID_X_CONTENT_TYPE_OPTIONS": "Set 'X-Content-Type-Options' to 'nosniff'.",
    "MISSING_X_FRAME_OPTIONS": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to protect against clickjacking.",
    "WEAK_X_FRAME_OPTIONS": "Use 'DENY' or 'SAMEORIGIN' for X-Frame-Options, or migrate to CSP frame-ancestors directive.",
    "COOKIE_MISSING_SECURE": "Add the 'Secure' attribute to sensitive cookies to ensure transmission over HTTPS only.",
    "COOKIE_MISSING_HTTPONLY": "Add the 'HttpOnly' attribute to prevent cookie theft via Cross-Site Scripting (XSS).",
    "COOKIE_MISSING_SAMESITE": "Set SameSite=Lax or SameSite=Strict to mitigate Cross-Site Request Forgery (CSRF).",
    "COOKIE_SAMESITE_NONE_INSECURE": "When SameSite=None is specified, the Secure flag must also be enabled.",
    "COOKIE_HOST_PREFIX_INVALID": "Ensure cookies with '__Host-' prefix have Secure, Path=/, and omit the Domain attribute.",
    "COOKIE_SECURE_PREFIX_INVALID": "Ensure cookies with '__Secure-' prefix have the Secure attribute enabled.",
    # Ports
    "PORT_OPEN": "Review network service necessity and restrict access using network firewalls or localhost binding.",
    "FTP_OPEN": "Disable unencrypted FTP service on port 21/tcp or restrict access to private networks.",
    "TELNET_OPEN": "Disable unencrypted Telnet on port 23/tcp and migrate to SSH.",
    "SMB_OPEN": "Block external exposure of port 445/tcp using network firewalls.",
    "RDP_OPEN": "Place RDP port 3389/tcp behind a VPN or bastion host with multi-factor authentication.",
    "REDIS_OPEN": "Bind Redis to 127.0.0.1 or a private VPC network, and require strong authentication.",
    "MYSQL_OPEN": "Restrict MySQL port 3306/tcp to internal application servers using firewall rules.",
    "POSTGRES_OPEN": "Restrict PostgreSQL port 5432/tcp to internal application servers using firewall rules.",
    "NO_HTTPS_PORT": "Enable HTTPS on port 443 with a valid TLS certificate and redirect port 80 traffic to HTTPS.",
    # SSL / TLS
    "CERT_EXPIRED": "Renew and install an active TLS certificate immediately.",
    "CHAIN_CERT_EXPIRED": "Update the intermediate CA certificate bundle on your web server.",
    "CERT_NOT_YET_VALID": "Ensure server system clocks are synchronized and certificate activation date has passed.",
    "CERT_EXPIRING_SOON": "Plan certificate renewal prior to expiration to prevent service interruption.",
    "CERT_HOSTNAME_MISMATCH": "Configure a certificate that covers this hostname in Subject Alternative Names (SAN).",
    "SELF_SIGNED_CERT": "Replace self-signed certificate with one issued by a trusted public Certificate Authority.",
    "DEPRECATED_TLS_VERSION": "Disable TLS 1.0 and TLS 1.1; enforce TLS 1.2 and TLS 1.3.",
    "WEAK_CIPHER_SUITE": "Disable weak ciphers (RC4, 3DES, DES, export, CBC) and configure modern AEAD ciphers.",
    "SHORT_RSA_KEY": "Upgrade RSA key length to at least 2048 bits or migrate to ECDSA (P-256/P-384).",
    "SHA1_SIGNATURE": "Reissue certificate using SHA-256 or stronger signature algorithm.",
    "INSECURE_PORT_80": "Redirect unencrypted HTTP requests to HTTPS.",
    # Technology
    "TECHNOLOGY_DISCLOSURE": "Configure web server to suppress banner versions and software disclosure headers.",
    "CMS_DETECTED": "Keep CMS core, plugins, and themes updated to their latest security releases.",
    "LARGE_TECH_STACK": "Audit and minimize exposed components, removing unused plugins and frameworks.",
    # Subdomains
    "NO_SUBDOMAINS_DISCOVERED": "Periodic passive monitoring recommended to detect unexpected infrastructure exposure.",
    "SUBDOMAINS_DISCOVERED": "Audit discovered subdomains to ensure deprecated or unmonitored assets are decommissioned.",
    "LARGE_ATTACK_SURFACE": "Implement an attack surface management routine to track and secure all active subdomains.",
}


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    severity: FindingSeverity
    message: str
    title: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    fingerprint: str = ""
    confidence: int = 100
    module: str = ""

    def __post_init__(self) -> None:
        if not self.title:
            object.__setattr__(
                self,
                "title",
                CANONICAL_TITLES.get(self.code, self.code.replace("_", " ").title()),
            )
        if not self.description:
            object.__setattr__(self, "description", self.message)
        if not self.evidence:
            object.__setattr__(self, "evidence", self.message)
        elif len(self.evidence) > 4096:
            object.__setattr__(self, "evidence", self.evidence[:4080] + "... [truncated]")
        if not self.remediation:
            object.__setattr__(
                self,
                "remediation",
                CANONICAL_REMEDIATIONS.get(
                    self.code,
                    "Review component configuration according to security best practices.",
                ),
            )
        if not self.fingerprint:
            raw = f"{self.module}:{self.code}:{self.evidence or self.message}"
            fp = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
            object.__setattr__(self, "fingerprint", fp)


@dataclass(frozen=True, slots=True)
class ModuleScanError:
    code: str
    message: str


def serialize(obj: Any) -> Any:
    """Recursively converts dataclasses, enums, and native types into a JSON-friendly format."""
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {k: serialize(v) for k, v in asdict(obj).items()}
    if isinstance(obj, list):
        return [serialize(item) for item in obj]
    if isinstance(obj, dict):
        return {k: serialize(v) for k, v in obj.items()}
    return obj


SCORE_VERSION: Final[str] = "v1.0"

SEVERITY_WEIGHTS: Final[dict[str, int]] = {
    FindingSeverity.CRITICAL.value: 25,
    FindingSeverity.HIGH.value: 15,
    FindingSeverity.MEDIUM.value: 8,
    FindingSeverity.LOW.value: 3,
    FindingSeverity.INFO.value: 1,
}


@dataclass(frozen=True, slots=True)
class RiskScoreResult:
    score: int
    level: str
    version: str = SCORE_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "version": self.version,
        }


def calculate_risk_score(summary: dict[str, int] | Any) -> RiskScoreResult:
    """Calculate deterministic canonical risk score (0-100) and risk tier based on findings summary."""
    if hasattr(summary, "model_dump"):
        counts = summary.model_dump()
    elif hasattr(summary, "__dict__"):
        counts = summary.__dict__
    elif isinstance(summary, dict):
        counts = summary
    else:
        counts = {}

    raw: float = 0.0
    for sev, weight in SEVERITY_WEIGHTS.items():
        count_val = counts.get(sev, 0)
        if isinstance(count_val, (int, float)):
            raw += float(count_val * weight)


    score = min(100, max(0, int(round(raw))))
    if score >= 75:
        level = "Critical Risk"
    elif score >= 50:
        level = "High Risk"
    elif score >= 25:
        level = "Moderate Risk"
    elif score > 0:
        level = "Low Risk"
    else:
        level = "Minimal Risk"

    return RiskScoreResult(score=score, level=level, version=SCORE_VERSION)


def summarize_findings(modules: dict[str, Any]) -> dict[str, int]:
    """Tally up the total number of findings across all scan modules by severity level."""
    counts = {s.value: 0 for s in FindingSeverity}
    for module_data in modules.values():
        if not isinstance(module_data, dict):
            continue
        for finding in module_data.get("findings", []):
            if not isinstance(finding, dict):
                continue
            sev = finding.get("severity", "info")
            if sev in counts:
                counts[sev] += 1
    return counts


def extract_module_statuses(modules: dict[str, Any]) -> dict[str, str]:
    """Map each module name to its standardized execution status: 'SUCCESS', 'ERROR', 'BLOCKED', 'TIMEOUT'."""
    statuses: dict[str, str] = {}
    for name, data in modules.items():
        if not isinstance(data, dict):
            statuses[name] = "ERROR"
            continue
        mod_status = str(data.get("status", "")).lower()
        if mod_status == "success":
            statuses[name] = "SUCCESS"
        else:
            err = data.get("error") or {}
            err_code = str(err.get("code", "")).upper() if isinstance(err, dict) else ""
            if "TIMEOUT" in err_code:
                statuses[name] = "TIMEOUT"
            elif "PROHIBITED" in err_code or "BLOCKED" in err_code:
                statuses[name] = "BLOCKED"
            else:
                statuses[name] = "ERROR"
    return statuses
