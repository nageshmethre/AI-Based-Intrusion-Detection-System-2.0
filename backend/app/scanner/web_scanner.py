"""Web Application Attack Scanner & Defensive Security Posture Inspector.

Performs defensive web application auditing, security header analysis,
sensitive file exposure checks, and WAF / attack vector resistance tests.
"""

import time
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional
import requests

SENSITIVE_PATHS = [
    {"path": "/.env", "name": "Environment Config File", "severity": "CRITICAL", "desc": "Contains secrets, database credentials, and API keys."},
    {"path": "/.git/HEAD", "name": "Git Repository Metadata", "severity": "CRITICAL", "desc": "Exposes full internal repository and source code."},
    {"path": "/config.json", "name": "Application Configuration", "severity": "HIGH", "desc": "May leak internal database connection strings or settings."},
    {"path": "/wp-config.php", "name": "WordPress Config", "severity": "CRITICAL", "desc": "Exposes database passwords and auth salt keys."},
    {"path": "/backup.sql", "name": "Database Backup File", "severity": "CRITICAL", "desc": "Full database dump publicly accessible."},
    {"path": "/phpinfo.php", "name": "PHP Diagnostic Info", "severity": "HIGH", "desc": "Reveals complete PHP runtime environment and server paths."},
    {"path": "/admin/", "name": "Administrative Interface", "severity": "LOW", "desc": "Exposed admin login gateway discovered."},
    {"path": "/robots.txt", "name": "Robots Exclusion File", "severity": "INFO", "desc": "Inspect disallowed directories for sensitive endpoints."}
]

SECURITY_HEADERS = [
    {
        "header": "Content-Security-Policy",
        "name": "Content Security Policy (CSP)",
        "severity": "HIGH",
        "desc": "Mitigates Cross-Site Scripting (XSS) and data injection attacks by restricting sources of executable scripts.",
        "remediation": "Add 'Content-Security-Policy: default-src \\'self\\'; script-src \\'self\\';' header."
    },
    {
        "header": "Strict-Transport-Security",
        "name": "HTTP Strict Transport Security (HSTS)",
        "severity": "HIGH",
        "desc": "Enforces secure HTTPS connections and prevents SSL-stripping man-in-the-middle attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
    },
    {
        "header": "X-Frame-Options",
        "name": "Anti-Clickjacking (X-Frame-Options)",
        "severity": "MEDIUM",
        "desc": "Prevents the website from being rendered inside an invisible iframe by malicious third-party sites.",
        "remediation": "Configure 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
    },
    {
        "header": "X-Content-Type-Options",
        "name": "MIME Sniffing Prevention",
        "severity": "LOW",
        "desc": "Instructs browsers to strictly honor the declared Content-Type header and not sniff MIME types.",
        "remediation": "Configure 'X-Content-Type-Options: nosniff'."
    },
    {
        "header": "Referrer-Policy",
        "name": "Referrer Leak Protection",
        "severity": "LOW",
        "desc": "Controls how much referrer information (paths, query parameters) is included with outgoing requests.",
        "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin'."
    },
    {
        "header": "Permissions-Policy",
        "name": "Browser Feature Permissions Policy",
        "severity": "LOW",
        "desc": "Restricts browser access to hardware APIs such as camera, microphone, and geolocation.",
        "remediation": "Set 'Permissions-Policy: camera=(), microphone=(), geolocation=()'."
    }
]

ATTACK_VECTOR_PAYLOADS = [
    {
        "type": "SQL_INJECTION",
        "name": "SQL Injection (SQLi) Probe",
        "payload": "' OR '1'='1' --",
        "category": "Injection Attack",
        "severity": "CRITICAL"
    },
    {
        "type": "XSS",
        "name": "Cross-Site Scripting (XSS) Probe",
        "payload": "<script>alert('SOC_TEST')</script>",
        "category": "Client-Side Injection",
        "severity": "HIGH"
    },
    {
        "type": "PATH_TRAVERSAL",
        "name": "Directory Path Traversal Probe",
        "payload": "../../../../etc/passwd",
        "category": "Arbitrary File Disclosure",
        "severity": "CRITICAL"
    },
    {
        "type": "COMMAND_INJECTION",
        "name": "OS Command Injection Probe",
        "payload": "; echo CYBERSOC_TEST_CMD ;",
        "category": "Remote Code Execution",
        "severity": "CRITICAL"
    }
]


def audit_website(target_url: str, check_exposures: bool = True, test_waf: bool = True) -> Dict[str, Any]:
    """Execute a comprehensive web security & attack posture audit on a target URL."""
    start_time = time.time()
    
    # Normalize URL
    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    is_https = parsed.scheme.lower() == "https"

    findings = []
    headers_analyzed = {}
    exposure_results = []
    attack_test_results = []
    server_info = {
        "target_url": target_url,
        "base_url": base_url,
        "host": parsed.netloc,
        "is_https": is_https,
        "status_code": None,
        "response_time_ms": None,
        "server_banner": "Unknown",
        "powered_by": "None",
        "cookies_analyzed": 0
    }

    session = requests.Session()
    session.headers.update({
        "User-Agent": "CyberSOC-WebAttackScanner/2.0 (Security Audit; https://cybersoc.local)"
    })

    # --- Phase 1: Baseline Request & Server Fingerprint ---
    try:
        t0 = time.time()
        resp = session.get(target_url, timeout=5, allow_redirects=True, verify=False)
        latency = round((time.time() - t0) * 1000, 2)
        
        server_info["status_code"] = resp.status_code
        server_info["response_time_ms"] = latency
        server_info["final_url"] = resp.url
        
        # Check banners
        server_hdr = resp.headers.get("Server")
        if server_hdr:
            server_info["server_banner"] = server_hdr
            if re.search(r"\d+\.\d+", server_hdr):
                findings.append({
                    "id": "SERVER_VERSION_LEAK",
                    "title": f"Server Banner Leaks Exact Version ({server_hdr})",
                    "severity": "LOW",
                    "category": "Information Disclosure",
                    "description": f"The web server exposes detailed software version string '{server_hdr}'. Attackers use this to identify known CVEs.",
                    "evidence": f"Server: {server_hdr}",
                    "remediation": "Disable detailed server tokens in server configuration (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx)."
                })

        powered_hdr = resp.headers.get("X-Powered-By")
        if powered_hdr:
            server_info["powered_by"] = powered_hdr
            findings.append({
                "id": "X_POWERED_BY_LEAK",
                "title": f"Technology Stack Disclosure via X-Powered-By ({powered_hdr})",
                "severity": "LOW",
                "category": "Information Disclosure",
                "description": f"The response header discloses backend framework '{powered_hdr}'.",
                "evidence": f"X-Powered-By: {powered_hdr}",
                "remediation": "Remove the 'X-Powered-By' header in backend application middleware."
            })

        # --- Phase 2: Security Headers Audit ---
        for sec in SECURITY_HEADERS:
            hdr_name = sec["header"]
            val = resp.headers.get(hdr_name)
            if val:
                headers_analyzed[hdr_name] = {
                    "status": "PRESENT",
                    "value": val,
                    "name": sec["name"]
                }
            else:
                # If site is HTTP and testing HSTS, skip or mark appropriately
                if hdr_name == "Strict-Transport-Security" and not is_https:
                    headers_analyzed[hdr_name] = {
                        "status": "NOT_APPLICABLE",
                        "value": None,
                        "name": sec["name"]
                    }
                    continue

                headers_analyzed[hdr_name] = {
                    "status": "MISSING",
                    "value": None,
                    "name": sec["name"]
                }
                findings.append({
                    "id": f"MISSING_{hdr_name.replace('-', '_').upper()}",
                    "title": f"Missing Security Header: {sec['name']}",
                    "severity": sec["severity"],
                    "category": "Security Misconfiguration",
                    "description": sec["desc"],
                    "evidence": f"{hdr_name} header not returned by server.",
                    "remediation": sec["remediation"]
                })

        # Check HTTPS
        if not is_https:
            findings.append({
                "id": "INSECURE_HTTP_TRANSPORT",
                "title": "Cleartext HTTP Transport in Use",
                "severity": "HIGH",
                "category": "Cryptographic Failures",
                "description": "The target website is operating over unencrypted HTTP. All data, credentials, and cookies are transmitted in cleartext.",
                "evidence": f"Protocol: {parsed.scheme.upper()}://",
                "remediation": "Deploy a valid TLS/SSL certificate and configure 301 redirection to HTTPS."
            })

        # Cookie security
        cookies = resp.cookies
        server_info["cookies_analyzed"] = len(cookies)
        for cookie in cookies:
            cookie_issues = []
            if not cookie.secure and is_https:
                cookie_issues.append("Missing 'Secure' flag")
            if not cookie.has_nonstandard_attr("HttpOnly") and not getattr(cookie, "httponly", False):
                cookie_issues.append("Missing 'HttpOnly' flag")
            if cookie_issues:
                findings.append({
                    "id": f"INSECURE_COOKIE_{cookie.name}",
                    "title": f"Insecure Cookie Flags on '{cookie.name}'",
                    "severity": "MEDIUM",
                    "category": "Session Management",
                    "description": f"Cookie '{cookie.name}' is missing security flags: {', '.join(cookie_issues)}.",
                    "evidence": f"Cookie: {cookie.name}={cookie.value[:10]}...",
                    "remediation": "Set 'Secure' and 'HttpOnly' flags on all session and sensitive cookies."
                })

    except Exception as e:
        return {
            "target_url": target_url,
            "status": "FAILED",
            "error": f"Failed to connect to target website: {str(e)}",
            "findings": [],
            "overall_score": 0,
            "grade": "N/A"
        }

    # --- Phase 3: Dangerous Path & Sensitive File Exposure Check ---
    if check_exposures:
        for path_entry in SENSITIVE_PATHS:
            test_path = path_entry["path"]
            check_url = urljoin(base_url, test_path)
            try:
                head_resp = session.get(check_url, timeout=3, allow_redirects=False, verify=False)
                # Check if it returned 200 OK with actual content
                is_exposed = head_resp.status_code == 200 and len(head_resp.content) > 10
                
                exposure_results.append({
                    "path": test_path,
                    "tested_url": check_url,
                    "status_code": head_resp.status_code,
                    "exposed": is_exposed,
                    "name": path_entry["name"]
                })

                if is_exposed:
                    findings.append({
                        "id": f"EXPOSED_PATH_{test_path.replace('/', '_').replace('.', '_')}",
                        "title": f"Exposed Sensitive Resource: {path_entry['name']} ({test_path})",
                        "severity": path_entry["severity"],
                        "category": "Security Exposure",
                        "description": f"The file '{test_path}' returned HTTP 200 OK without authentication. {path_entry['desc']}",
                        "evidence": f"HTTP {head_resp.status_code} at {check_url} ({len(head_resp.content)} bytes)",
                        "remediation": f"Block public access to '{test_path}' via web server configuration or move files outside document root."
                    })
            except Exception:
                exposure_results.append({
                    "path": test_path,
                    "tested_url": check_url,
                    "status_code": 0,
                    "exposed": False,
                    "name": path_entry["name"]
                })

    # --- Phase 4: Web Attack Vector & WAF Defense Audit ---
    if test_waf:
        for atk in ATTACK_VECTOR_PAYLOADS:
            test_url = f"{target_url}{'&' if '?' in target_url else '?'}sec_probe={requests.utils.quote(atk['payload'])}"
            try:
                atk_resp = session.get(test_url, timeout=3, verify=False)
                # Check status: if 403 / 400 / 406, WAF is actively dropping or filtering the request!
                is_blocked_by_waf = atk_resp.status_code in [400, 403, 406, 429]
                reflected = atk["payload"] in atk_resp.text if atk["type"] == "XSS" else False

                attack_test_results.append({
                    "attack_type": atk["type"],
                    "name": atk["name"],
                    "category": atk["category"],
                    "payload": atk["payload"],
                    "status_code": atk_resp.status_code,
                    "waf_blocked": is_blocked_by_waf,
                    "reflected": reflected
                })

                if reflected:
                    findings.append({
                        "id": f"REFLECTED_{atk['type']}",
                        "title": f"Potential XSS: Unfiltered Script Reflection Detected",
                        "severity": "CRITICAL",
                        "category": "Client-Side Injection",
                        "description": "The test script payload was reflected back in the HTTP response body without HTML sanitization.",
                        "evidence": f"Reflected in response from {test_url}",
                        "remediation": "Apply context-aware output encoding (e.g., OWASP Java Encoder or React JSX sanitization) before rendering user input."
                    })
                elif not is_blocked_by_waf and atk_resp.status_code == 200:
                    findings.append({
                        "id": f"UNFILTERED_{atk['type']}",
                        "title": f"No Active WAF Filtering for {atk['name']}",
                        "severity": "LOW",
                        "category": "Defense in Depth",
                        "description": f"The web endpoint processed the {atk['name']} payload with HTTP 200 OK. An active WAF/IPS rule was not triggered at the reverse proxy layer.",
                        "evidence": f"Server returned HTTP 200 to probe '{atk['payload']}'",
                        "remediation": "Ensure parameterized queries and deploy a Web Application Firewall (ModSecurity, Cloudflare, or AWS WAF) to block malicious inputs."
                    })

            except Exception as e:
                attack_test_results.append({
                    "attack_type": atk["type"],
                    "name": atk["name"],
                    "category": atk["category"],
                    "payload": atk["payload"],
                    "status_code": 0,
                    "waf_blocked": False,
                    "error": str(e)
                })

    # --- Phase 5: Score Calculation & Grading ---
    score = 100
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if sev == "CRITICAL":
            score -= 25
        elif sev == "HIGH":
            score -= 15
        elif sev == "MEDIUM":
            score -= 8
        elif sev == "LOW":
            score -= 3

    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
        risk_level = "LOW"
    elif score >= 75:
        grade = "B"
        risk_level = "MODERATE"
    elif score >= 60:
        grade = "C"
        risk_level = "ELEVATED"
    elif score >= 40:
        grade = "D"
        risk_level = "HIGH"
    else:
        grade = "F"
        risk_level = "CRITICAL"

    duration = round(time.time() - start_time, 2)

    return {
        "status": "COMPLETED",
        "target_url": target_url,
        "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "duration_seconds": duration,
        "overall_score": score,
        "grade": grade,
        "risk_level": risk_level,
        "summary": severity_counts,
        "total_findings": len(findings),
        "server_info": server_info,
        "headers_analyzed": headers_analyzed,
        "exposure_results": exposure_results,
        "attack_test_results": attack_test_results,
        "findings": findings
    }
