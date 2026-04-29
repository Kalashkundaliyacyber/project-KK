"""
ScanWise AI — AI Analysis Module
Uses Claude API (claude-sonnet-4-20250514) to generate intelligent,
explainable security analysis from parsed scan JSON.
Falls back to rule-based analysis if API is unavailable.
"""
import json
import os
import urllib.request
import urllib.error
from typing import Optional


# ── Prompt Template ────────────────────────────────────────────────────────────

ANALYSIS_PROMPT = """You are a senior cybersecurity analyst. Analyze the following network scan data and return a structured security assessment.

SCAN DATA:
{scan_json}

INSTRUCTIONS:
- Analyze each discovered service and version
- Identify risk level for each finding (low/medium/high/critical)
- Explain WHY each risk level was assigned
- Suggest the next safe scan to run
- Provide patch/hardening guidance
- Flag any version uncertainties

STRICT SAFETY RULES:
- Do NOT suggest exploits, payloads, or attack methods
- Do NOT provide weaponization guidance
- Only provide defensive recommendations
- If version is approximate, say so explicitly

Return ONLY valid JSON in this exact structure (no markdown, no extra text):
{{
  "findings": [
    {{
      "port": <int>,
      "service": "<name>",
      "version": "<detected>",
      "exposure": "<public|internal|unknown>"
    }}
  ],
  "version_status": [
    {{
      "service": "<name>",
      "version": "<detected>",
      "status": "<latest|outdated|unsupported|unknown>",
      "confidence": "<high|medium|low>",
      "note": "<explanation>"
    }}
  ],
  "cve_insight": [
    {{
      "service": "<name>",
      "cve_id": "<CVE-YYYY-XXXXX or 'unknown'>",
      "severity": "<critical|high|medium|low>",
      "description": "<one sentence, no exploit details>",
      "confidence": "<high|medium|low>"
    }}
  ],
  "risk_analysis": [
    {{
      "service": "<name>",
      "port": <int>,
      "risk_level": "<critical|high|medium|low>",
      "score": <0.0-10.0>,
      "reason": "<clear explanation why this risk level>"
    }}
  ],
  "recommendations": [
    {{
      "service": "<name>",
      "action": "<specific action to take>",
      "priority": "<immediate|high|medium|low>"
    }}
  ],
  "next_scan": {{
    "type": "<tcp_basic|udp_scan|service_detect|version_deep|enum_scripts|os_detect>",
    "reason": "<why this scan is recommended next>",
    "command_hint": "<safe nmap flag description only, no actual targets>"
  }},
  "notes": [
    "<any uncertainty, assumption, or limitation worth mentioning>"
  ],
  "overall_risk": "<critical|high|medium|low>",
  "summary": "<2-3 sentence plain English summary of findings>"
}}"""


# ── Main Analysis Function ─────────────────────────────────────────────────────

def analyze_scan(data: dict) -> dict:
    """
    Analyze parsed scan JSON using Claude AI.
    Falls back to rule-based analysis if AI is unavailable.

    Args:
        data: Parsed scan dict containing hosts, ports, services, versions

    Returns:
        Structured analysis dict with findings, risks, recommendations
    """
    try:
        result = _ai_analyze(data)
        result["engine"] = "claude-ai"
        return result
    except Exception as e:
        # Graceful fallback to rule-based analysis
        result = _rule_based_analyze(data)
        result["engine"] = "rule-based-fallback"
        result["fallback_reason"] = str(e)
        return result


# ── AI Analysis via Claude API ─────────────────────────────────────────────────

def _ai_analyze(data: dict) -> dict:
    """Call Claude API and parse response."""
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not set")

    # Build clean input for the prompt
    scan_input = _build_prompt_input(data)
    prompt = ANALYSIS_PROMPT.format(scan_json=json.dumps(scan_input, indent=2))

    payload = json.dumps({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 2000,
        "messages": [{"role": "user", "content": prompt}]
    }).encode()

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type":      "application/json",
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode())

    # Extract text content from response
    raw_text = ""
    for block in body.get("content", []):
        if block.get("type") == "text":
            raw_text += block.get("text", "")

    return _parse_ai_response(raw_text)


def _parse_ai_response(raw: str) -> dict:
    """Extract and parse JSON from Claude's response."""
    raw = raw.strip()

    # Strip markdown code fences if present
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1]) if lines[-1].strip() == "```" else "\n".join(lines[1:])

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Try to find JSON object within the text
        start = raw.find("{")
        end   = raw.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(raw[start:end])
        raise ValueError(f"Could not parse AI response as JSON: {raw[:200]}")


def _build_prompt_input(data: dict) -> dict:
    """
    Convert internal scan data format to clean prompt input.
    Handles both the internal pipeline format and the simple API format.
    """
    # Simple format: {"host": "...", "services": [...]}
    if "services" in data and "host" in data:
        return data

    # Internal pipeline format: {"hosts": [{"ip": ..., "ports": [...]}]}
    hosts = data.get("hosts", [])
    if not hosts:
        return {"host": "unknown", "services": []}

    host = hosts[0]
    services = []
    for port in host.get("ports", []):
        va = port.get("version_analysis", {})
        services.append({
            "port":     port.get("port"),
            "service":  port.get("service", "unknown"),
            "version":  f"{port.get('product','')} {port.get('version','')}".strip() or "unknown",
            "exposure": port.get("context", {}).get("exposure_type", "unknown"),
            "cves":     [c["cve_id"] for c in port.get("cves", [])[:3]],
            "version_status": va.get("status", "unknown"),
        })

    return {
        "host":     host.get("ip", "unknown"),
        "os":       host.get("os", {}).get("name", "unknown") if host.get("os") else "unknown",
        "services": services,
    }


# ── Rule-Based Fallback ────────────────────────────────────────────────────────

def _rule_based_analyze(data: dict) -> dict:
    """
    Rule-based fallback analysis when AI is unavailable.
    Produces the same output structure as the AI analysis.
    """
    prompt_input = _build_prompt_input(data)
    services     = prompt_input.get("services", [])

    findings         = []
    version_status   = []
    cve_insight      = []
    risk_analysis    = []
    recommendations  = []

    RISK_SERVICES = {
        "ftp":    ("high",   "FTP transmits credentials in plaintext"),
        "telnet": ("critical","Telnet is unencrypted remote access"),
        "ssh":    ("medium", "SSH is high-value but generally secure if patched"),
        "http":   ("medium", "Unencrypted web traffic"),
        "https":  ("low",    "Encrypted web traffic — verify TLS version"),
        "mysql":  ("high",   "Database exposure — restrict to internal only"),
        "smb":    ("critical","SMB is a primary ransomware vector"),
        "rdp":    ("critical","RDP should never be exposed to the internet"),
        "snmp":   ("high",   "SNMPv1/v2c uses plaintext community strings"),
    }

    OUTDATED_HINTS = {
        "2.2": "outdated", "2.0": "unsupported",
        "5.5": "unsupported", "5.6": "unsupported",
        "7.":  "outdated",   "6.":  "unsupported",
        "2.3.4": "unsupported",
    }

    overall_scores = []

    for svc in services:
        port    = svc.get("port", 0)
        name    = svc.get("service", "unknown")
        version = svc.get("version", "unknown")
        exposure = svc.get("exposure", "unknown")

        findings.append({
            "port": port, "service": name,
            "version": version, "exposure": exposure
        })

        # Version status
        v_status = "unknown"
        for hint, status in OUTDATED_HINTS.items():
            if hint in version:
                v_status = status
                break
        version_status.append({
            "service":    name,
            "version":    version,
            "status":     v_status,
            "confidence": "medium" if v_status != "unknown" else "low",
            "note":       f"Version '{version}' pattern matched as {v_status}" if v_status != "unknown"
                          else "Could not determine version status from pattern matching"
        })

        # CVE insight (high-confidence known cases only)
        if "2.3.4" in version and name == "ftp":
            cve_insight.append({
                "service": name, "cve_id": "CVE-2011-2523",
                "severity": "critical",
                "description": "vsftpd 2.3.4 contains a backdoor — remove immediately",
                "confidence": "high"
            })
        elif "2.2" in version and name in ("http", "https"):
            cve_insight.append({
                "service": name, "cve_id": "CVE-2017-7679",
                "severity": "critical",
                "description": "Apache 2.2 is end-of-life with known critical vulnerabilities",
                "confidence": "high"
            })
        else:
            cve_insight.append({
                "service": name, "cve_id": "unknown",
                "severity": "unknown",
                "description": "Run version_deep scan for accurate CVE matching",
                "confidence": "low"
            })

        # Risk analysis
        risk_level, reason = RISK_SERVICES.get(name, ("low", "Non-standard service"))
        score = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 2.0}.get(risk_level, 2.0)
        if v_status == "unsupported": score = min(score + 1.5, 10.0)
        if v_status == "outdated":    score = min(score + 0.8, 10.0)
        actual_level = (
            "critical" if score >= 8.5 else
            "high"     if score >= 6.5 else
            "medium"   if score >= 4.0 else "low"
        )
        risk_analysis.append({
            "service": name, "port": port,
            "risk_level": actual_level, "score": round(score, 1),
            "reason": reason + (f" | Version is {v_status}" if v_status != "unknown" else "")
        })
        overall_scores.append(score)

        # Recommendations
        PATCHES = {
            "ftp":    "Replace FTP with SFTP. Disable anonymous login.",
            "telnet": "Disable Telnet immediately. Replace with SSH.",
            "ssh":    "Disable root login. Use key auth. Restrict by IP.",
            "http":   "Redirect all traffic to HTTPS. Hide server version headers.",
            "https":  "Enforce TLS 1.2/1.3. Disable older TLS versions.",
            "mysql":  "Bind to localhost only. Disable remote root login.",
            "smb":    "Disable SMBv1. Block port 445 at the firewall.",
            "rdp":    "Put behind VPN. Enable NLA. Restrict by IP.",
            "snmp":   "Upgrade to SNMPv3. Restrict access to monitoring systems.",
        }
        recommendations.append({
            "service":  name,
            "action":   PATCHES.get(name, f"Review if port {port} needs to be open. Apply latest patches."),
            "priority": actual_level if actual_level in ("immediate", "high") else actual_level
        })

    # Next scan suggestion
    has_no_version = any(s.get("version", "unknown") in ("unknown", "") for s in services)
    has_critical   = any(r["risk_level"] == "critical" for r in risk_analysis)

    if has_no_version:
        next_scan = {
            "type": "service_detect",
            "reason": "Some services have no version info. Service detection will identify exact versions for CVE mapping.",
            "command_hint": "nmap -sV -T3 --open (add target)"
        }
    elif has_critical:
        next_scan = {
            "type": "enum_scripts",
            "reason": "Critical risks found. NSE scripts will gather deeper service intelligence.",
            "command_hint": "nmap -sC -sV -T3 --open (add target)"
        }
    else:
        next_scan = {
            "type": "udp_scan",
            "reason": "TCP scan complete. UDP services like DNS (53), SNMP (161) may still be exposed.",
            "command_hint": "nmap -sU --top-ports 100 -T3 (add target, requires root)"
        }

    # Overall risk
    max_score   = max(overall_scores) if overall_scores else 0
    overall     = ("critical" if max_score >= 8.5 else "high" if max_score >= 6.5
                   else "medium" if max_score >= 4.0 else "low")
    svc_count   = len(services)
    crit_count  = sum(1 for r in risk_analysis if r["risk_level"] == "critical")

    return {
        "findings":        findings,
        "version_status":  version_status,
        "cve_insight":     cve_insight,
        "risk_analysis":   risk_analysis,
        "recommendations": recommendations,
        "next_scan":       next_scan,
        "notes": [
            "Analysis generated by rule-based fallback engine (AI unavailable).",
            "Set ANTHROPIC_API_KEY environment variable to enable AI analysis.",
            "Run a version_deep scan for higher-confidence CVE matching.",
        ],
        "overall_risk": overall,
        "summary": (
            f"Scan found {svc_count} open service(s) on {prompt_input.get('host', 'target')}. "
            f"{crit_count} critical risk(s) identified. "
            f"{'Immediate remediation required.' if crit_count > 0 else 'Review recommendations and apply patches.'}"
        )
    }
