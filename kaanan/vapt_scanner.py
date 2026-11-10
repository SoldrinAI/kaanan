"""vapt_scanner.py — Kaanan VAPT Engine (SAST-integrated v3)

Pipeline:
  Phase 0 SAST       : Build vulnerability intelligence map from static analysis.
  Phase 1 Doc scan   : Extract live API surface.
  Phase 2 Auto-auth  : Obtain real session token for protected endpoint testing.
  Phase 3 Attack     : Baseline -> 404-skip -> baseline-content-analysis ->
                       SAST-informed attack generation -> fire -> LLM analysis.
"""
from __future__ import annotations
import json, re, time, warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import httpx, litellm
from rich.console import Console
from kaanan.config import KaananConfig, VaptConfig
from kaanan.doc_scanner import BackendEndpoint, run_doc_scan
from kaanan.scanner import FileResult, Vulnerability, run_scan

warnings.filterwarnings("ignore", message=".*SSL.*")
console = Console()

HTTP_TIMEOUT          = 15.0
BODY_EXCERPT_LEN      = 2000
MAX_ATTACKS_PER_EP    = 12
MAX_SAST_FINDINGS     = 8
ATTACK_GEN_MAX_TOKENS = 2048
ANALYSIS_MAX_TOKENS   = 1200

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_SKIP_STATUSES    = frozenset({404, 405, 410})
_TOKEN_KEYS       = ("token", "access_token", "jwt", "auth_token", "bearer",
                    "id_token", "sessionToken", "accessToken", "authToken")
_BYPASS_INDICATORS = ("bypass", "forgery", "forged", "invalid", "none algorithm",
                      "omit", "without auth", "no token", "no authorization",
                      "missing auth")
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

@dataclass
class AttackPayload:
    vector: str; cwe: str; owasp: str; method: str; path: str
    headers: dict; body: Optional[dict]; mutation_description: str

@dataclass
class VaptFinding:
    severity: str; vector: str; cwe: str; owasp: str
    endpoint_method: str; endpoint_path: str; mutation_description: str
    attack_body: str; baseline_status: Optional[int]; attack_status: Optional[int]
    response_time_ms: Optional[float]; evidence: str; description: str
    impact: str; remediation: str; reasoning: str = ""; sast_confirmed: bool = False
    def __post_init__(self):
        self.severity = self.severity.upper()
        if self.severity not in _VALID_SEVERITIES:
            self.severity = "MEDIUM"

@dataclass
class AttackAttempt:
    vector: str; cwe: str; owasp: str; method: str; path: str
    mutation_description: str; attack_body: str; baseline_status: Optional[int]
    attack_status: Optional[int]; attack_time_ms: Optional[float]
    confirmed: bool; reasoning: str; finding: Optional[VaptFinding] = None
    is_baseline_analysis: bool = False

@dataclass
class VaptEndpointResult:
    method: str; path: str; file_source: str; authentication: str
    baseline_status: Optional[int] = None
    baseline_response_time_ms: Optional[float] = None
    attacks_fired: int = 0
    attack_attempts: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    error: Optional[str] = None; tokens_used: int = 0
    budget_exhausted: bool = False; used_real_token: bool = False

@dataclass
class VaptScanResult:
    target_url: str; target_file: str; model: str
    authenticated: bool = False; auth_endpoint: str = ""
    endpoint_results: list = field(default_factory=list)
    total_tokens_used: int = 0; sast_findings_total: int = 0


_BASELINE_EXPOSURE_PROMPT = (
    "You are a security analyst doing passive inspection of a live API baseline response. No attack sent.\n\n"
    "TASK: Does the response ITSELF leak sensitive info?\n\n"
    "FLAG if in response body: debug: true, internal file paths, db filenames (e.g. app.db),\n"
    "stack traces, password hashes, plaintext passwords, API keys, secret tokens,\n"
    "internal IPs/hostnames, verbose version strings, DB connection strings, hardcoded credentials.\n\n"
    "DO NOT flag: standard 4xx error bodies, public API schema, non-sensitive metadata.\n\n"
    "Return ONLY valid JSON:\n"
    '{"issues":[{"severity":"MEDIUM","type":"Sensitive Data Exposure","cwe":"CWE-200",'
    '"owasp":"A02:2021 - Cryptographic Failures","evidence":"...","description":"...",'
    '"impact":"...","remediation":"..."}]}\n'
    "None found: {\"issues\":[]}"
)

_ATTACK_GEN_PROMPT = (
    "You are a senior penetration tester on an authorized engagement.\n\n"
    "PRIMARY MISSION - SAST CONFIRMATION:\n"
    "Static analysis found specific vulnerabilities. Generate payloads that CONFIRM those at runtime.\n\n"
    "SAST-TO-PAYLOAD MAPPING:\n"
    "- SQL Injection in field X -> SQLi payload directly in field X\n"
    "- Hardcoded secret ABC -> try ABC as credential/token\n"
    "- Path Traversal in filename -> ../../etc/passwd payload\n"
    "- Command Injection in table_name -> users; id payload\n"
    "- IDOR (no ownership check) -> change resource ID to access another user's data\n"
    "- Mass Assignment (role writable) -> send role=admin in body\n"
    "- Broken Auth (no expiry, weak secret) -> forge JWT with none algorithm\n"
    "- MD5 hashing -> try known MD5 hashes as passwords\n\n"
    "SECONDARY MISSION: Dynamic-only vulns (IDOR, business logic, timing).\n\n"
    "OUTPUT: ONLY valid JSON array. Zero markdown. Max 12 payloads. Return [] if no surface.\n\n"
    "Schema: {\"vector\":\"SQL Injection\",\"cwe\":\"CWE-89\",\"owasp\":\"A03:2021 - Injection\","
    "\"method\":\"POST\",\"path\":\"/api/auth/login\","
    "\"headers\":{\"Content-Type\":\"application/json\"},"
    "\"body\":{\"username\":\"' OR '1'='1'-- \",\"password\":\"x\"},"
    "\"mutation_description\":\"OR-bypass in username; confirmed if HTTP 200 with session token.\"}\n\n"
    "RULES: Substitute real values into {path_params}. body=null for GET/DELETE.\n"
    "headers must include Content-Type: application/json.\n"
    "Auth bypass: omit Authorization header intentionally.\n"
    "JWT forgery: Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.\n"
    "mutation_description: one impersonal sentence.\nReturn the JSON array now."
)

_ANALYSIS_PROMPT = (
    "You are a senior penetration tester evaluating a live attack response.\n\n"
    "TASK: Did this attack CONFIRM a vulnerability? Provide 2-3 concise impersonal sentences.\n\n"
    "If SAST CONTEXT shown, confirm/deny runtime exploitability of that specific finding.\n\n"
    "CONFIRMATION TABLE (confirm ONLY on CLEAR evidence):\n"
    "SQL Injection: SQL error in body OR login bypass (HTTP 200 + token on injected creds)\n"
    "BOLA/IDOR: HTTP 200 with another user's private data when ID was mutated\n"
    "Broken Auth: HTTP 200/201 on protected resource with invalid/none-algorithm JWT\n"
    "Auth Bypass: HTTP 200/201 on protected resource with NO Authorization header\n"
    "Command Injection: OS output (root:, uid=, /bin/, directory listing)\n"
    "Path Traversal: Filesystem content (/etc/passwd body, root:x:0:0)\n"
    "SSRF: Internal service content or response time >3x baseline\n"
    "XSS: Injected <script> reflected VERBATIM in body\n"
    "Mass Assignment: HTTP 200 with admin=true, role=admin in response\n"
    "Sensitive Exposure: Credentials/hashes/tokens without valid auth\n\n"
    "DO NOT confirm on: status code change alone, generic errors, time variance only.\n\n"
    "CONFIRMED: {\"confirmed\":true,\"severity\":\"HIGH\",\"evidence\":\"specific proof\","
    "\"description\":\"what is vulnerable\",\"impact\":\"exploitation consequence\","
    "\"remediation\":\"concrete fix with code\",\"reasoning\":\"2-3 impersonal sentences\"}\n\n"
    "NOT CONFIRMED: {\"confirmed\":false,\"reasoning\":\"2-3 impersonal sentences: "
    "evidence sought, what observed, why not confirmed\"}\n\n"
    "SEVERITY: CRITICAL=RCE/full bypass, HIGH=confirmed injection/IDOR, "
    "MEDIUM=partial leakage, LOW=minor info.\nReturn JSON now."
)


def _substitute_path_params(path, value="1"):
    path = re.sub(r"\{[^}]+\}", value, path)
    path = re.sub(r"(?<=/):([a-zA-Z_][a-zA-Z0-9_]*)", value, path)
    return path

def _build_minimal_body(request_payload):
    fields = {}
    for m in re.finditer(r"(\w+)\s*\(([^)]+)\)", request_payload):
        name, hint, nl = m.group(1), m.group(2).lower(), m.group(1).lower()
        if any(t in hint for t in ("int", "number", "float", "integer")):
            fields[name] = 1
        elif "bool" in hint:
            fields[name] = True
        elif "email" in nl:
            fields[name] = "test@example.com"
        elif any(k in nl for k in ("password", "pass", "passwd")):
            fields[name] = "Test@1234"
        elif "token" in nl or "key" in nl:
            fields[name] = "dummy_baseline_token"
        elif any(k in nl for k in ("id", "_id")):
            fields[name] = 1
        else:
            fields[name] = "test_value"
    return fields

def _excerpt(text, max_len=BODY_EXCERPT_LEN):
    return text[:max_len] if len(text) > max_len else text

def _extract_token(body_text):
    try:
        data = json.loads(body_text)
    except Exception:
        return None
    for key in _TOKEN_KEYS:
        if isinstance(data.get(key), str) and len(data[key]) > 10:
            return data[key]
    for v in data.values():
        if isinstance(v, dict):
            for key in _TOKEN_KEYS:
                if isinstance(v.get(key), str) and len(v[key]) > 10:
                    return v[key]
    return None

def _extract_str_field(text, field_name):
    m = re.search(rf'"{re.escape(field_name)}"\s*:\s*"', text, re.DOTALL)
    if not m:
        return ""
    pos, buf = m.end(), []
    while pos < len(text):
        ch = text[pos]
        if ch == "\\" and pos + 1 < len(text):
            buf.append(text[pos + 1]); pos += 2
        elif ch == '"':
            break
        else:
            buf.append(ch); pos += 1
    return "".join(buf).strip()

def _format_sast_findings(findings):
    if not findings:
        return "  None available. Apply contextual analysis."
    parts = []
    for v in findings[:MAX_SAST_FINDINGS]:
        ln = v.verified_line or v.line
        line_ref = f"line {ln}" if ln else "?"
        snippet = (v.code_snippet or "").strip()[:100]
        desc = (v.description or "")[:150]
        parts.append(
            f"  [{v.severity}] {v.type} ({v.cwe}) at {line_ref}\n"
            f"    Code: {snippet}\n"
            f"    {desc}"
        )
    return "\n\n".join(parts)

def _inject_auth_token(payloads, auth_token, endpoint):
    if not auth_token:
        return payloads
    if "None" in endpoint.authentication or "Public" in endpoint.authentication:
        return payloads
    result = []
    for p in payloads:
        headers = dict(p.headers)
        dl = p.mutation_description.lower()
        vl = p.vector.lower()
        is_bypass = any(ind in dl for ind in _BYPASS_INDICATORS)
        is_auth_attack = any(
            k in vl for k in
            ("broken auth", "jwt", "forgery", "bypass", "missing auth", "token")
        )
        if not is_bypass and not is_auth_attack:
            headers["Authorization"] = f"Bearer {auth_token}"
        result.append(AttackPayload(
            vector=p.vector, cwe=p.cwe, owasp=p.owasp,
            method=p.method, path=p.path, headers=headers,
            body=p.body, mutation_description=p.mutation_description,
        ))
    return result


def _fire_request(method, url, headers, body):
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT, verify=False) as client:
            t0 = time.monotonic()
            if body is not None:
                resp = client.request(method, url, json=body, headers=headers)
            else:
                resp = client.request(method, url, headers=headers)
            ms = round((time.monotonic() - t0) * 1000, 2)
        return resp.status_code, ms, _excerpt(resp.text), dict(resp.headers)
    except Exception as exc:
        return None, None, str(exc)[:300], {}

def _baseline_request(endpoint, base_url, auth_token=None):
    path = _substitute_path_params(endpoint.path)
    url = base_url.rstrip("/") + path
    headers = {"Content-Type": "application/json"}
    is_protected = (
        "None" not in endpoint.authentication and
        "Public" not in endpoint.authentication
    )
    if is_protected:
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        else:
            headers["Authorization"] = "Bearer baseline_dummy_token_kaanan"
    body = None
    if endpoint.method.upper() in ("POST", "PUT", "PATCH"):
        body = _build_minimal_body(endpoint.request_payload) or None
    status, ms, body_text, _ = _fire_request(endpoint.method.upper(), url, headers, body)
    return status, ms, body_text

def _attack_request(attack, base_url):
    url = base_url.rstrip("/") + attack.path
    return _fire_request(attack.method, url, attack.headers, attack.body)

def _auto_authenticate(endpoint_pairs, config):
    if not config.test_username or not config.test_password:
        console.print(
            "  [dim]No test credentials. Protected endpoints use placeholder token.[/dim]"
        )
        return None, ""
    AUTH_KW = (
        "login", "signin", "sign-in", "token", "auth/token",
        "auth/login", "obtain", "session",
    )
    candidates = [
        (fs, ep) for fs, ep in endpoint_pairs
        if ep.method.upper() == "POST" and
        any(kw in ep.path.lower() for kw in AUTH_KW)
    ]
    for _, ep in candidates:
        body = _build_minimal_body(ep.request_payload)
        injected = False
        for k in list(body.keys()):
            kl = k.lower()
            if "email" in kl or "username" in kl or "user" in kl:
                body[k] = config.test_username; injected = True
            elif "password" in kl or "pass" in kl:
                body[k] = config.test_password; injected = True
        if not injected:
            body = {"username": config.test_username, "password": config.test_password}
        url = config.base_url.rstrip("/") + ep.path
        status, _, body_text, _ = _fire_request(
            "POST", url, {"Content-Type": "application/json"}, body
        )
        if status in (200, 201):
            token = _extract_token(body_text)
            if token:
                console.print(
                    f"  [bold green]Auto-authenticated[/bold green] via "
                    f"[cyan]{ep.path}[/cyan] as [bold]{config.test_username}[/bold]"
                )
                return token, ep.path
    console.print(
        f"  [yellow]Auto-authentication failed for {config.test_username!r}.[/yellow]"
    )
    return None, ""


def _analyze_baseline_exposure(b_status, b_body, b_headers, endpoint, config):
    if not b_body.strip():
        return [], 0
    ct = b_headers.get("content-type", "unknown")
    user_msg = (
        f"ENDPOINT : {endpoint.method} {endpoint.path}\n"
        f"STATUS   : {b_status}\n"
        f"CONTENT-TYPE: {ct}\n\n"
        f"RESPONSE BODY:\n{_excerpt(b_body, 1500)}\n\n"
        "Analyse this baseline response for sensitive data exposure now."
    )
    try:
        response = litellm.completion(
            model=config.model, api_key=config.api_key,
            messages=[
                {"role": "system", "content": _BASELINE_EXPOSURE_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            temperature=0.0, max_tokens=ANALYSIS_MAX_TOKENS,
        )
        raw   = response.choices[0].message.content or ""
        usage = getattr(response, "usage", None)
        tok   = (getattr(usage, "prompt_tokens", 0) or 0) +                 (getattr(usage, "completion_tokens", 0) or 0)
        return _parse_baseline_issues(raw, b_status, endpoint), tok
    except Exception as exc:
        console.print(f"\n    [red]Baseline analysis error:[/red] {str(exc)[:100]}")
        return [], 0

def _parse_baseline_issues(raw, b_status, endpoint):
    cleaned = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip().rstrip("`")
    data = None
    m = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if m:
        try:
            data = json.loads(m.group())
        except json.JSONDecodeError:
            pass
    if data is None:
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            pass
    if data is None or not isinstance(data.get("issues"), list):
        return []
    attempts = []
    for issue in data["issues"]:
        if not isinstance(issue, dict):
            continue
        finding = VaptFinding(
            severity=str(issue.get("severity", "MEDIUM")),
            vector=str(issue.get("type", "Sensitive Data Exposure")),
            cwe=str(issue.get("cwe", "CWE-200")),
            owasp=str(issue.get("owasp", "A02:2021 - Cryptographic Failures")),
            endpoint_method=endpoint.method, endpoint_path=endpoint.path,
            mutation_description=(
                "Baseline response analysis — no attack required. "
                "Vulnerability present in the server default response."
            ),
            attack_body="", baseline_status=b_status, attack_status=None,
            response_time_ms=None,
            evidence=str(issue.get("evidence", "")),
            description=str(issue.get("description", "")),
            impact=str(issue.get("impact", "")),
            remediation=str(issue.get("remediation", "")),
            reasoning=(
                "Identified through passive inspection of the baseline HTTP response. "
                "No attack payload required."
            ),
        )
        attempts.append(AttackAttempt(
            vector=finding.vector, cwe=finding.cwe, owasp=finding.owasp,
            method=endpoint.method, path=endpoint.path,
            mutation_description=finding.mutation_description,
            attack_body="", baseline_status=b_status, attack_status=None,
            attack_time_ms=None, confirmed=True,
            reasoning=finding.reasoning, finding=finding,
            is_baseline_analysis=True,
        ))
    return attempts

def _generate_attacks(endpoint, config, sast_findings=None):
    sast_block = _format_sast_findings(sast_findings or [])
    user_msg = (
        f"SAST FINDINGS for this file:\n{sast_block}\n\n"
        f"ENDPOINT:\n"
        f"  Method    : {endpoint.method}\n"
        f"  Path      : {endpoint.path}\n"
        f"  Auth      : {endpoint.authentication}\n"
        f"  Payload   : {endpoint.request_payload}\n"
        f"  Responses : {endpoint.response_scenarios}\n\n"
        "Primary: confirm SAST findings at runtime.\n"
        "Secondary: discover dynamic vulns SAST cannot detect.\n"
        "Generate the JSON attack array now."
    )
    try:
        response = litellm.completion(
            model=config.model, api_key=config.api_key,
            messages=[
                {"role": "system", "content": _ATTACK_GEN_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            temperature=0.3, max_tokens=ATTACK_GEN_MAX_TOKENS,
        )
        raw   = response.choices[0].message.content or ""
        usage = getattr(response, "usage", None)
        tok   = (getattr(usage, "prompt_tokens", 0) or 0) +                 (getattr(usage, "completion_tokens", 0) or 0)
        return _parse_attack_payloads(raw, endpoint.method), tok
    except Exception as exc:
        console.print(f"\n    [red]Attack gen error:[/red] {str(exc)[:120]}")
        return [], 0

def _parse_attack_payloads(raw, default_method):
    cleaned = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip().rstrip("`")
    match = re.search(r"\[.*\]", cleaned, re.DOTALL)
    if not match:
        return []
    try:
        data = json.loads(match.group())
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    payloads = []
    for item in data[:MAX_ATTACKS_PER_EP]:
        if not isinstance(item, dict):
            continue
        body = item.get("body")
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                body = None
        payloads.append(AttackPayload(
            vector=str(item.get("vector", "Unknown")),
            cwe=str(item.get("cwe", "")),
            owasp=str(item.get("owasp", "")),
            method=str(item.get("method", default_method)).upper(),
            path=str(item.get("path", "/")),
            headers=dict(item.get("headers", {"Content-Type": "application/json"})),
            body=body,
            mutation_description=str(item.get("mutation_description", "")),
        ))
    return payloads

def _analyze_response(
    attack, baseline_status, baseline_time_ms, baseline_body,
    attack_status, attack_time_ms, attack_body, attack_headers,
    config, sast_findings=None,
):
    sast_ctx = ""
    if sast_findings:
        rel = [
            v for v in sast_findings
            if v.type.lower() in attack.vector.lower() or
               attack.vector.lower() in v.type.lower()
        ][:3]
        if rel:
            lines = ["\nSAST CONTEXT - This attack targets a statically-confirmed vulnerability:"]
            for v in rel:
                desc = (v.description or "")[:120]
                lines.append(f"  [{v.severity}] {v.type}: {desc}")
            lines.append("")
            sast_ctx = "\n".join(lines)

    body_str = json.dumps(attack.body) if attack.body else "None"
    bl_status_str = str(baseline_status) if baseline_status is not None else "N/A"
    at_status_str = str(attack_status) if attack_status is not None else "Connection error"
    ct = attack_headers.get("content-type", "unknown")

    user_msg = (
        f"ATTACK:\n"
        f"  Vector  : {attack.vector} ({attack.cwe})\n"
        f"  OWASP   : {attack.owasp}\n"
        f"  Mutation: {attack.mutation_description}\n"
        f"  Method  : {attack.method}  Path: {attack.path}\n"
        f"  Body    : {body_str}\n"
        f"{sast_ctx}\n"
        f"BASELINE RESPONSE:\n"
        f"  Status  : {bl_status_str}  Time: {baseline_time_ms}ms\n"
        f"  Body    : {_excerpt(baseline_body, 800)}\n\n"
        f"ATTACK RESPONSE:\n"
        f"  Status  : {at_status_str}  Time: {attack_time_ms}ms\n"
        f"  Content-Type: {ct}\n"
        f"  Body    : {_excerpt(attack_body, 800)}\n\n"
        "Evaluate and return JSON now."
    )
    try:
        response = litellm.completion(
            model=config.model, api_key=config.api_key,
            messages=[
                {"role": "system", "content": _ANALYSIS_PROMPT},
                {"role": "user",   "content": user_msg},
            ],
            temperature=0.0, max_tokens=ANALYSIS_MAX_TOKENS,
        )
        raw   = response.choices[0].message.content or ""
        usage = getattr(response, "usage", None)
        tok   = (getattr(usage, "prompt_tokens", 0) or 0) +                 (getattr(usage, "completion_tokens", 0) or 0)
        confirmed, reasoning, finding = _parse_analysis(
            raw, attack, baseline_status, attack_status, attack_time_ms, sast_findings
        )
    except Exception as exc:
        console.print(f"\n      [red]Analysis error:[/red] {str(exc)[:120]}")
        confirmed, reasoning, finding, tok = (
            False, f"Analysis failed: {str(exc)[:150]}", None, 0
        )
    return AttackAttempt(
        vector=attack.vector, cwe=attack.cwe, owasp=attack.owasp,
        method=attack.method, path=attack.path,
        mutation_description=attack.mutation_description,
        attack_body=json.dumps(attack.body, indent=2) if attack.body else "",
        baseline_status=baseline_status, attack_status=attack_status,
        attack_time_ms=attack_time_ms, confirmed=confirmed,
        reasoning=reasoning, finding=finding, is_baseline_analysis=False,
    ), tok

def _make_finding(attack, baseline_status, attack_status, attack_time_ms,
                  severity, evidence, desc, impact, rem, reasoning, is_sast):
    return VaptFinding(
        severity=severity, vector=attack.vector, cwe=attack.cwe, owasp=attack.owasp,
        endpoint_method=attack.method, endpoint_path=attack.path,
        mutation_description=attack.mutation_description,
        attack_body=json.dumps(attack.body, indent=2) if attack.body else "",
        baseline_status=baseline_status, attack_status=attack_status,
        response_time_ms=attack_time_ms,
        evidence=evidence, description=desc, impact=impact, remediation=rem,
        reasoning=reasoning, sast_confirmed=is_sast,
    )

def _parse_analysis(raw, attack, baseline_status, attack_status,
                    attack_time_ms, sast_findings=None):
    cleaned = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip().rstrip("`")
    data = None
    m = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if m:
        try:
            data = json.loads(m.group())
        except json.JSONDecodeError:
            pass
    if data is None:
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            pass

    is_sast = bool(
        sast_findings and any(
            v.type.lower() in attack.vector.lower() for v in sast_findings
        )
    )

    if data is None:
        cm = re.search(r'"confirmed"\s*:\s*(true|false)', cleaned, re.IGNORECASE)
        if not cm:
            return False, f"Unparseable: {cleaned[:120].replace(chr(10), ' ')}", None
        confirmed = cm.group(1).lower() == "true"
        reasoning = _extract_str_field(cleaned, "reasoning") or "Reasoning unavailable."
        if not confirmed:
            return False, reasoning, None
        return True, reasoning, _make_finding(
            attack, baseline_status, attack_status, attack_time_ms,
            _extract_str_field(cleaned, "severity") or "MEDIUM",
            _extract_str_field(cleaned, "evidence"),
            _extract_str_field(cleaned, "description"),
            _extract_str_field(cleaned, "impact"),
            _extract_str_field(cleaned, "remediation"),
            reasoning, is_sast,
        )

    reasoning = str(data.get("reasoning", "No reasoning."))
    confirmed = bool(data.get("confirmed", False))
    if not confirmed:
        return False, reasoning, None
    return True, reasoning, _make_finding(
        attack, baseline_status, attack_status, attack_time_ms,
        str(data.get("severity", "MEDIUM")),
        str(data.get("evidence", "")),
        str(data.get("description", "")),
        str(data.get("impact", "")),
        str(data.get("remediation", "")),
        reasoning, is_sast,
    )


def run_vapt_scan(
    target_dir,
    config,
    prefilled_sast_results=None,
    prefilled_doc_results=None,
):
    """Main VAPT entry point. Runs SAST -> Doc scan -> Auto-auth -> Per-endpoint attack.

    Args:
        target_dir:             Directory containing the application source code.
        config:                 VaptConfig loaded from .env.
        prefilled_sast_results: If supplied (e.g. from ``kaanan run pipeline``),
                                Phase 0 is skipped and these results are used directly.
        prefilled_doc_results:  If supplied (e.g. from ``kaanan run pipeline``),
                                Phase 1 doc-scan is skipped; the supplied results are used.
    """

    # ── Phase 0: SAST intelligence ────────────────────────────────────────────
    base_llm = KaananConfig(api_key=config.api_key, model=config.model)

    if prefilled_sast_results is not None:
        console.print(
            "\n[bold cyan]Kaanan VAPT[/bold cyan] "
            "[dim]Phase 0/3 — SAST results [green]pre-supplied by pipeline[/green], "
            "skipping re-scan.[/dim]\n"
        )
        sast_results = prefilled_sast_results
    else:
        console.print(
            "\n[bold cyan]Kaanan VAPT[/bold cyan] "
            "[dim]Phase 0/3 — SAST intelligence scan...[/dim]\n"
        )
        sast_results = run_scan(target_dir=target_dir, config=base_llm)

    sast_map = {}
    total_sast = 0
    for fr in sast_results:
        total_sast += len(fr.vulnerabilities)
        key = Path(fr.filepath).name
        sast_map[key] = sorted(
            fr.vulnerabilities, key=lambda v: _SEV_ORDER.get(v.severity, 99)
        )

    if total_sast:
        console.print(
            f"  [green]SAST complete[/green] — "
            f"[bold]{total_sast}[/bold] finding(s) across "
            f"[bold]{len(sast_results)}[/bold] file(s). "
            "VAPT will target these first.\n"
        )
    else:
        console.print(
            "  [dim]No SAST findings — VAPT will use contextual analysis only.[/dim]\n"
        )

    # ── Phase 1: Doc scan ────────────────────────────────────────────────────────────────────────────
    if prefilled_doc_results is not None:
        console.print(
            "[bold cyan]Kaanan VAPT[/bold cyan] "
            "[dim]Phase 1/3 — API surface [green]pre-supplied by pipeline[/green], "
            "skipping re-scan.[/dim]\n"
        )
        doc_results = prefilled_doc_results
    else:
        target_file_path = target_dir / config.target_file
        if target_file_path.exists():
            console.print(
                "[bold cyan]Kaanan VAPT[/bold cyan] "
                f"[dim]Phase 1/3 — extracting API surface from "
                f"[cyan]{config.target_file}[/cyan]...[/dim]\n"
            )
            doc_results = run_doc_scan(
                target_dir=target_file_path.parent,
                config=base_llm,
                target_file=target_file_path,
            )
        else:
            console.print(
                "[bold cyan]Kaanan VAPT[/bold cyan] "
                f"[dim]Phase 1/3 — [yellow]target file {config.target_file!r} not found "
                f"in {target_dir}, falling back to full directory scan[/yellow]...[/dim]\n"
            )
            doc_results = run_doc_scan(target_dir=target_dir, config=base_llm)

    endpoint_pairs = [
        (dr.filepath, ep)
        for dr in doc_results
        if dr.classification == "Backend"
        for ep in dr.endpoints
    ]

    if not endpoint_pairs:
        console.print("[yellow]No backend endpoints found.[/yellow]")
        return VaptScanResult(
            target_url=config.base_url, target_file=config.target_file,
            model=config.model, sast_findings_total=total_sast,
        )

    # ── Phase 2: Auto-authenticate ────────────────────────────────────────────
    console.print(
        "[bold cyan]Kaanan VAPT[/bold cyan] "
        "[dim]Phase 2/3 — attempting auto-authentication...[/dim]\n"
    )
    auth_token, auth_ep = _auto_authenticate(endpoint_pairs, config)

    # ── Phase 3: Attack ───────────────────────────────────────────────────────
    auth_label = ("YES via " + auth_ep) if auth_token else "NO"
    console.print(
        "\n[bold cyan]Kaanan VAPT[/bold cyan] "
        f"[dim]Phase 3/3 — attacking [bold]{len(endpoint_pairs)}[/bold] endpoint(s) "
        f"at [bold]{config.base_url}[/bold][/dim]\n"
        f"  Model         : [bold]{config.model}[/bold]\n"
        f"  Token budget  : [bold]{config.max_tokens_per_api:,}[/bold] per endpoint\n"
        f"  Entry point   : [bold]{config.target_file}[/bold]\n"
        f"  Authenticated : [bold]{auth_label}[/bold]\n"
        f"  SAST guidance : [bold]{total_sast}[/bold] finding(s) informing attacks\n"
    )

    result = VaptScanResult(
        target_url=config.base_url, target_file=config.target_file,
        model=config.model, authenticated=bool(auth_token),
        auth_endpoint=auth_ep, sast_findings_total=total_sast,
    )

    for file_source, endpoint in endpoint_pairs:
        console.print(
            f"  [dim]->[/dim] [cyan]{endpoint.method:<7} {endpoint.path}[/cyan]  "
            f"[dim]({file_source})[/dim]",
            end="  ",
        )
        ep_result = VaptEndpointResult(
            method=endpoint.method, path=endpoint.path,
            file_source=file_source, authentication=endpoint.authentication,
            used_real_token=bool(auth_token),
        )
        ep_sast = sast_map.get(Path(file_source).name, [])

        # Baseline
        b_status, b_time, b_body = _baseline_request(
            endpoint, config.base_url, auth_token
        )
        ep_result.baseline_status           = b_status
        ep_result.baseline_response_time_ms = b_time

        if b_status is None:
            ep_result.error = f"Unreachable: {b_body}"
            console.print("[red]Unreachable[/red]")
            result.endpoint_results.append(ep_result)
            continue

        # 404/405/410 = route not found; skip ALL attacks
        if b_status in _SKIP_STATUSES:
            ep_result.error = (
                f"HTTP {b_status} — route not found. "
                "Attacks skipped. Verify KAANAN_TARGET_IP, KAANAN_TARGET_PORT, "
                "and URL prefix."
            )
            console.print(f"[yellow]HTTP {b_status} — not found, skipped[/yellow]")
            result.endpoint_results.append(ep_result)
            continue

        console.print(f"[dim]baseline={b_status}[/dim]  ", end="")

        # Passive baseline content analysis (2xx and 5xx)
        if b_status < 300 or b_status >= 500:
            base_attempts, base_tokens = _analyze_baseline_exposure(
                b_status, b_body, {}, endpoint, config
            )
            ep_result.tokens_used += base_tokens
            for ba in base_attempts:
                ep_result.attack_attempts.append(ba)
                if ba.confirmed and ba.finding:
                    ep_result.findings.append(ba.finding)

        # SAST-informed attack generation
        payloads, gen_tokens = _generate_attacks(endpoint, config, ep_sast)
        ep_result.tokens_used += gen_tokens

        if not payloads:
            console.print("[dim]no attacks generated[/dim]")
            result.endpoint_results.append(ep_result)
            continue

        # Inject real token into authenticated non-bypass attacks
        payloads = _inject_auth_token(payloads, auth_token, endpoint)

        # Fire + analyse
        for attack in payloads:
            if ep_result.tokens_used >= config.max_tokens_per_api:
                ep_result.budget_exhausted = True
                break
            a_status, a_time, a_body, a_hdrs = _attack_request(attack, config.base_url)
            ep_result.attacks_fired += 1
            attempt, atoks = _analyze_response(
                attack, b_status, b_time, b_body,
                a_status, a_time, a_body, a_hdrs,
                config, ep_sast,
            )
            ep_result.attack_attempts.append(attempt)
            ep_result.tokens_used += atoks
            if attempt.confirmed and attempt.finding:
                ep_result.findings.append(attempt.finding)

        result.total_tokens_used += ep_result.tokens_used

        budget_tag = " [yellow](budget limit)[/yellow]" if ep_result.budget_exhausted else ""
        if ep_result.findings:
            fc   = len(ep_result.findings)
            crit = sum(1 for f in ep_result.findings if f.severity == "CRITICAL")
            high = sum(1 for f in ep_result.findings if f.severity == "HIGH")
            sev_tag = f" [{crit}C/{high}H]" if (crit or high) else ""
            console.print(
                f"[red]{fc} finding(s){sev_tag}[/red]  "
                f"[dim]{ep_result.attacks_fired} attack(s)[/dim]" + budget_tag
            )
        else:
            console.print(
                f"[green]No findings[/green]  "
                f"[dim]{ep_result.attacks_fired} attack(s)[/dim]" + budget_tag
            )
        result.endpoint_results.append(ep_result)

    # Bulk-404 warning
    skipped = sum(
        1 for ep in result.endpoint_results
        if ep.error and any(f"HTTP {s}" in ep.error for s in _SKIP_STATUSES)
    )
    total_eps = len(result.endpoint_results)
    if total_eps > 0 and skipped / total_eps >= 0.5:
        console.print(
            f"\n[bold red]WARNING: {skipped}/{total_eps} endpoints returned "
            f"HTTP 404/405/410.[/bold red]\n"
            f"[yellow]App may not be running at [bold]{config.base_url}[/bold]. "
            "Check IP/port and URL prefix.[/yellow]\n"
        )
    return result