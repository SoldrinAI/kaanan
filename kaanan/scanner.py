import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import litellm
from rich.console import Console

from kaanan.config import KaananConfig

console = Console()

SYSTEM_PROMPT = """You are a senior application security engineer performing expert-level Static Application Security Testing (SAST).

TASK: Analyze the provided source code and identify ALL security vulnerabilities with precision.

OUTPUT RULES:
1. Return ONLY a valid JSON array. Zero markdown, zero prose, zero code fences.
2. If no vulnerabilities exist, return exactly: []
3. Every object MUST contain these exact keys — no extras, no omissions.

REQUIRED KEYS PER VULNERABILITY:
- "severity"     : Exactly one of: "CRITICAL", "HIGH", "MEDIUM", "LOW"
- "type"         : Short vulnerability class, e.g. "SQL Injection", "Hardcoded Secret", "XSS", "Path Traversal", "Command Injection", "Insecure Deserialization", "IDOR", "SSRF", "Broken Authentication"
- "cwe"          : CWE identifier string, e.g. "CWE-89" or "CWE-798"
- "owasp"        : OWASP Top 10 2021 category, e.g. "A03:2021 - Injection" or "A02:2021 - Cryptographic Failures"
- "line"         : Integer. The exact line number in the file (count from 1). Must point to the specific line containing the vulnerability, NOT a comment or blank line above it.
- "code_snippet" : The EXACT text of the vulnerable line(s) of code as it appears in the file. Copy it verbatim from the source. This is used to verify your line number.
- "description"  : 2-3 sentences. Name the SPECIFIC variable, function, parameter, or value that is vulnerable. Explain precisely why it is insecure and what an attacker can do.
- "impact"       : 1-2 sentences. Describe the real-world consequence of exploitation — what data is exposed, what system access is gained, what operations an attacker can perform.
- "remediation"  : Specific, concrete fix using the actual variable/function names from the code. Include a corrected code example where applicable.

SEVERITY DEFINITIONS:
- CRITICAL : Remote code execution, authentication bypass, full system/data compromise
- HIGH     : Injection flaws, privilege escalation, significant data leakage, broken auth
- MEDIUM   : Information disclosure, weak cryptography, insecure configuration, missing controls
- LOW      : Best practice violations, minor misconfigurations, defence-in-depth gaps

LINE NUMBER ACCURACY:
- Count every line from the top of the file starting at 1
- The "line" must point to the actual executable/declarative code line with the flaw
- NEVER point to a comment, docstring, blank line, or section separator
- Cross-verify: the "code_snippet" you provide must literally be the content of that line number

EXAMPLE OUTPUT:
[
  {
    "severity": "HIGH",
    "type": "SQL Injection",
    "cwe": "CWE-89",
    "owasp": "A03:2021 - Injection",
    "line": 42,
    "code_snippet": "    query = f\\"SELECT * FROM users WHERE id = {user_id}\\"",
    "description": "The variable `user_id` from the HTTP request is directly interpolated into the SQL query string on line 42 without sanitization or parameterization. An attacker can inject arbitrary SQL by manipulating the `user_id` parameter.",
    "impact": "An attacker can dump the entire database, bypass authentication, modify or delete records, and potentially execute OS commands via SQL if the DB user has FILE privileges.",
    "remediation": "Replace f-string interpolation with a parameterized query: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)). Never concatenate user input into SQL strings."
  }
]

Analyze every line. Do not skip subtle issues. Return the JSON array now."""


@dataclass
class Vulnerability:
    severity: str
    type: str
    cwe: str
    owasp: str
    line: Optional[int]
    code_snippet: str
    description: str
    impact: str
    remediation: str
    verified_line: Optional[int] = None   # set after snippet search

    VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def __post_init__(self):
        self.severity = self.severity.upper()
        if self.severity not in self.VALID_SEVERITIES:
            self.severity = "LOW"


@dataclass
class FileResult:
    filepath: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    error: Optional[str] = None
    source_lines: list[str] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    model: str = ""


DEFAULT_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".java", ".go",
    ".php", ".rb", ".cs", ".cpp", ".c",
}


def load_whitelist(whitelist_path: Path) -> set[str]:
    if not whitelist_path.exists():
        console.print(
            f"[dim]kaanan_whitelist.txt not found — using default extensions: "
            f"{', '.join(sorted(DEFAULT_EXTENSIONS))}[/dim]"
        )
        return DEFAULT_EXTENSIONS

    extensions: set[str] = set()
    for line in whitelist_path.read_text(encoding="utf-8").splitlines():
        ext = line.strip().lower()
        if ext and not ext.startswith("#"):
            if not ext.startswith("."):
                ext = f".{ext}"
            extensions.add(ext)

    if not extensions:
        console.print("[dim]kaanan_whitelist.txt is empty — using default extensions.[/dim]")
        return DEFAULT_EXTENSIONS

    return extensions


def collect_files(target_dir: Path, whitelist: set[str]) -> list[Path]:
    SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__",
                 ".mypy_cache", "dist", "build"}
    collected: list[Path] = []
    for path in target_dir.rglob("*"):
        if any(part in SKIP_DIRS or part.startswith(".") for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in whitelist:
            collected.append(path)
    return sorted(collected)


def _find_snippet_line(source_lines: list[str], snippet: str) -> Optional[int]:
    """
    Search source_lines for the LLM-provided snippet and return the real line number.
    Tries exact match first, then stripped match, then substring match.
    Returns 1-based line number or None.
    """
    if not snippet or not source_lines:
        return None

    needle = snippet.strip()
    if not needle:
        return None

    # Pass 1: exact stripped match
    for i, line in enumerate(source_lines):
        if line.strip() == needle:
            return i + 1

    # Pass 2: needle is contained in the line
    for i, line in enumerate(source_lines):
        if needle in line:
            return i + 1

    # Pass 3: line is contained in the needle (multi-line snippet, use first line)
    first_needle_line = needle.splitlines()[0].strip()
    if first_needle_line:
        for i, line in enumerate(source_lines):
            if first_needle_line in line:
                return i + 1

    return None


def _parse_vulnerabilities(raw: str, source_lines: list[str]) -> list[Vulnerability]:
    cleaned = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip()
    match = re.search(r"\[.*\]", cleaned, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON array in LLM response: {raw[:200]}")

    data = json.loads(match.group())
    if not isinstance(data, list):
        raise ValueError("LLM returned JSON but not an array.")

    vulns: list[Vulnerability] = []
    for item in data:
        if not isinstance(item, dict):
            continue

        snippet = str(item.get("code_snippet", "")).strip()

        # Verify / correct the LLM's line number using the snippet text
        verified = _find_snippet_line(source_lines, snippet)

        v = Vulnerability(
            severity=str(item.get("severity", "LOW")),
            type=str(item.get("type", "Unknown")),
            cwe=str(item.get("cwe", "")),
            owasp=str(item.get("owasp", "")),
            line=item.get("line") if isinstance(item.get("line"), int) else None,
            code_snippet=snippet,
            description=str(item.get("description", "")),
            impact=str(item.get("impact", "")),
            remediation=str(item.get("remediation", "")),
            verified_line=verified,
        )
        vulns.append(v)
    return vulns


def analyze_file(filepath: Path, relative_path: str, config: KaananConfig) -> FileResult:
    try:
        source_code = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return FileResult(filepath=relative_path, error=f"Could not read file: {exc}")

    source_lines = source_code.splitlines()

    if not source_code.strip():
        return FileResult(filepath=relative_path, source_lines=source_lines)

    user_message = (
        f"File: {relative_path}\n\n"
        "```\n"
        + "\n".join(f"{i+1:4d}  {line}" for i, line in enumerate(source_lines))
        + "\n```\n\n"
        "The code above has line numbers prepended (format: '   N  code'). "
        "Use these to report accurate line numbers. Return the JSON vulnerability array now."
    )

    try:
        response = litellm.completion(
            model=config.model,
            api_key=config.api_key,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_message},
            ],
            temperature=0.0,
            max_tokens=4096,
        )
        raw_content: str = response.choices[0].message.content or ""
        vulns = _parse_vulnerabilities(raw_content, source_lines)
        usage = getattr(response, "usage", None)
        prompt_tok     = getattr(usage, "prompt_tokens",     0) or 0
        completion_tok = getattr(usage, "completion_tokens", 0) or 0
        return FileResult(filepath=relative_path, vulnerabilities=vulns,
                          source_lines=source_lines,
                          prompt_tokens=prompt_tok,
                          completion_tokens=completion_tok,
                          model=config.model)

    except Exception as exc:
        return FileResult(filepath=relative_path, error=str(exc),
                          source_lines=source_lines)


def run_scan(target_dir: Path, config: KaananConfig) -> list[FileResult]:
    whitelist_path = Path.cwd() / "kaanan_whitelist.txt"
    whitelist = load_whitelist(whitelist_path)
    files = collect_files(target_dir, whitelist)

    if not files:
        console.print(f"[yellow]No files matching {whitelist} found in {target_dir}[/yellow]")
        return []

    console.print(
        f"\n[bold cyan]Kaanan SAST[/bold cyan] — scanning "
        f"[bold]{len(files)}[/bold] file(s) with model [bold]{config.model}[/bold]\n"
    )

    results: list[FileResult] = []
    for file_path in files:
        relative = str(file_path.relative_to(target_dir.parent))
        console.print(f"  [dim]->[/dim] Analyzing [cyan]{relative}[/cyan]...", end=" ")

        result = analyze_file(file_path, relative, config)

        if result.error:
            console.print(f"[red]ERROR[/red] ({result.error[:60]})")
        elif not result.vulnerabilities:
            console.print("[green]Clean[/green]")
        else:
            count    = len(result.vulnerabilities)
            critical = sum(1 for v in result.vulnerabilities if v.severity == "CRITICAL")
            high     = sum(1 for v in result.vulnerabilities if v.severity == "HIGH")
            tag = (f"[red]{count} issue(s)"
                   + (f" [{critical}C/{high}H]" if (critical or high) else "")
                   + "[/red]")
            console.print(tag)

        results.append(result)

    return results