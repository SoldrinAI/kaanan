import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import litellm
from rich.console import Console

from kaanan.config import KaananConfig

console = Console()


# ---------------------------------------------------------------------------
# Fast-skip extensions — classify Non-Code without an LLM call
# ---------------------------------------------------------------------------

_FAST_SKIP: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".pdf", ".docx", ".xlsx", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".lock", ".sum",
    ".toml", ".cfg", ".ini", ".env", ".envrc",
    ".yaml", ".yml",
    ".md", ".rst", ".txt",
    ".gitignore", ".dockerignore", ".editorconfig",
    ".prettierrc", ".eslintrc", ".babelrc",
    ".nvmrc", ".python-version",
})

# Default extensions when no kaanan_whitelist.txt is present.
# Broader than the SAST default to include frontend file types.
DOC_DEFAULT_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".java", ".go", ".php", ".rb", ".cs", ".cpp", ".c",
    ".tsx", ".jsx", ".vue", ".html", ".svelte",
    ".dart", ".swift", ".kt",
})


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class BackendEndpoint:
    method: str
    path: str
    authentication: str
    request_payload: str
    response_scenarios: str
    curl_command: str


@dataclass
class FrontendElement:
    name: str
    selector_type: str
    selector_value: str
    validation: str


@dataclass
class UserFlow:
    trigger: str
    resulting_state: str


@dataclass
class APIBinding:
    action: str
    target_endpoint: str


@dataclass
class FrontendDoc:
    screen_name: str
    route: str
    elements: list[FrontendElement] = field(default_factory=list)
    user_flows: list[UserFlow] = field(default_factory=list)
    api_bindings: list[APIBinding] = field(default_factory=list)


@dataclass
class DocFileResult:
    filepath: str
    classification: str   # "Backend" | "Frontend-Web" | "Frontend-App" | "Non-Code" | "Error"
    endpoints: list[BackendEndpoint] = field(default_factory=list)
    frontend: Optional[FrontendDoc] = None
    error: Optional[str] = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    model: str = ""


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert Codebase Architecture Analyzer and UAT Technical Writer.

TASK: Classify the provided source file and extract structured UAT documentation from it.

OUTPUT RULES:
1. Return ONLY a valid JSON object. Zero markdown, zero prose, zero code fences.
2. Determine the classification first, then extract according to its schema.

CLASSIFICATION DEFINITIONS:
- "Non-Code"      : Not executable source code. Includes images, lockfiles, config files
                    (.toml, .yaml, .env, .ini), documentation (.md, .txt), ignore files.
- "Backend"       : Server-side source code containing routing, HTTP handlers, database
                    queries, or core business logic (.py, .java, .go, server-side .js/.ts).
- "Frontend-Web"  : Client-side web code. React/Vue/Angular components, HTML templates,
                    DOM manipulation (.tsx, .jsx, .vue, .html, .svelte).
- "Frontend-App"  : Mobile application source. React Native, Flutter, Swift, or Kotlin
                    files with mobile UI primitives (.dart, .swift, .kt).

SCHEMA -- NON-CODE:
{"classification": "Non-Code"}

SCHEMA -- BACKEND:
{
  "classification": "Backend",
  "endpoints": [
    {
      "method": "PUT",
      "path": "/api/users/{user_id}/profile",
      "authentication": "JWT required - Bearer token",
      "request_payload": "display_name (string, optional), avatar_url (string, optional, valid URL)",
      "response_scenarios": "200 OK: {user: object}. 401: Missing or invalid token. 422: Validation error with field details.",
      "curl_command": "curl -X PUT https://api.example.com/api/users/42/profile -H 'Content-Type: application/json' -H 'Authorization: Bearer <token>' -d '{\"display_name\":\"Alice\"}'"
    }
  ]
}

SCHEMA -- FRONTEND-WEB or FRONTEND-APP:
{
  "classification": "Frontend-Web",
  "screen_name": "Login Page",
  "route": "/login",
  "elements": [
    {
      "name": "Email Input",
      "selector_type": "data-testid",
      "selector_value": "login-email-input",
      "validation": "Required, valid email format, max 255 chars"
    },
    {
      "name": "Submit Button",
      "selector_type": "data-testid",
      "selector_value": "login-submit-btn",
      "validation": "Disabled until all required fields are filled"
    }
  ],
  "user_flows": [
    {
      "trigger": "User submits form with valid credentials",
      "resulting_state": "Redirected to /dashboard. Auth token stored in localStorage."
    },
    {
      "trigger": "User submits form with invalid credentials",
      "resulting_state": "Error banner displayed: 'Invalid email or password'."
    }
  ],
  "api_bindings": [
    {
      "action": "Submit Login Form (onClick of login-submit-btn)",
      "target_endpoint": "POST /api/users/login"
    }
  ]
}

ACCURACY RULES:
- Extract ALL endpoints from backend files. A file with 5 routes must return all 5 endpoints.
- PATH VERBATIM RULE (critical): The "path" field MUST be copied CHARACTER-FOR-CHARACTER from
  the route decorator or annotation as it appears in the source code.
  NEVER shorten, simplify, merge, guess, or infer a path.
  If the decorator says @router.put("/api/users/{user_id}/profile"), the path is
  exactly "/api/users/{user_id}/profile" — NOT "/api/users/{user_id}", NOT "/api/users/profile".
  If the decorator says @app.get("/api/files/download"), the path is "/api/files/download"
  — NOT "/api/download", NOT "/files/download".
  Preserve every path segment, every path parameter name, and every sub-resource segment.
- PATH PARAMETER RULE: Keep path parameters in their original brace/colon notation exactly
  as written. {user_id} stays {user_id}. :id stays :id. Do NOT substitute real values.
- NO INFERENCE: Do not invent or guess paths that are not explicitly present in the source
  code of THIS file. If a path is constructed dynamically or imported from another module
  and cannot be read directly, omit that endpoint entirely.
- Selector priority: data-testid > accessibilityIdentifier > id > className > element type.
  If no usable selector exists, set selector_value to "No selector defined".
- If a frontend API endpoint cannot be statically resolved from the code, use
  target_endpoint: "Dynamic/Unknown Target".
- Authentication: detect JWT middleware, decorators (@login_required, @requires_auth),
  guards (AuthGuard), session checks, or role annotations.
  If none detected, use "None - Public endpoint".
- curl_command: use https://api.example.com as base URL when no actual URL is in the code.
  Substitute "1" for integer path params and "abc123" for string path params in the example URL.
  Always include Content-Type header and a realistic mock request body.
- Include ALL interactive elements: buttons, inputs, dropdowns, checkboxes, sliders, links.
- Use the actual variable names, field names, and constraint values found in the code.
- If a backend file has no route handlers (utility, model, or config file), return:
  {"classification": "Backend", "endpoints": []}

Return the JSON object now."""


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def _parse_doc_response(
    raw: str,
) -> tuple[str, list[BackendEndpoint], Optional[FrontendDoc]]:
    cleaned = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip().rstrip("`")

    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not match:
        raise ValueError(f"No JSON object in LLM response: {raw[:200]}")

    data = json.loads(match.group())
    classification = str(data.get("classification", "Non-Code"))

    endpoints: list[BackendEndpoint] = []
    frontend: Optional[FrontendDoc] = None

    if classification == "Backend":
        for ep in data.get("endpoints", []):
            if not isinstance(ep, dict):
                continue
            endpoints.append(BackendEndpoint(
                method=str(ep.get("method", "GET")).upper(),
                path=str(ep.get("path", "/")),
                authentication=str(ep.get("authentication", "Unknown")),
                request_payload=str(ep.get("request_payload", "None")),
                response_scenarios=str(ep.get("response_scenarios", "")),
                curl_command=str(ep.get("curl_command", "")),
            ))

    elif classification in ("Frontend-Web", "Frontend-App"):
        elements = [
            FrontendElement(
                name=str(e.get("name", "")),
                selector_type=str(e.get("selector_type", "")),
                selector_value=str(e.get("selector_value", "")),
                validation=str(e.get("validation", "None")),
            )
            for e in data.get("elements", [])
            if isinstance(e, dict)
        ]
        user_flows = [
            UserFlow(
                trigger=str(f.get("trigger", "")),
                resulting_state=str(f.get("resulting_state", "")),
            )
            for f in data.get("user_flows", [])
            if isinstance(f, dict)
        ]
        api_bindings = [
            APIBinding(
                action=str(b.get("action", "")),
                target_endpoint=str(b.get("target_endpoint", "")),
            )
            for b in data.get("api_bindings", [])
            if isinstance(b, dict)
        ]
        frontend = FrontendDoc(
            screen_name=str(data.get("screen_name", "Unknown Screen")),
            route=str(data.get("route", "Unknown")),
            elements=elements,
            user_flows=user_flows,
            api_bindings=api_bindings,
        )

    return classification, endpoints, frontend


# ---------------------------------------------------------------------------
# Single-file analyzer
# ---------------------------------------------------------------------------

def analyze_file_doc(
    filepath: Path, relative_path: str, config: KaananConfig,
) -> DocFileResult:
    # Fast-path: binary / purely-informational file — skip LLM entirely
    if filepath.suffix.lower() in _FAST_SKIP:
        return DocFileResult(filepath=relative_path, classification="Non-Code")

    try:
        source_code = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return DocFileResult(
            filepath=relative_path, classification="Error",
            error=f"Could not read file: {exc}",
        )

    if not source_code.strip():
        return DocFileResult(filepath=relative_path, classification="Non-Code")

    user_message = (
        f"File: {relative_path}\n\n"
        "```\n"
        + "\n".join(f"{i+1:4d}  {line}" for i, line in enumerate(source_code.splitlines()))
        + "\n```\n\n"
        "Classify this file and return the UAT documentation JSON now."
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
            max_tokens=8192,
        )
        raw_content: str = response.choices[0].message.content or ""
        classification, endpoints, frontend = _parse_doc_response(raw_content)

        usage          = getattr(response, "usage", None)
        prompt_tok     = getattr(usage, "prompt_tokens",     0) or 0
        completion_tok = getattr(usage, "completion_tokens", 0) or 0

        return DocFileResult(
            filepath=relative_path,
            classification=classification,
            endpoints=endpoints,
            frontend=frontend,
            prompt_tokens=prompt_tok,
            completion_tokens=completion_tok,
            model=config.model,
        )

    except Exception as exc:
        return DocFileResult(
            filepath=relative_path, classification="Error", error=str(exc),
        )


# ---------------------------------------------------------------------------
# Directory collector (doc-specific defaults)
# ---------------------------------------------------------------------------

def _collect_doc_files(target_dir: Path) -> list[Path]:
    SKIP_DIRS = {
        ".git", ".venv", "venv", "node_modules", "__pycache__",
        ".mypy_cache", "dist", "build",
    }
    collected: list[Path] = []
    for path in target_dir.rglob("*"):
        if any(part in SKIP_DIRS or part.startswith(".") for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in DOC_DEFAULT_EXTENSIONS:
            collected.append(path)
    return sorted(collected)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_doc_scan(
    target_dir: Path,
    config: KaananConfig,
    target_file: Optional[Path] = None,
) -> list[DocFileResult]:
    """Scan *target_file* if supplied, otherwise scan *target_dir*.

    Passing *target_file* is preferred for VAPT mode: it restricts analysis
    to the app entry point so that only genuinely registered routes are
    extracted, avoiding false paths from helper/model files.
    """
    if target_file is not None:
        # Single-file mode — bypass whitelist / directory collection entirely
        if not target_file.is_file():
            console.print(f"[yellow]Target file not found: {target_file}[/yellow]")
            return []
        files = [target_file]
        console.print(
            f"\n[bold cyan]Kaanan UAT Doc[/bold cyan] — documenting "
            f"[bold]1[/bold] file ([cyan]{target_file.name}[/cyan]) "
            f"with model [bold]{config.model}[/bold]\n"
        )
    else:
        whitelist_path = Path.cwd() / "kaanan_whitelist.txt"

        if whitelist_path.exists():
            from kaanan.scanner import load_whitelist, collect_files
            whitelist = load_whitelist(whitelist_path)
            files = collect_files(target_dir, whitelist)
        else:
            console.print(
                f"[dim]kaanan_whitelist.txt not found — using doc defaults: "
                f"{', '.join(sorted(DOC_DEFAULT_EXTENSIONS))}[/dim]"
            )
            files = _collect_doc_files(target_dir)

        if not files:
            console.print(f"[yellow]No files found in {target_dir}[/yellow]")
            return []

        console.print(
            f"\n[bold cyan]Kaanan UAT Doc[/bold cyan] — documenting "
            f"[bold]{len(files)}[/bold] file(s) with model [bold]{config.model}[/bold]\n"
        )

    results: list[DocFileResult] = []
    for file_path in files:
        relative = str(file_path.relative_to(target_dir.parent))
        console.print(f"  [dim]->[/dim] Analyzing [cyan]{relative}[/cyan]...", end=" ")

        result = analyze_file_doc(file_path, relative, config)

        if result.classification == "Error":
            console.print(f"[red]ERROR[/red] ({(result.error or '')[:60]})")
        elif result.classification == "Non-Code":
            console.print("[dim]Non-Code — skipped[/dim]")
        elif result.classification == "Backend":
            ep_count = len(result.endpoints)
            if ep_count:
                console.print(f"[blue]Backend[/blue] — [bold]{ep_count}[/bold] endpoint(s)")
            else:
                console.print("[blue]Backend[/blue] — [dim]no route handlers[/dim]")
        else:
            label  = result.classification.replace("Frontend-", "")
            screen = result.frontend.screen_name if result.frontend else "?"
            console.print(f"[magenta]{label}[/magenta] — {screen}")

        results.append(result)

    return results