from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint

app = typer.Typer(
    name="kaanan",
    help="Kaanan — AI-driven SAST, UAT documentation, and VAPT tool.",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()


# ============================================================================
# Setup guide
# ============================================================================

def _print_setup_guide() -> None:
    console.print()
    console.print(Panel.fit(
        "[bold cyan]Kaanan[/bold cyan] — AI-driven SAST, UAT Documentation & VAPT\n"
        "[dim]Powered by LiteLLM. Works with OpenAI, Anthropic, Ollama, and more.[/dim]",
        border_style="cyan",
    ))

    console.print("""
[bold white]QUICK START[/bold white]
[dim]─────────────────────────────────────────────────────────────────[/dim]

  [bold]Step 1[/bold]  Install Kaanan
    [cyan]pip install kaanan[/cyan]

  [bold]Step 2[/bold]  Create a [bold].env[/bold] file in your project root
    [cyan]kaanan init[/cyan]

  [bold]Step 3[/bold]  Run a SAST scan
    [cyan]kaanan scan --dir ./src[/cyan]
    [cyan]kaanan scan --dir .   --output ./reports/security.pdf[/cyan]

  [bold]Step 4[/bold]  Generate UAT documentation
    [cyan]kaanan document scan --dir ./src[/cyan]
    [cyan]kaanan document scan --dir . --output ./reports/uat.pdf[/cyan]

  [bold]Step 5[/bold]  Run VAPT against your live application
    [dim]1. Start your application (e.g. python app.py)[/dim]
    [dim]2. Add VAPT vars to your .env (see below)[/dim]
    [cyan]kaanan vapt --dir ./src[/cyan]
    [cyan]kaanan vapt --dir . --output ./reports/vapt.pdf[/cyan]

  [bold]Step 6[/bold]  Run the full pipeline (SAST + UAT + VAPT in one command)
    [dim]1. Start your application (e.g. python app.py)[/dim]
    [dim]2. Ensure all VAPT vars are set in .env (see below)[/dim]
    [cyan]kaanan run pipeline --dir ./src[/cyan]
    [cyan]kaanan run pipeline --dir . --output-dir ./reports[/cyan]
    [cyan]kaanan run pipeline --dir ./src --skip-vapt[/cyan]  [dim]# SAST + UAT only[/dim]

  [bold]Step 7[/bold]  Open the PDF reports
    [dim]SAST default output:[/dim]  [cyan]kaanan_report.pdf[/cyan]
    [dim]UAT default output:[/dim]   [cyan]kaanan_uat_report.pdf[/cyan]
    [dim]VAPT default output:[/dim]  [cyan]kaanan_vapt_report.pdf[/cyan]

[bold white]SUPPORTED LLM PROVIDERS[/bold white]
[dim]─────────────────────────────────────────────────────────────────[/dim]

  Provider        KAANAN_MODEL value
  ──────────────  ─────────────────────────────────────────────
  OpenAI          [cyan]gpt-4o[/cyan]  /  [cyan]gpt-4o-mini[/cyan]  /  [cyan]gpt-4-turbo[/cyan]
  Anthropic       [cyan]claude-3-5-sonnet-20241022[/cyan]  /  [cyan]claude-3-opus-20240229[/cyan]
  Google          [cyan]gemini/gemini-1.5-pro[/cyan]
  Local (Ollama)  [cyan]ollama/llama3[/cyan]  /  [cyan]ollama/mistral[/cyan]
  Azure OpenAI    [cyan]azure/your-deployment-name[/cyan]
  AWS Bedrock     [cyan]bedrock/anthropic.claude-3-sonnet[/cyan]

  [dim]Full provider list: https://docs.litellm.ai/docs/providers[/dim]

[bold white].ENV FILE FORMAT[/bold white]
[dim]─────────────────────────────────────────────────────────────────[/dim]

  [dim]# Required for all modes:[/dim]
  [cyan]KAANAN_API_KEY=sk-...[/cyan]            [dim]# Your provider API key[/dim]
  [cyan]KAANAN_MODEL=gpt-4o[/cyan]              [dim]# LiteLLM model string[/dim]

  [dim]# Required for VAPT only:[/dim]
  [cyan]KAANAN_TARGET_IP=127.0.0.1[/cyan]       [dim]# IP where your app is running[/dim]
  [cyan]KAANAN_TARGET_PORT=5000[/cyan]           [dim]# Port your app listens on[/dim]
  [cyan]KAANAN_TARGET_FILE=app.py[/cyan]         [dim]# Entry-point file (e.g. app.py, index.js)[/dim]
  [cyan]KAANAN_MAX_TOKENS_PER_API=5000[/cyan]    [dim]# Token budget per endpoint[/dim]

  [dim]The .env file must be in the directory where you run kaanan.[/dim]

[bold white]WHITELIST (OPTIONAL)[/bold white]
[dim]─────────────────────────────────────────────────────────────────[/dim]

  Create [cyan]kaanan_whitelist.txt[/cyan] to control which file types are scanned.
  One extension per line. If absent, Kaanan uses per-mode defaults.

  SAST defaults:  [dim].py  .js  .ts  .java  .go  .php  .rb  .cs  .cpp  .c[/dim]
  UAT defaults:   [dim]All SAST defaults plus .tsx .jsx .vue .html .dart .swift .kt[/dim]
  VAPT defaults:  [dim]Same as UAT defaults (VAPT runs doc scan internally)[/dim]

[bold white]SAST REPORT[/bold white]
[dim]─────────────────────────────────────────────────────────────────[/dim]

  Output is a self-contained PDF with:
  * Severity summary (CRITICAL / HIGH / MEDIUM / LOW counts)
  * Per-file findings with CWE ID and OWASP Top 10 category
  * Exact vulnerable code snippet with line highlighting
  * Impact assessment and actionable remediation per finding

[bold white]UAT DOCUMENTATION REPORT[/bold white]
[dim]─────────────────────────────────────────────────────────────────[/dim]

  Output is a self-contained PDF with:
  * File classification (Backend / Frontend-Web / Frontend-App / Non-Code)
  * Backend: all endpoint routes, auth, request/response details, executable cURL
  * Frontend: screen identity, testable element selectors, user flows, API bindings

[bold white]VAPT REPORT[/bold white]
[dim]─────────────────────────────────────────────────────────────────[/dim]

  The VAPT agent requires your application to be running before you invoke it.
  It performs two phases automatically:
    [dim]Phase 1[/dim]  Runs the doc scanner to extract the live API surface from source.
    [dim]Phase 2[/dim]  Attacks each discovered endpoint with targeted payloads and
             confirms vulnerabilities using live HTTP response analysis.

  Covers: SQLi, NoSQLi, BOLA/IDOR, Broken Auth, Command Injection, Path
  Traversal, SSRF, XSS, Mass Assignment, and Sensitive Data Exposure.

  Output PDF includes:
  * Target summary and overall risk rating
  * Per-endpoint: baseline status, attacks fired, budget usage
  * Confirmed finding cards: evidence, impact, attack payload, remediation

[bold white]COMMANDS[/bold white]
[dim]─────────────────────────────────────────────────────────────────[/dim]

  [cyan]kaanan --help[/cyan]                     Show this guide
  [cyan]kaanan init[/cyan]                       Scaffold .env + kaanan_whitelist.txt
  [cyan]kaanan scan --help[/cyan]               Show SAST scan options
  [cyan]kaanan scan --dir PATH[/cyan]           Run a full SAST scan
  [cyan]kaanan document scan --help[/cyan]      Show UAT doc scan options
  [cyan]kaanan document scan --dir PATH[/cyan]  Generate UAT documentation
  [cyan]kaanan vapt --help[/cyan]               Show VAPT options
  [cyan]kaanan vapt --dir PATH[/cyan]           Run VAPT against a live application
  [cyan]kaanan run pipeline --dir PATH[/cyan]   Run SAST + UAT + VAPT in one command

[bold white]EXAMPLES[/bold white]
[dim]─────────────────────────────────────────────────────────────────[/dim]

  [dim]# SAST — scan your entire project[/dim]
  [cyan]kaanan scan --dir .[/cyan]

  [dim]# UAT — document all backend and frontend files[/dim]
  [cyan]kaanan document scan --dir ./src[/cyan]

  [dim]# VAPT — start your app first, then run[/dim]
  [cyan]kaanan vapt --dir ./src[/cyan]

  [dim]# Use a local Ollama model (no API key needed)[/dim]
  [dim]# Set KAANAN_MODEL=ollama/llama3 in .env, KAANAN_API_KEY=dummy[/dim]
  [cyan]kaanan scan --dir ./src[/cyan]
""")
    console.print(Panel(
        """[bold yellow]  IMPORTANT — PLEASE READ BEFORE USE[/bold yellow]

  [bold white]Data Privacy[/bold white]
  Kaanan does [bold]not[/bold] collect, store, transmit, or log your source code.
  Your code never touches Kaanan\'s servers. All processing is local.

  [bold white]Third-Party LLM Risk[/bold white]
  Kaanan sends your source code directly to the LLM provider you configure
  (e.g. OpenAI, Anthropic, Google). Kaanan has no control over how those
  providers handle your data. Many commercial API tiers [bold]may use your
  inputs to train or improve their models[/bold] by default.

  Before scanning production or proprietary code, you are strongly advised to:
    [cyan]*[/cyan] Review your LLM provider\'s data usage and privacy policy
    [cyan]*[/cyan] Opt out of training data collection if your provider offers it
    [cyan]*[/cyan] Use an enterprise or zero-data-retention API tier
    [cyan]*[/cyan] Use a local model (e.g. [cyan]ollama/llama3[/cyan]) for maximum privacy

  [bold white]VAPT Authorisation[/bold white]
  The VAPT agent fires real HTTP attack payloads against a live server.
  [bold]Only run it against applications you own or have explicit written
  authorisation to test.[/bold] Unauthorised testing is illegal.

  [bold white]Acceptance of Risk[/bold white]
  By installing and using Kaanan, you acknowledge and accept all risks
  associated with transmitting your source code to third-party LLM providers.
  Kaanan and its authors accept no liability for data exposure, model training
  on your code, or any consequences thereof.""",
        title="[bold yellow]DISCLAIMER[/bold yellow]",
        border_style="yellow",
        padding=(0, 2),
    ))


# ============================================================================
# Root app callbacks
# ============================================================================

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """
    [bold cyan]Kaanan[/bold cyan] — AI-driven SAST, UAT documentation, and VAPT tool.

    Run [bold]kaanan --help[/bold] for the full setup guide.
    Run [bold]kaanan scan --help[/bold] for SAST options.
    Run [bold]kaanan document scan --help[/bold] for UAT documentation options.
    Run [bold]kaanan vapt --help[/bold] for VAPT options.
    Run [bold]kaanan run pipeline --help[/bold] for pipeline options.
    """
    if ctx.invoked_subcommand is None:
        _print_setup_guide()


# ============================================================================
# kaanan scan
# ============================================================================

@app.command()
def scan(
    directory: Path = typer.Option(
        ...,
        "--dir", "-d",
        help="Target directory to scan. Must exist.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    output: Path = typer.Option(
        Path("kaanan_report.pdf"),
        "--output", "-o",
        help="Output path for the PDF report. Default: kaanan_report.pdf",
    ),
):
    """
    [bold cyan]Scan[/bold cyan] a directory for security vulnerabilities using AI-powered SAST.

    Reads [bold]KAANAN_API_KEY[/bold] and [bold]KAANAN_MODEL[/bold] from a [bold].env[/bold] file
    in your current working directory.

    [dim]Examples:[/dim]
      kaanan scan --dir ./src
      kaanan scan --dir .
      kaanan scan --dir ./src --output ./reports/security.pdf
    """
    from kaanan.config import load_config

    try:
        config = load_config()
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"\n[bold red]Config Error:[/bold red] {exc}\n")
        console.print("[dim]Run [cyan]kaanan --help[/cyan] for setup instructions.[/dim]\n")
        raise typer.Exit(code=1)

    from kaanan.scanner import run_scan

    try:
        results = run_scan(target_dir=directory, config=config)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"\n[bold red]Scan Error:[/bold red] {exc}\n")
        raise typer.Exit(code=1)

    if not results:
        console.print("[yellow]No files were scanned. Check your whitelist or directory.[/yellow]")
        raise typer.Exit(code=0)

    from kaanan.report import generate_report

    try:
        generate_report(results=results, output_path=output)
    except Exception as exc:
        console.print(f"\n[bold red]Report Error:[/bold red] {exc}\n")
        raise typer.Exit(code=1)

    total_vulns = sum(len(r.vulnerabilities) for r in results)
    console.print(
        f"\n[bold green]Scan complete.[/bold green] "
        f"[bold]{total_vulns}[/bold] issue(s) found across "
        f"[bold]{len(results)}[/bold] file(s)."
    )
    console.print(f"[bold]Report:[/bold] [cyan]{output.resolve()}[/cyan]\n")


# ============================================================================
# kaanan init
# ============================================================================

@app.command()
def init():
    """
    Scaffold a [bold].env[/bold] and [bold]kaanan_whitelist.txt[/bold] in the current directory.

    Safe to run multiple times — will not overwrite existing files.
    """
    env_path       = Path.cwd() / ".env"
    whitelist_path = Path.cwd() / "kaanan_whitelist.txt"

    console.print()
    if not env_path.exists():
        env_path.write_text(
            "# ── LLM Configuration (required for all modes) ─────────────────────\n"
            "KAANAN_API_KEY=your_api_key_here\n"
            "KAANAN_MODEL=gpt-4o\n"
            "# Anthropic: KAANAN_MODEL=claude-3-5-sonnet-20241022\n"
            "# Ollama:    KAANAN_MODEL=ollama/llama3  (set API_KEY=dummy)\n"
            "# Azure:     KAANAN_MODEL=azure/your-deployment\n"
            "\n"
            "# ── VAPT Configuration (required for kaanan vapt) ───────────────────\n"
            "# Start your application before running kaanan vapt or kaanan run pipeline.\n"
            "# KAANAN_TARGET_IP=127.0.0.1\n"
            "# KAANAN_TARGET_PORT=5000\n"
            "# KAANAN_TARGET_FILE=app.py\n"
            "# KAANAN_MAX_TOKENS_PER_API=10000\n"
            "#\n"
            "# Optional: supply test credentials for auto-authentication.\n"
            "# The VAPT agent will log in, obtain a real token, and use it to\n"
            "# test protected endpoints (IDOR, broken auth, mass assignment).\n"
            "# KAANAN_TEST_USERNAME=admin\n"
            "# KAANAN_TEST_PASSWORD=admin123\n",
            encoding="utf-8",
        )
        console.print(f"  [green]Created[/green]  {env_path}")
    else:
        console.print(f"  [yellow]Skipped[/yellow]  {env_path} (already exists)")

    if not whitelist_path.exists():
        whitelist_path.write_text(
            "# File extensions Kaanan will scan. One per line.\n"
            "# Lines starting with # are ignored.\n"
            "# SAST defaults: .py .js .ts .java .go .php .rb .cs\n"
            "# UAT / VAPT defaults also include: .tsx .jsx .vue .html .dart .swift .kt\n"
            ".py\n.js\n.ts\n.java\n.go\n.php\n.rb\n.cs\n"
            ".tsx\n.jsx\n.vue\n.html\n.dart\n.swift\n.kt\n",
            encoding="utf-8",
        )
        console.print(f"  [green]Created[/green]  {whitelist_path}")
    else:
        console.print(f"  [yellow]Skipped[/yellow]  {whitelist_path} (already exists)")

    console.print("""
  [bold]Next steps:[/bold]

    1. Open [cyan].env[/cyan] and set your real [bold]KAANAN_API_KEY[/bold] and [bold]KAANAN_MODEL[/bold]
    2. Optionally edit [cyan]kaanan_whitelist.txt[/cyan] for your stack
    3. SAST scan:   [bold cyan]kaanan scan --dir ./src[/bold cyan]
    4. UAT docs:    [bold cyan]kaanan document scan --dir ./src[/bold cyan]
    5. VAPT:        [bold cyan]kaanan vapt --dir ./src[/bold cyan]
       [dim](Uncomment and set the VAPT vars in .env first, then start your app)[/dim]
    6. Pipeline:    [bold cyan]kaanan run pipeline --dir ./src[/bold cyan]
       [dim](Runs SAST + UAT + VAPT in sequence, saving each report as it completes)[/dim]
       [dim](For pipeline + VAPT: uncomment the VAPT vars in .env and start your app first)[/dim]
       [dim](For pipeline without VAPT: use --skip-vapt flag)[/dim]

  [dim]Need help? Run:[/dim] [cyan]kaanan --help[/cyan]
""")


# ============================================================================
# kaanan document  (sub-app)
# ============================================================================

document_app = typer.Typer(
    name="document",
    help="UAT documentation generation commands.",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)
app.add_typer(document_app, name="document")


@document_app.command("scan")
def document_scan(
    directory: Path = typer.Option(
        ...,
        "--dir", "-d",
        help="Target directory to document. Must exist.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    output: Path = typer.Option(
        Path("kaanan_uat_report.pdf"),
        "--output", "-o",
        help="Output path for the UAT PDF. Default: kaanan_uat_report.pdf",
    ),
):
    """
    [bold cyan]Document[/bold cyan] a directory by generating structured UAT documentation.

    Classifies each file as [bold]Backend[/bold], [bold]Frontend-Web[/bold],
    [bold]Frontend-App[/bold], or [bold]Non-Code[/bold], then extracts:

    [dim]Backend   :[/dim]  Endpoint routes, authentication, request/response, executable cURL
    [dim]Frontend  :[/dim]  Screen identity, element selectors, user flows, API bindings
    [dim]Non-Code  :[/dim]  Skipped automatically (no LLM call)

    Reads [bold]KAANAN_API_KEY[/bold] and [bold]KAANAN_MODEL[/bold] from a [bold].env[/bold] file
    in your current working directory.

    [dim]Examples:[/dim]
      kaanan document scan --dir ./src
      kaanan document scan --dir .
      kaanan document scan --dir ./src --output ./reports/uat.pdf
    """
    from kaanan.config import load_config

    try:
        config = load_config()
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"\n[bold red]Config Error:[/bold red] {exc}\n")
        console.print("[dim]Run [cyan]kaanan --help[/cyan] for setup instructions.[/dim]\n")
        raise typer.Exit(code=1)

    from kaanan.doc_scanner import run_doc_scan

    try:
        results = run_doc_scan(target_dir=directory, config=config)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"\n[bold red]Scan Error:[/bold red] {exc}\n")
        raise typer.Exit(code=1)

    if not results:
        console.print("[yellow]No files were found. Check your whitelist or directory.[/yellow]")
        raise typer.Exit(code=0)

    from kaanan.doc_report import generate_doc_report

    try:
        generate_doc_report(results=results, output_path=output)
    except Exception as exc:
        console.print(f"\n[bold red]Report Error:[/bold red] {exc}\n")
        raise typer.Exit(code=1)

    total_endpoints = sum(len(r.endpoints) for r in results)
    total_screens   = sum(1 for r in results if r.frontend is not None)
    console.print(
        f"\n[bold green]Documentation complete.[/bold green] "
        f"[bold]{total_endpoints}[/bold] endpoint(s) and "
        f"[bold]{total_screens}[/bold] UI screen(s) documented across "
        f"[bold]{len(results)}[/bold] file(s)."
    )
    console.print(f"[bold]Report:[/bold] [cyan]{output.resolve()}[/cyan]\n")


# ============================================================================
# kaanan vapt
# ============================================================================

@app.command()
def vapt(
    directory: Path = typer.Option(
        ...,
        "--dir", "-d",
        help="Directory containing the application source code. Must exist.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    output: Path = typer.Option(
        Path("kaanan_vapt_report.pdf"),
        "--output", "-o",
        help="Output path for the VAPT PDF report. Default: kaanan_vapt_report.pdf",
    ),
):
    """
    [bold cyan]VAPT[/bold cyan] — run a full Vulnerability Assessment & Penetration Test
    against a live running application.

    [bold yellow]Your application must be running before invoking this command.[/bold yellow]

    The agent automatically:
      [dim]1.[/dim] Runs the doc scanner to extract the full API surface from source.
      [dim]2.[/dim] Fires a baseline request at each discovered endpoint.
      [dim]3.[/dim] Generates context-aware attack payloads using the LLM.
      [dim]4.[/dim] Fires each payload and analyses live HTTP responses for confirmed
         vulnerabilities (SQLi, BOLA/IDOR, Broken Auth, SSRF, XSS, and more).
      [dim]5.[/dim] Writes a structured VAPT PDF report with evidence and remediation.

    Required [bold].env[/bold] keys (in addition to KAANAN_API_KEY / KAANAN_MODEL):
      [cyan]KAANAN_TARGET_IP[/cyan]           IP where your app is running (e.g. 127.0.0.1)
      [cyan]KAANAN_TARGET_PORT[/cyan]         Port your app listens on (e.g. 5000)
      [cyan]KAANAN_TARGET_FILE[/cyan]         Entry-point file (e.g. app.py or index.js)
      [cyan]KAANAN_MAX_TOKENS_PER_API[/cyan]  LLM token budget per endpoint (e.g. 5000)

    [bold red]Only test applications you own or have explicit written authorisation
    to test. Unauthorised testing is illegal.[/bold red]

    [dim]Examples:[/dim]
      kaanan vapt --dir ./src
      kaanan vapt --dir .
      kaanan vapt --dir ./src --output ./reports/vapt.pdf
    """
    from kaanan.config import load_vapt_config

    try:
        config = load_vapt_config()
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"\n[bold red]Config Error:[/bold red] {exc}\n")
        console.print(
            "[dim]Ensure your .env contains KAANAN_TARGET_IP, KAANAN_TARGET_PORT, "
            "KAANAN_TARGET_FILE, and KAANAN_MAX_TOKENS_PER_API.\n"
            "Run [cyan]kaanan init[/cyan] to scaffold a template.[/dim]\n"
        )
        raise typer.Exit(code=1)

    # Authorisation acknowledgement
    console.print()
    console.print(Panel(
        "[bold yellow]AUTHORISATION REQUIRED[/bold yellow]\n\n"
        f"  Target : [bold]{config.base_url}[/bold]\n"
        f"  File   : [bold]{config.target_file}[/bold]\n\n"
        "  By proceeding you confirm that you own or have explicit written\n"
        "  authorisation to perform penetration testing on this target.\n"
        "  Kaanan accepts no liability for unauthorised use.",
        border_style="yellow",
        padding=(0, 2),
    ))

    proceed = typer.confirm("  Confirm and start VAPT?", default=False)
    if not proceed:
        console.print("[yellow]VAPT cancelled.[/yellow]\n")
        raise typer.Exit(code=0)

    from kaanan.vapt_scanner import run_vapt_scan

    try:
        result = run_vapt_scan(target_dir=directory, config=config)
    except Exception as exc:
        console.print(f"\n[bold red]VAPT Error:[/bold red] {exc}\n")
        raise typer.Exit(code=1)

    if not result.endpoint_results:
        console.print(
            "[yellow]No endpoints were tested. "
            "Check that your source directory contains backend files "
            "and that your application is running.[/yellow]"
        )
        raise typer.Exit(code=0)

    from kaanan.vapt_report import generate_vapt_report

    try:
        generate_vapt_report(result=result, output_path=output)
    except Exception as exc:
        console.print(f"\n[bold red]Report Error:[/bold red] {exc}\n")
        raise typer.Exit(code=1)

    total_findings = sum(len(ep.findings) for ep in result.endpoint_results)
    total_attacks  = sum(ep.attacks_fired for ep in result.endpoint_results)
    console.print(
        f"\n[bold green]VAPT complete.[/bold green] "
        f"[bold]{total_findings}[/bold] confirmed finding(s) from "
        f"[bold]{total_attacks}[/bold] attack(s) across "
        f"[bold]{len(result.endpoint_results)}[/bold] endpoint(s). "
        f"[dim]{result.total_tokens_used:,} tokens used.[/dim]"
    )
    console.print(f"[bold]Report:[/bold] [cyan]{output.resolve()}[/cyan]\n")

# ============================================================================
# kaanan run pipeline
# ============================================================================

pipeline_app = typer.Typer(
    name="run",
    help="Orchestrated multi-agent pipeline commands.",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)
app.add_typer(pipeline_app, name="run")


@pipeline_app.command("pipeline")
def run_pipeline(
    directory: Path = typer.Option(
        ...,
        "--dir", "-d",
        help="Directory containing the application source code. Must exist.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    output_dir: Path = typer.Option(
        Path("."),
        "--output-dir", "-o",
        help="Directory where all three reports are saved. Default: current directory.",
    ),
    sast_report: str = typer.Option(
        "kaanan_report.pdf",
        "--sast-report",
        help="Filename for the SAST PDF report.",
    ),
    doc_report: str = typer.Option(
        "kaanan_uat_report.pdf",
        "--doc-report",
        help="Filename for the UAT documentation PDF report.",
    ),
    vapt_report: str = typer.Option(
        "kaanan_vapt_report.pdf",
        "--vapt-report",
        help="Filename for the VAPT PDF report.",
    ),
    skip_vapt: bool = typer.Option(
        False,
        "--skip-vapt",
        help="Run only SAST + UAT documentation, skip VAPT.",
    ),
):
    """
    [bold cyan]Pipeline[/bold cyan] — run all three Kaanan agents in sequence.

    [bold]Stage 1[/bold]  [cyan]SAST[/cyan]          — static vulnerability scan, report saved immediately.
    [bold]Stage 2[/bold]  [cyan]UAT Document[/cyan]  — API surface extraction, report saved immediately.
    [bold]Stage 3[/bold]  [cyan]VAPT[/cyan]          — live penetration test using SAST + UAT results,
                         report saved immediately. Skipped if [bold]--skip-vapt[/bold] is set.

    VAPT reuses the SAST findings and UAT endpoint map produced in Stages 1-2,
    so no work is repeated. Each report is written to disk as soon as its stage
    completes — a crash in Stage 3 still gives you the SAST and UAT reports.

    Required [bold].env[/bold] keys for all stages:
      [cyan]KAANAN_API_KEY[/cyan]   and   [cyan]KAANAN_MODEL[/cyan]

    Additional [bold].env[/bold] keys required for VAPT (Stage 3):
      [cyan]KAANAN_TARGET_IP[/cyan]           IP where your app is running
      [cyan]KAANAN_TARGET_PORT[/cyan]         Port your app listens on
      [cyan]KAANAN_TARGET_FILE[/cyan]         Entry-point file (e.g. app.py)
      [cyan]KAANAN_MAX_TOKENS_PER_API[/cyan]  Token budget per endpoint

    [bold red]Only test applications you own or have explicit written authorisation
    to test. Unauthorised testing is illegal.[/bold red]

    [dim]Examples:[/dim]
      kaanan run pipeline --dir ./src
      kaanan run pipeline --dir . --output-dir ./reports
      kaanan run pipeline --dir ./src --skip-vapt
    """
    from kaanan.config import load_config, load_vapt_config

    # ── Config ────────────────────────────────────────────────────────────────
    try:
        base_config = load_config()
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"\n[bold red]Config Error:[/bold red] {exc}\n")
        console.print("[dim]Run [cyan]kaanan --help[/cyan] for setup instructions.[/dim]\n")
        raise typer.Exit(code=1)

    vapt_config = None
    if not skip_vapt:
        try:
            vapt_config = load_vapt_config()
        except (FileNotFoundError, ValueError) as exc:
            console.print(
                f"\n[bold yellow]VAPT Config Warning:[/bold yellow] {exc}\n"
                "[dim]VAPT stage will be skipped. "
                "Add the missing .env keys and re-run to include it.[/dim]\n"
            )
            skip_vapt = True

    output_dir.mkdir(parents=True, exist_ok=True)
    sast_path = output_dir / sast_report
    doc_path  = output_dir / doc_report
    vapt_path = output_dir / vapt_report

    # ── Banner ────────────────────────────────────────────────────────────────
    console.print()
    console.print(Panel.fit(
        "[bold cyan]Kaanan Pipeline[/bold cyan]\n"
        f"[dim]Directory : {directory}[/dim]\n"
        f"[dim]Reports   : {output_dir.resolve()}[/dim]\n"
        + (
            f"[dim]Target    : {vapt_config.base_url}[/dim]"
            if vapt_config else
            "[dim]VAPT      : skipped[/dim]"
        ),
        border_style="cyan",
    ))

    if not skip_vapt:
        console.print()
        console.print(Panel(
            "[bold yellow]AUTHORISATION REQUIRED[/bold yellow]\n\n"
            f"  Target : [bold]{vapt_config.base_url}[/bold]\n"
            f"  File   : [bold]{vapt_config.target_file}[/bold]\n\n"
            "  Stage 3 will fire real HTTP attack payloads against a live server.\n"
            "  By proceeding you confirm that you own or have explicit written\n"
            "  authorisation to perform penetration testing on this target.\n"
            "  Kaanan accepts no liability for unauthorised use.",
            border_style="yellow",
            padding=(0, 2),
        ))
        proceed = typer.confirm("  Confirm and start pipeline?", default=False)
        if not proceed:
            console.print("[yellow]Pipeline cancelled.[/yellow]\n")
            raise typer.Exit(code=0)

    # =========================================================================
    # Stage 1 — SAST
    # =========================================================================
    console.print()
    console.print(Panel.fit(
        "[bold cyan]Stage 1 / 3[/bold cyan]  [white]SAST — Static Application Security Testing[/white]",
        border_style="cyan",
    ))

    from kaanan.scanner import run_scan
    from kaanan.report import generate_report

    try:
        sast_results = run_scan(target_dir=directory, config=base_config)
    except Exception as exc:
        console.print(f"\n[bold red]SAST Error:[/bold red] {exc}\n")
        raise typer.Exit(code=1)

    if not sast_results:
        console.print("[yellow]No files were scanned. Check your whitelist or directory.[/yellow]")
        sast_results = []
    else:
        try:
            generate_report(results=sast_results, output_path=sast_path)
            total_vulns = sum(len(r.vulnerabilities) for r in sast_results)
            console.print(
                f"\n[bold green]Stage 1 complete.[/bold green] "
                f"[bold]{total_vulns}[/bold] issue(s) found across "
                f"[bold]{len(sast_results)}[/bold] file(s).\n"
                f"[bold]Report saved:[/bold] [cyan]{sast_path.resolve()}[/cyan]\n"
            )
        except Exception as exc:
            console.print(f"\n[bold red]SAST Report Error:[/bold red] {exc}\n")
            raise typer.Exit(code=1)

    # =========================================================================
    # Stage 2 — UAT Documentation
    # =========================================================================
    console.print(Panel.fit(
        "[bold cyan]Stage 2 / 3[/bold cyan]  [white]UAT — API Surface Documentation[/white]",
        border_style="cyan",
    ))

    from kaanan.doc_scanner import run_doc_scan
    from kaanan.doc_report import generate_doc_report

    # In pipeline mode, scope the doc scan to the VAPT target file when
    # available so VAPT receives the same precise endpoint map.
    # Falls back to full directory scan when VAPT is skipped or unconfigured.
    doc_target_file = None
    if vapt_config:
        candidate = directory / vapt_config.target_file
        if candidate.exists():
            doc_target_file = candidate

    try:
        doc_results = run_doc_scan(
            target_dir=directory,
            config=base_config,
            target_file=doc_target_file,
        )
    except Exception as exc:
        console.print(f"\n[bold red]UAT Doc Error:[/bold red] {exc}\n")
        raise typer.Exit(code=1)

    if not doc_results:
        console.print("[yellow]No files were documented.[/yellow]")
        doc_results = []
    else:
        try:
            generate_doc_report(results=doc_results, output_path=doc_path)
            total_endpoints = sum(len(r.endpoints) for r in doc_results)
            total_screens   = sum(1 for r in doc_results if r.frontend is not None)
            console.print(
                f"\n[bold green]Stage 2 complete.[/bold green] "
                f"[bold]{total_endpoints}[/bold] endpoint(s) and "
                f"[bold]{total_screens}[/bold] UI screen(s) documented.\n"
                f"[bold]Report saved:[/bold] [cyan]{doc_path.resolve()}[/cyan]\n"
            )
        except Exception as exc:
            console.print(f"\n[bold red]UAT Report Error:[/bold red] {exc}\n")
            raise typer.Exit(code=1)

    # =========================================================================
    # Stage 3 — VAPT
    # =========================================================================
    if skip_vapt:
        console.print(Panel.fit(
            "[bold cyan]Stage 3 / 3[/bold cyan]  [dim]VAPT — skipped[/dim]",
            border_style="dim",
        ))
        console.print(
            "\n[bold green]Pipeline complete.[/bold green] "
            "SAST and UAT reports saved. VAPT was skipped.\n"
        )
        raise typer.Exit(code=0)

    console.print(Panel.fit(
        "[bold cyan]Stage 3 / 3[/bold cyan]  [white]VAPT — Vulnerability Assessment & Penetration Test[/white]",
        border_style="cyan",
    ))

    from kaanan.vapt_scanner import run_vapt_scan
    from kaanan.vapt_report import generate_vapt_report

    try:
        vapt_result = run_vapt_scan(
            target_dir=directory,
            config=vapt_config,
            prefilled_sast_results=sast_results,
            prefilled_doc_results=doc_results,
        )
    except Exception as exc:
        console.print(f"\n[bold red]VAPT Error:[/bold red] {exc}\n")
        raise typer.Exit(code=1)

    if not vapt_result.endpoint_results:
        console.print(
            "[yellow]No endpoints were tested. "
            "Check that your source directory contains backend files "
            "and that your application is running.[/yellow]"
        )
    else:
        try:
            generate_vapt_report(result=vapt_result, output_path=vapt_path)
            total_findings = sum(len(ep.findings) for ep in vapt_result.endpoint_results)
            total_attacks  = sum(ep.attacks_fired for ep in vapt_result.endpoint_results)
            console.print(
                f"\n[bold green]Stage 3 complete.[/bold green] "
                f"[bold]{total_findings}[/bold] confirmed finding(s) from "
                f"[bold]{total_attacks}[/bold] attack(s) across "
                f"[bold]{len(vapt_result.endpoint_results)}[/bold] endpoint(s). "
                f"[dim]{vapt_result.total_tokens_used:,} tokens used.[/dim]\n"
                f"[bold]Report saved:[/bold] [cyan]{vapt_path.resolve()}[/cyan]\n"
            )
        except Exception as exc:
            console.print(f"\n[bold red]VAPT Report Error:[/bold red] {exc}\n")
            raise typer.Exit(code=1)

    # ── Final summary ─────────────────────────────────────────────────────────
    console.print(Panel(
        "[bold green]Pipeline complete.[/bold green]\n\n"
        f"  [dim]SAST report :[/dim] [cyan]{sast_path.resolve()}[/cyan]\n"
        f"  [dim]UAT report  :[/dim] [cyan]{doc_path.resolve()}[/cyan]\n"
        f"  [dim]VAPT report :[/dim] [cyan]{vapt_path.resolve()}[/cyan]",
        border_style="green",
        padding=(0, 2),
    ))