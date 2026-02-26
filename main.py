#!/usr/bin/env python3
"""
ai-secrets-scanner: AI-powered secrets and credential scanner.
Scans source code, config files, and git repositories for hardcoded secrets,
API keys, credentials, and sensitive data. Uses pattern matching combined
with AI-based context analysis to minimize false positives.
"""

import os
import re
import sys
import click
from pathlib import Path
from openai import OpenAI
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

client = OpenAI()
console = Console()

# Regex patterns for common secrets
SECRET_PATTERNS = {
    "AWS Access Key":        r"(?i)AKIA[0-9A-Z]{16}",
    "AWS Secret Key":        r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s]*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
    "GitHub Token":          r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}",
    "Google API Key":        r"AIza[0-9A-Za-z\-_]{35}",
    "Stripe Secret Key":     r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable Key":r"pk_live_[0-9a-zA-Z]{24}",
    "Slack Token":           r"xox[baprs]-[0-9A-Za-z\-]{10,48}",
    "Private Key Header":    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Generic Password":      r"(?i)(password|passwd|pwd|secret|token|api[_\-]?key)\s*[=:]\s*['\"]?[^\s'\"]{8,}",
    "JWT Token":             r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Basic Auth (Base64)":   r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{20,}",
    "Database URL":          r"(?i)(mysql|postgres|mongodb|redis|mssql):\/\/[^:]+:[^@]+@[^\s]+",
    "SSH Private Key":       r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "Heroku API Key":        r"(?i)heroku[_\-\s]?api[_\-\s]?key[\s]*[=:]\s*['\"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "SendGrid API Key":      r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
}

IGNORE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                     ".pdf", ".zip", ".tar", ".gz", ".bin", ".exe", ".dll"}

IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def scan_file(file_path: Path) -> list:
    """Scan a single file for secret patterns."""
    findings = []
    try:
        content = file_path.read_text(errors="ignore")
        for secret_type, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content):
                line_num = content[:match.start()].count("\n") + 1
                findings.append({
                    "file": str(file_path),
                    "line": line_num,
                    "type": secret_type,
                    "match": match.group()[:80] + "..." if len(match.group()) > 80 else match.group(),
                })
    except (PermissionError, OSError):
        pass
    return findings


def scan_path(target: str) -> list:
    """Recursively scan a directory or single file."""
    target_path = Path(target)
    all_findings = []

    if target_path.is_file():
        return scan_file(target_path)

    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for file in files:
            fp = Path(root) / file
            if fp.suffix.lower() in IGNORE_EXTENSIONS:
                continue
            all_findings.extend(scan_file(fp))

    return all_findings


@click.command()
@click.argument("target", default=".")
@click.option("--ai-review", is_flag=True, help="Use AI to review and contextualize findings.")
@click.option("--severity-filter", default="all",
              type=click.Choice(["all", "critical", "high"], case_sensitive=False),
              help="Filter findings by severity.")
def scan(target: str, ai_review: bool, severity_filter: str):
    """Scan a directory or file for hardcoded secrets and credentials.

    Example:
        python main.py .
        python main.py /path/to/repo --ai-review
        python main.py src/ --severity-filter critical
    """
    console.print(Panel(f"[bold cyan]Scanning: {target}[/bold cyan]", expand=False))
    findings = scan_path(target)

    if not findings:
        console.print("[bold green]No secrets detected.[/bold green]")
        return

    # Display findings table
    table = Table(title=f"Secrets Scan Results ({len(findings)} findings)",
                  show_header=True, header_style="bold red")
    table.add_column("#", style="dim", width=4)
    table.add_column("File", style="cyan")
    table.add_column("Line", width=6)
    table.add_column("Type", style="yellow")
    table.add_column("Match Preview", style="red")

    for i, f in enumerate(findings[:50], 1):  # Cap display at 50
        table.add_row(str(i), f["file"], str(f["line"]), f["type"], f["match"])

    console.print(table)

    if len(findings) > 50:
        console.print(f"[bold yellow]... and {len(findings) - 50} more findings.[/bold yellow]")

    if ai_review:
        console.print("\n[bold yellow]Running AI risk assessment...[/bold yellow]")
        findings_summary = "\n".join(
            [f"- {f['type']} in {f['file']}:{f['line']} → {f['match']}" for f in findings[:30]]
        )

        prompt = f"""You are a security engineer reviewing secrets scan results. Analyze the following findings and provide:

1. **Risk Summary** – Overall risk level and most critical findings.
2. **False Positive Assessment** – Which findings are likely false positives?
3. **Confirmed Secrets** – Which findings are definitely real secrets?
4. **Immediate Actions** – What must be done right now (e.g., rotate keys)?
5. **Remediation Plan** – How to properly manage secrets going forward (vault, env vars, etc.).
6. **Prevention Recommendations** – Pre-commit hooks, secret scanning CI/CD integration.

Findings:
{findings_summary}

Format your response in Markdown."""

        try:
            response = client.chat.completions.create(
                model="gpt-4.1-mini",
                messages=[
                    {"role": "system", "content": "You are an expert application security engineer specializing in secrets management and DevSecOps."},
                    {"role": "user", "content": prompt}
                ]
            )
            console.print(Markdown(response.choices[0].message.content))
        except Exception as e:
            console.print(f"[bold red]AI review error:[/bold red] {e}")


if __name__ == "__main__":
    scan()
