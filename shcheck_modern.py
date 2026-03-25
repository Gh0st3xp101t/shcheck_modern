#!/usr/bin/env python3
"""
shcheck-modern — Modern Security Headers Analyzer
A modern, feature-rich tool to audit HTTP security headers.
Inspired by santoru/shcheck, rewritten from scratch with async support,
rich terminal output, scoring, and deep header analysis.

Author: Security Assessment Tool
License: GPL-3.0
"""

import argparse
import asyncio
import csv
import json
import sys
import ssl
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

try:
    import httpx
except ImportError:
    sys.exit("[!] httpx is required: pip install httpx")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.columns import Columns
    from rich import box
except ImportError:
    sys.exit("[!] rich is required: pip install rich")

# ─────────────────────────────────────────────────────────────
# Constants & header definitions
# ─────────────────────────────────────────────────────────────

VERSION = "1.0.0"
BANNER = r"""
     _     ___ _           _      __  __         _
 ___| |_  / __| |_  ___ __| |__  |  \/  |___  __| |___ _ _ _ _
(_-<| ' \| (__| ' \/ -_) _| / /  | |\/| / _ \/ _` / -_) '_| ' \
/__/|_||_|\___|_||_\___\__|_\_\  |_|  |_\___/\__,_\___|_| |_||_|
"""

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class HeaderCheck:
    """Definition of a security header to check."""
    name: str
    severity: Severity
    description: str
    reference: str
    weight: int  # scoring weight (higher = more important)
    analyzer: Optional[str] = None  # name of analysis method


# ── Security headers we check (ordered by importance) ──

SECURITY_HEADERS: list[HeaderCheck] = [
    HeaderCheck(
        name="Strict-Transport-Security",
        severity=Severity.HIGH,
        description="Forces HTTPS connections, prevents protocol downgrade attacks",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        weight=15,
        analyzer="analyze_hsts",
    ),
    HeaderCheck(
        name="Content-Security-Policy",
        severity=Severity.HIGH,
        description="Controls which resources the browser is allowed to load",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        weight=15,
        analyzer="analyze_csp",
    ),
    HeaderCheck(
        name="X-Content-Type-Options",
        severity=Severity.MEDIUM,
        description="Prevents MIME-type sniffing (expected: nosniff)",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        weight=10,
        analyzer="analyze_xcto",
    ),
    HeaderCheck(
        name="X-Frame-Options",
        severity=Severity.MEDIUM,
        description="Controls whether the site can be embedded in iframes",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        weight=10,
        analyzer="analyze_xfo",
    ),
    HeaderCheck(
        name="Referrer-Policy",
        severity=Severity.MEDIUM,
        description="Controls how much referrer info is sent with requests",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        weight=8,
        analyzer="analyze_referrer",
    ),
    HeaderCheck(
        name="Permissions-Policy",
        severity=Severity.MEDIUM,
        description="Controls which browser features can be used (replaces Feature-Policy)",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        weight=8,
    ),
    HeaderCheck(
        name="X-XSS-Protection",
        severity=Severity.LOW,
        description="Legacy XSS filter (modern browsers ignore it; best set to '0')",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
        weight=2,
        analyzer="analyze_xxss",
    ),
    HeaderCheck(
        name="Cross-Origin-Opener-Policy",
        severity=Severity.MEDIUM,
        description="Isolates browsing context to prevent cross-origin attacks",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
        weight=6,
    ),
    HeaderCheck(
        name="Cross-Origin-Resource-Policy",
        severity=Severity.MEDIUM,
        description="Controls which origins can read the resource",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
        weight=6,
    ),
    HeaderCheck(
        name="Cross-Origin-Embedder-Policy",
        severity=Severity.MEDIUM,
        description="Prevents loading cross-origin resources without explicit permission",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
        weight=5,
    ),
    HeaderCheck(
        name="X-Permitted-Cross-Domain-Policies",
        severity=Severity.LOW,
        description="Controls Adobe Flash/PDF cross-domain data loading",
        reference="https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies",
        weight=2,
    ),
    HeaderCheck(
        name="Clear-Site-Data",
        severity=Severity.LOW,
        description="Instructs the browser to clear site data (cookies, storage, cache)",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data",
        weight=2,
    ),
]

INFORMATION_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Varnish",
    "Via",
    "X-Runtime",
    "X-Version",
    "X-Backend-Server",
]

CACHING_HEADERS = [
    "Cache-Control",
    "Pragma",
    "Expires",
    "ETag",
    "Last-Modified",
    "Age",
    "Vary",
    "CDN-Cache-Control",
    "Surrogate-Control",
]

DEPRECATED_HEADERS = [
    "X-XSS-Protection",
    "X-Content-Security-Policy",
    "X-WebKit-CSP",
    "Public-Key-Pins",
    "Public-Key-Pins-Report-Only",
    "Expect-CT",
    "Feature-Policy",
]

# ─────────────────────────────────────────────────────────────
# Header value analyzers
# ─────────────────────────────────────────────────────────────

class HeaderAnalyzer:
    """Deep analysis of header values — returns (score_modifier, findings)."""

    @staticmethod
    def analyze_hsts(value: str) -> tuple[float, list[str]]:
        findings = []
        score = 1.0
        val_lower = value.lower()

        # max-age
        if "max-age=" in val_lower:
            try:
                max_age = int(val_lower.split("max-age=")[1].split(";")[0].strip())
                if max_age >= 31536000:
                    findings.append(f"✓ max-age={max_age} (≥1 year — good)")
                elif max_age >= 15768000:
                    findings.append(f"~ max-age={max_age} (≥6 months — acceptable)")
                    score = 0.7
                else:
                    findings.append(f"✗ max-age={max_age} (too low — recommend ≥31536000)")
                    score = 0.4
            except (ValueError, IndexError):
                findings.append("✗ Could not parse max-age value")
                score = 0.5
        else:
            findings.append("✗ Missing max-age directive")
            score = 0.3

        if "includesubdomains" in val_lower:
            findings.append("✓ includeSubDomains is set")
        else:
            findings.append("~ includeSubDomains not set (recommended)")
            score *= 0.9

        if "preload" in val_lower:
            findings.append("✓ preload is set")
        else:
            findings.append("~ preload not set (recommended for HSTS preload list)")
            score *= 0.95

        return score, findings

    @staticmethod
    def analyze_csp(value: str) -> tuple[float, list[str]]:
        findings = []
        score = 1.0
        val_lower = value.lower()

        dangerous_sources = ["'unsafe-inline'", "'unsafe-eval'", "data:", "*"]
        for src in dangerous_sources:
            if src in val_lower:
                findings.append(f"✗ Contains {src} — weakens CSP significantly")
                score *= 0.6

        important_directives = [
            ("default-src", "Fallback for all resource types"),
            ("script-src", "Controls script loading"),
            ("object-src", "Controls plugin loading (should be 'none')"),
            ("base-uri", "Restricts <base> element URLs"),
            ("frame-ancestors", "Replaces X-Frame-Options"),
        ]
        for directive, desc in important_directives:
            if directive in val_lower:
                findings.append(f"✓ {directive} is defined ({desc})")
            else:
                findings.append(f"~ {directive} not defined ({desc})")
                score *= 0.9

        if "report-uri" in val_lower or "report-to" in val_lower:
            findings.append("✓ CSP reporting is configured")

        return score, findings

    @staticmethod
    def analyze_xcto(value: str) -> tuple[float, list[str]]:
        if value.strip().lower() == "nosniff":
            return 1.0, ["✓ Correctly set to 'nosniff'"]
        return 0.3, [f"✗ Unexpected value '{value}' — should be 'nosniff'"]

    @staticmethod
    def analyze_xfo(value: str) -> tuple[float, list[str]]:
        val_upper = value.strip().upper()
        if val_upper == "DENY":
            return 1.0, ["✓ Set to DENY — page cannot be framed at all"]
        elif val_upper == "SAMEORIGIN":
            return 0.9, ["✓ Set to SAMEORIGIN — only same-origin framing allowed"]
        elif val_upper.startswith("ALLOW-FROM"):
            return 0.6, ["~ ALLOW-FROM is deprecated and not widely supported"]
        return 0.3, [f"✗ Unexpected value '{value}'"]

    @staticmethod
    def analyze_referrer(value: str) -> tuple[float, list[str]]:
        val_lower = value.strip().lower()
        good_policies = {
            "no-referrer": 1.0,
            "strict-origin": 0.95,
            "strict-origin-when-cross-origin": 0.9,
            "same-origin": 0.9,
            "origin": 0.8,
            "origin-when-cross-origin": 0.75,
            "no-referrer-when-downgrade": 0.6,
        }
        if val_lower in good_policies:
            return good_policies[val_lower], [f"✓ Policy '{val_lower}' is set"]
        if val_lower == "unsafe-url":
            return 0.2, ["✗ 'unsafe-url' leaks full URL — strongly discouraged"]
        return 0.5, [f"~ Unknown policy '{val_lower}'"]

    @staticmethod
    def analyze_xxss(value: str) -> tuple[float, list[str]]:
        val = value.strip()
        if val == "0":
            return 1.0, ["✓ Set to '0' — correctly disables legacy filter"]
        if val.startswith("1"):
            return 0.5, [
                "~ Set to '1' — legacy XSS filter enabled.",
                "  Modern recommendation: set to '0' and rely on CSP instead",
            ]
        return 0.3, [f"~ Unexpected value '{val}'"]


# ─────────────────────────────────────────────────────────────
# Result data classes
# ─────────────────────────────────────────────────────────────

@dataclass
class HeaderResult:
    name: str
    present: bool
    value: Optional[str] = None
    severity: str = ""
    description: str = ""
    score_modifier: float = 0.0
    findings: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    url: str
    status_code: int = 0
    final_url: str = ""
    error: Optional[str] = None
    grade: str = ""
    score: float = 0.0
    security_headers: list[HeaderResult] = field(default_factory=list)
    info_headers: dict = field(default_factory=dict)
    caching_headers: dict = field(default_factory=dict)
    deprecated_headers: dict = field(default_factory=dict)
    raw_headers: dict = field(default_factory=dict)
    scan_time: float = 0.0
    tls_info: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────
# Scanner
# ─────────────────────────────────────────────────────────────

class SecurityHeaderScanner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.console = Console(force_terminal=not args.json_output)
        self.analyzer = HeaderAnalyzer()

    def _build_client_kwargs(self) -> dict:
        kwargs: dict = {
            "timeout": httpx.Timeout(self.args.timeout),
            "follow_redirects": True,
            "max_redirects": 10,
        }

        headers = {"User-Agent": self.args.user_agent}
        if self.args.cookie:
            headers["Cookie"] = self.args.cookie
        if self.args.add_headers:
            for h in self.args.add_headers:
                if ":" in h:
                    key, val = h.split(":", 1)
                    headers[key.strip()] = val.strip()
        kwargs["headers"] = headers

        if self.args.disable_ssl:
            kwargs["verify"] = False

        if self.args.proxy:
            kwargs["proxy"] = self.args.proxy

        return kwargs

    async def scan_target(self, url: str) -> ScanResult:
        result = ScanResult(url=url)
        t0 = time.monotonic()

        # Ensure URL has a scheme
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        # Custom port
        if self.args.port:
            parsed = urlparse(url)
            url = f"{parsed.scheme}://{parsed.hostname}:{self.args.port}{parsed.path or '/'}"

        try:
            async with httpx.AsyncClient(**self._build_client_kwargs()) as client:
                method = "GET" if self.args.use_get else "HEAD"
                resp = await client.request(method, url)

                # Some servers return empty HEAD; fall back to GET
                if method == "HEAD" and not resp.headers:
                    resp = await client.get(url)

                result.status_code = resp.status_code
                result.final_url = str(resp.url)
                result.raw_headers = dict(resp.headers)

        except httpx.ConnectError as e:
            result.error = f"Connection error: {e}"
        except httpx.TimeoutException:
            result.error = "Connection timed out"
        except Exception as e:
            result.error = str(e)

        if result.error:
            result.scan_time = time.monotonic() - t0
            return result

        # ── Analyze security headers ──
        total_weight = 0
        earned_weight = 0.0

        for hdef in SECURITY_HEADERS:
            raw_value = result.raw_headers.get(hdef.name.lower()) or result.raw_headers.get(hdef.name)
            # httpx normalizes header names to lowercase
            present = raw_value is not None
            if not present:
                # try case-insensitive search
                for k, v in result.raw_headers.items():
                    if k.lower() == hdef.name.lower():
                        raw_value = v
                        present = True
                        break

            hr = HeaderResult(
                name=hdef.name,
                present=present,
                value=raw_value,
                severity=hdef.severity.value,
                description=hdef.description,
            )

            total_weight += hdef.weight

            if present and hdef.analyzer and hasattr(self.analyzer, hdef.analyzer):
                fn = getattr(self.analyzer, hdef.analyzer)
                modifier, findings = fn(raw_value)
                hr.score_modifier = modifier
                hr.findings = findings
                earned_weight += hdef.weight * modifier
            elif present:
                hr.score_modifier = 1.0
                hr.findings = [f"✓ Present: {raw_value}"]
                earned_weight += hdef.weight
            else:
                hr.score_modifier = 0.0
                hr.findings = [f"✗ Missing — {hdef.description}"]

            result.security_headers.append(hr)

        # ── Score & grade ──
        result.score = round((earned_weight / total_weight) * 100, 1) if total_weight else 0
        result.grade = self._score_to_grade(result.score)

        # ── Information headers ──
        for h in INFORMATION_HEADERS:
            for k, v in result.raw_headers.items():
                if k.lower() == h.lower():
                    result.info_headers[h] = v

        # ── Caching headers ──
        for h in CACHING_HEADERS:
            for k, v in result.raw_headers.items():
                if k.lower() == h.lower():
                    result.caching_headers[h] = v

        # ── Deprecated headers ──
        for h in DEPRECATED_HEADERS:
            for k, v in result.raw_headers.items():
                if k.lower() == h.lower():
                    result.deprecated_headers[h] = v

        result.scan_time = time.monotonic() - t0
        return result

    @staticmethod
    def _score_to_grade(score: float) -> str:
        if score >= 90:
            return "A+"
        elif score >= 80:
            return "A"
        elif score >= 70:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 45:
            return "D"
        else:
            return "F"

    # ── Display helpers ──

    def _grade_color(self, grade: str) -> str:
        return {
            "A+": "bold green",
            "A": "green",
            "B": "yellow",
            "C": "dark_orange",
            "D": "red",
            "F": "bold red",
        }.get(grade, "white")

    def _severity_color(self, sev: str) -> str:
        return {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim",
        }.get(sev, "white")

    def print_result(self, result: ScanResult) -> None:
        c = self.console

        if result.error:
            c.print(Panel(
                f"[bold red]Error scanning {result.url}[/]\n{result.error}",
                border_style="red",
            ))
            return

        # ── Header panel ──
        grade_color = self._grade_color(result.grade)
        title_text = Text()
        title_text.append(f" {result.final_url} ", style="bold white on blue")
        title_text.append("  ")
        title_text.append(f" {result.grade} ", style=f"bold white on {grade_color.replace('bold ', '')}")
        title_text.append(f"  Score: {result.score}/100", style=grade_color)

        meta = (
            f"Status: {result.status_code}  |  "
            f"Scan time: {result.scan_time:.2f}s  |  "
            f"Redirected: {'yes → ' + result.final_url if result.final_url != result.url else 'no'}"
        )

        c.print()
        c.print(Panel(title_text, subtitle=meta, border_style="blue", padding=(0, 2)))

        # ── Security headers table ──
        table = Table(
            title="Security Headers",
            box=box.ROUNDED,
            show_lines=True,
            title_style="bold cyan",
            expand=True,
        )
        table.add_column("Header", style="bold", min_width=30, ratio=3)
        table.add_column("Status", justify="center", width=10)
        table.add_column("Severity", justify="center", width=10)
        table.add_column("Analysis", ratio=5)

        for hr in result.security_headers:
            status = Text("✓ Present", style="green") if hr.present else Text("✗ Missing", style="red")
            sev_style = self._severity_color(hr.severity)
            severity_text = Text(hr.severity.upper(), style=sev_style)

            analysis_parts = []
            if hr.present and hr.value:
                # Truncate very long values
                display_val = hr.value if len(hr.value) <= 120 else hr.value[:117] + "..."
                analysis_parts.append(f"[dim]{display_val}[/dim]")
            for f in hr.findings:
                if f.startswith("✓"):
                    analysis_parts.append(f"[green]{f}[/green]")
                elif f.startswith("✗"):
                    analysis_parts.append(f"[red]{f}[/red]")
                else:
                    analysis_parts.append(f"[yellow]{f}[/yellow]")

            table.add_row(hr.name, status, severity_text, "\n".join(analysis_parts))

        c.print(table)

        # ── Information headers (if present & requested) ──
        if self.args.information and result.info_headers:
            info_table = Table(
                title="⚠ Information Disclosure Headers",
                box=box.SIMPLE_HEAVY,
                title_style="bold yellow",
            )
            info_table.add_column("Header", style="bold yellow")
            info_table.add_column("Value", style="red")
            for k, v in result.info_headers.items():
                info_table.add_row(k, v)
            c.print(info_table)

        # ── Caching headers ──
        if self.args.caching and result.caching_headers:
            cache_table = Table(
                title="Caching Headers",
                box=box.SIMPLE_HEAVY,
                title_style="bold cyan",
            )
            cache_table.add_column("Header", style="bold")
            cache_table.add_column("Value")
            for k, v in result.caching_headers.items():
                cache_table.add_row(k, v)
            c.print(cache_table)

        # ── Deprecated headers ──
        if self.args.deprecated and result.deprecated_headers:
            dep_table = Table(
                title="⚠ Deprecated Headers Found",
                box=box.SIMPLE_HEAVY,
                title_style="bold red",
            )
            dep_table.add_column("Header", style="bold red")
            dep_table.add_column("Value")
            for k, v in result.deprecated_headers.items():
                dep_table.add_row(k, v)
            c.print(dep_table)

        c.print()

    # ── Export methods ──

    @staticmethod
    def results_to_json(results: list[ScanResult]) -> str:
        output = []
        for r in results:
            entry = {
                "url": r.url,
                "final_url": r.final_url,
                "status_code": r.status_code,
                "error": r.error,
                "grade": r.grade,
                "score": r.score,
                "scan_time": round(r.scan_time, 3),
                "security_headers": {},
                "info_headers": r.info_headers,
                "caching_headers": r.caching_headers,
                "deprecated_headers": r.deprecated_headers,
            }
            for hr in r.security_headers:
                entry["security_headers"][hr.name] = {
                    "present": hr.present,
                    "value": hr.value,
                    "severity": hr.severity,
                    "score_modifier": hr.score_modifier,
                    "findings": hr.findings,
                }
            output.append(entry)
        return json.dumps(output, indent=2, ensure_ascii=False)

    @staticmethod
    def results_to_csv(results: list[ScanResult], path: str) -> None:
        header_names = [h.name for h in SECURITY_HEADERS]
        fieldnames = ["url", "final_url", "status_code", "grade", "score", "scan_time"] + header_names
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                row = {
                    "url": r.url,
                    "final_url": r.final_url,
                    "status_code": r.status_code,
                    "grade": r.grade,
                    "score": r.score,
                    "scan_time": round(r.scan_time, 3),
                }
                for hr in r.security_headers:
                    row[hr.name] = hr.value or ""
                writer.writerow(row)

    # ── Main scan orchestrator ──

    async def run(self, targets: list[str]) -> list[ScanResult]:
        results = []

        if not self.args.json_output:
            self.console.print(BANNER, style="bold cyan")
            self.console.print(
                f"[dim]v{VERSION} — Security Headers Analyzer[/dim]\n",
                justify="center",
            )

        if len(targets) == 1:
            result = await self.scan_target(targets[0])
            results.append(result)
            if not self.args.json_output:
                self.print_result(result)
        else:
            # Concurrent scanning with progress
            sem = asyncio.Semaphore(self.args.concurrency)

            async def _bounded_scan(url: str) -> ScanResult:
                async with sem:
                    return await self.scan_target(url)

            if not self.args.json_output:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("{task.completed}/{task.total}"),
                    console=self.console,
                ) as progress:
                    task = progress.add_task("Scanning targets...", total=len(targets))
                    tasks = []
                    for url in targets:
                        tasks.append(_bounded_scan(url))

                    for coro in asyncio.as_completed(tasks):
                        r = await coro
                        results.append(r)
                        progress.advance(task)

                # Print all results
                for r in sorted(results, key=lambda x: x.url):
                    self.print_result(r)

                # Summary table
                self._print_summary(results)
            else:
                tasks = [_bounded_scan(url) for url in targets]
                results = await asyncio.gather(*tasks)

        # ── Output ──
        if self.args.json_output:
            print(self.results_to_json(results))

        if self.args.csv_output:
            self.results_to_csv(results, self.args.csv_output)
            if not self.args.json_output:
                self.console.print(f"[green]✓ CSV saved to {self.args.csv_output}[/green]")

        return results

    def _print_summary(self, results: list[ScanResult]) -> None:
        table = Table(
            title="Summary",
            box=box.DOUBLE_EDGE,
            title_style="bold white",
        )
        table.add_column("Target", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("Grade", justify="center")
        table.add_column("Score", justify="right")
        table.add_column("Time", justify="right")

        for r in sorted(results, key=lambda x: x.score, reverse=True):
            if r.error:
                table.add_row(r.url, "[red]ERROR[/red]", "-", "-", "-")
            else:
                gc = self._grade_color(r.grade)
                table.add_row(
                    r.url,
                    str(r.status_code),
                    Text(r.grade, style=gc),
                    f"{r.score}",
                    f"{r.scan_time:.2f}s",
                )

        self.console.print(table)


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shcheck-modern",
        description="Modern Security Headers Analyzer — check HTTP security headers with scoring & deep analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com
  %(prog)s -ixk https://example.com https://google.com
  %(prog)s --hfile targets.txt -j > results.json
  %(prog)s --csv report.csv https://example.com
        """,
    )

    parser.add_argument("targets", nargs="*", help="Target URL(s) to scan")
    parser.add_argument("-p", "--port", type=int, help="Custom port to connect to")
    parser.add_argument("-c", "--cookie", help="Cookie string for the request")
    parser.add_argument(
        "-a", "--add-header", dest="add_headers", action="append",
        help="Additional header (e.g. 'Authorization: Bearer xxx'). Repeatable.",
    )
    parser.add_argument(
        "-d", "--disable-ssl-check", dest="disable_ssl", action="store_true",
        help="Disable SSL/TLS certificate validation",
    )
    parser.add_argument(
        "-g", "--use-get-method", dest="use_get", action="store_true",
        help="Use GET method instead of HEAD",
    )
    parser.add_argument(
        "-j", "--json", dest="json_output", action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--csv", dest="csv_output", metavar="FILE",
        help="Export results to CSV file",
    )
    parser.add_argument(
        "-i", "--information", action="store_true",
        help="Display information disclosure headers",
    )
    parser.add_argument(
        "-x", "--caching", action="store_true",
        help="Display caching headers",
    )
    parser.add_argument(
        "-k", "--deprecated", action="store_true",
        help="Display deprecated headers",
    )
    parser.add_argument(
        "--proxy", dest="proxy", metavar="URL",
        help="Proxy URL (e.g. http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--hfile", metavar="FILE",
        help="Load target hosts from a file (one per line)",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--concurrency", type=int, default=10,
        help="Max concurrent scans (default: 10)",
    )
    parser.add_argument(
        "--user-agent", dest="user_agent",
        default=f"shcheck-modern/{VERSION}",
        help="Custom User-Agent string",
    )
    parser.add_argument(
        "-V", "--version", action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    targets = list(args.targets) if args.targets else []

    # Load targets from file
    if args.hfile:
        try:
            with open(args.hfile) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        except FileNotFoundError:
            print(f"[!] File not found: {args.hfile}", file=sys.stderr)
            sys.exit(1)

    if not targets:
        parser.print_help()
        sys.exit(1)

    # Suppress SSL warnings if disabled
    if args.disable_ssl:
        import warnings
        import urllib3
        warnings.filterwarnings("ignore")
        try:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

    scanner = SecurityHeaderScanner(args)
    results = asyncio.run(scanner.run(targets))

    # Exit code: 0 if all A/A+, 1 if any warnings
    if any(r.error for r in results):
        sys.exit(2)
    if any(r.grade in ("D", "F") for r in results):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
