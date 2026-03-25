<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/async-httpx-FF6B35?style=for-the-badge" alt="httpx"/>
  <img src="https://img.shields.io/badge/terminal-rich-7C3AED?style=for-the-badge" alt="Rich"/>
  <img src="https://img.shields.io/badge/license-GPL--3.0-green?style=for-the-badge" alt="GPL-3.0"/>
</p>

<h1 align="center">
  🛡️ shcheck-modern
</h1>

<p align="center">
  <strong>A modern, async security headers analyzer with scoring, deep analysis, and rich terminal output.</strong>
</p>

<p align="center">
  Inspired by <a href="https://github.com/santoru/shcheck">santoru/shcheck</a> — rewritten from scratch for speed, depth, and style.
</p>

---



---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🎯 | **Security Scoring** | Weighted scoring system with grades from **A+** to **F** based on header presence *and* quality |
| 🔬 | **Deep Analysis** | Inspects header values: HSTS max-age, CSP directives, Referrer policies, X-Frame-Options modes… |
| ⚡ | **Async Scanning** | Concurrent multi-target scanning powered by `httpx` + `asyncio` with configurable concurrency |
| 🎨 | **Rich Output** | Beautiful terminal tables, color-coded severities, progress bars, and grade panels via `rich` |
| 📊 | **Multiple Exports** | JSON (`-j`) and CSV (`--csv`) output for reporting and CI/CD integration |
| 🔍 | **12 Security Headers** | Covers modern headers: `Permissions-Policy`, `Cross-Origin-*-Policy`, `Clear-Site-Data`… |
| ⚠️ | **Info Disclosure** | Detects leaky headers: `Server`, `X-Powered-By`, `X-AspNet-Version`, and more |
| 🚦 | **CI-Friendly Exit Codes** | `0` = all good, `1` = poor grades, `2` = errors |

## 📦 Installation

```bash
# Clone the repo
git clone https://github.com/youruser/shcheck-modern.git
cd shcheck-modern

# Install dependencies
pip install httpx rich

# Run
./shcheck_modern.py https://example.com
```

### Requirements

- Python **3.10+**
- [`httpx`](https://www.python-httpx.org/) — async HTTP client
- [`rich`](https://github.com/Textualize/rich) — terminal formatting

## 🚀 Quick Start

```bash
# Basic scan
./shcheck_modern.py https://example.com

# Full audit (info disclosure + caching + deprecated headers)
./shcheck_modern.py -ixk https://example.com

# Multiple targets
./shcheck_modern.py https://example.com https://google.com https://github.com

# From a file
./shcheck_modern.py --hfile targets.txt
```

## 📖 Usage

```
usage: shcheck-modern [-h] [-p PORT] [-c COOKIE] [-a ADD_HEADERS] [-d] [-g]
                      [-j] [--csv FILE] [-i] [-x] [-k] [--proxy URL]
                      [--hfile FILE] [--timeout TIMEOUT]
                      [--concurrency CONCURRENCY] [--user-agent USER_AGENT]
                      [-V]
                      [targets ...]
```

### Options

| Flag | Long | Description |
|------|------|-------------|
| `-p` | `--port PORT` | Custom port to connect to |
| `-c` | `--cookie COOKIE` | Cookie string for the request |
| `-a` | `--add-header` | Additional header (repeatable), e.g. `'Authorization: Bearer xxx'` |
| `-d` | `--disable-ssl-check` | Disable TLS certificate validation |
| `-g` | `--use-get-method` | Use GET instead of HEAD |
| `-j` | `--json` | Output results as JSON |
| | `--csv FILE` | Export results to CSV |
| `-i` | `--information` | Show information disclosure headers |
| `-x` | `--caching` | Show caching headers |
| `-k` | `--deprecated` | Show deprecated headers |
| | `--proxy URL` | Route through a proxy (e.g. `http://127.0.0.1:8080`) |
| | `--hfile FILE` | Load targets from file (one per line) |
| | `--timeout SEC` | Request timeout in seconds (default: `10`) |
| | `--concurrency N` | Max concurrent scans (default: `10`) |
| | `--user-agent UA` | Custom User-Agent string |
| `-V` | `--version` | Show version |

## 🎯 Headers Checked

### Security Headers (scored & analyzed)

| Header | Severity | Weight | Deep Analysis |
|--------|----------|--------|---------------|
| `Strict-Transport-Security` | 🔴 High | 15 | max-age value, includeSubDomains, preload |
| `Content-Security-Policy` | 🔴 High | 15 | unsafe-inline/eval, key directives, reporting |
| `X-Content-Type-Options` | 🟡 Medium | 10 | Validates `nosniff` value |
| `X-Frame-Options` | 🟡 Medium | 10 | DENY vs SAMEORIGIN vs ALLOW-FROM |
| `Referrer-Policy` | 🟡 Medium | 8 | Policy strength ranking |
| `Permissions-Policy` | 🟡 Medium | 8 | Presence check |
| `Cross-Origin-Opener-Policy` | 🟡 Medium | 6 | Presence check |
| `Cross-Origin-Resource-Policy` | 🟡 Medium | 6 | Presence check |
| `Cross-Origin-Embedder-Policy` | 🟡 Medium | 5 | Presence check |
| `X-XSS-Protection` | 🔵 Low | 2 | Validates `0` (modern recommendation) |
| `X-Permitted-Cross-Domain-Policies` | 🔵 Low | 2 | Presence check |
| `Clear-Site-Data` | 🔵 Low | 2 | Presence check |

### Information Disclosure Headers (`-i`)

Detects: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `X-Drupal-Cache`, `X-Varnish`, `Via`, `X-Runtime`, `X-Version`, `X-Backend-Server`

### Deprecated Headers (`-k`)

Flags: `X-XSS-Protection`, `X-Content-Security-Policy`, `X-WebKit-CSP`, `Public-Key-Pins`, `Expect-CT`, `Feature-Policy`

## 📊 Scoring System

The score is computed as a **weighted average** of all 12 security headers. Each header has a weight reflecting its importance, and analyzers evaluate the *quality* of the value (not just presence).

| Grade | Score Range | Meaning |
|-------|-------------|---------|
| **A+** | 90 – 100 | Excellent — all critical headers present with strong values |
| **A** | 80 – 89 | Great — minor improvements possible |
| **B** | 70 – 79 | Good — some headers missing or misconfigured |
| **C** | 60 – 69 | Fair — several gaps in security posture |
| **D** | 45 – 59 | Poor — significant headers missing |
| **F** | 0 – 44 | Failing — most security headers absent |

### Example: HSTS Scoring

A header like `Strict-Transport-Security: max-age=300` will score **lower** than `max-age=31536000; includeSubDomains; preload` even though both are "present" — the analyzer checks the actual configuration quality.

## 🔧 Advanced Usage

### Scan through Burp Suite

```bash
./shcheck_modern.py --proxy http://127.0.0.1:8080 -d https://target.com
```

### CI/CD Pipeline Integration

```bash
# JSON output for parsing
./shcheck_modern.py -j https://api.example.com > headers.json

# CSV for spreadsheet reporting
./shcheck_modern.py --csv report.csv --hfile production-hosts.txt

# Use exit code in CI
./shcheck_modern.py https://myapp.com || echo "Security headers need attention!"
```

### Mass Scan from File

```bash
# targets.txt — one URL per line, # for comments
cat targets.txt
# Production
https://app.example.com
https://api.example.com
# Staging
https://staging.example.com

./shcheck_modern.py --hfile targets.txt --concurrency 20 --csv results.csv
```

### Custom Headers & Auth

```bash
./shcheck_modern.py \
  -a "Authorization: Bearer eyJhbG..." \
  -a "X-Custom-Header: value" \
  -c "session=abc123" \
  https://protected.example.com
```

## 🆚 Comparison with shcheck

| Feature | shcheck | shcheck-modern |
|---------|---------|----------------|
| Async scanning | ❌ | ✅ (httpx + asyncio) |
| Security scoring | ❌ | ✅ A+ → F grading |
| Header value analysis | ❌ | ✅ Deep analysis |
| Terminal output | Basic colors | Rich tables & panels |
| CSV export | ❌ | ✅ |
| JSON export | ✅ | ✅ |
| Cross-Origin headers | ❌ | ✅ (COOP, CORP, COEP) |
| Permissions-Policy | ❌ | ✅ |
| Concurrent scanning | ❌ | ✅ Configurable |
| CI exit codes | ❌ | ✅ |
| Proxy support | ✅ | ✅ |
| Python version | 3.x | 3.10+ |

## 📜 License

This project is licensed under the **GPL-3.0** License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for security professionals. Use responsibly and only on systems you are authorized to test.</sub>
</p>
