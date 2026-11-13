# ReconBuddy

**Your friendly, zero-dependency recon companion for ethical bug hunting.**

ReconBuddy is a single-file Python tool that makes the first steps of bug hunting easy for beginners. It runs entirely on the Python standard library — no `pip install`, no external binaries, no API keys.

> ⚠️ **Ethical use only.** Use ReconBuddy exclusively on domains you own or have explicit written permission to test (e.g. within a bug bounty program's scope). The built-in authorization gate enforces this.

---

## Why ReconBuddy?

Most recon frameworks require a stack of Go binaries, API keys, and configuration. ReconBuddy takes the opposite approach:

- **Zero dependencies** — only Python 3.7+ and the standard library.
- **Beginner-friendly** — clear console output, actionable advice, and a report you can read immediately.
- **Passive first** — subdomain enumeration uses certificate transparency logs, so it does not touch the target aggressively.
- **Ethical by design** — an explicit permission prompt and a visible disclaimer are part of the workflow.
- **Report-ready** — generates both Markdown and HTML so you can drop findings into a bug bounty report or a personal notes system.

---

## What it does

| Step | What happens | Why it matters |
|------|--------------|----------------|
| 1. Passive subdomains | Queries `crt.sh` certificate transparency logs for subdomains of the target. | Expands your attack surface without active brute-forcing. |
| 2. HTTP/HTTPS probe | Tries HTTPS first, then HTTP. Records status, server header, and page title. | Confirms which endpoints are live and how they respond. |
| 3. Security-header audit | Checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy. | Missing headers are common, low-hanging findings that are easy to report and fix. |
| 4. Well-known files | Looks for `robots.txt`, `sitemap.xml`, and `/.well-known/security.txt`. | These files often reveal hidden paths, structure, or contact information. |
| 5. Deep mode (opt-in) | Checks for exposed `.git/HEAD` and `.env`. | High-severity findings if present — but **only run deep mode if your scope allows it**. |

---

## Quick start

```bash
# 1. Clone the repo
git clone https://github.com/yourname/reconbuddy.git
cd reconbuddy

# 2. Run against a target you are authorized to test
python3 reconbuddy.py example.com --i-have-permission

# 3. Optional: enable deep checks for sensitive files
python3 reconbuddy.py example.com --i-have-permission --deep
```

Reports land in `reconbuddy-reports/` as Markdown and HTML.

---

## Authorization and legal notice

ReconBuddy includes a mandatory authorization gate. When you run it without the `--i-have-permission` flag, it will ask you to type `I HAVE PERMISSION`. This is intentional: bug hunting is only ethical and legal when you have explicit permission.

**You are responsible for your actions.** The author assumes no liability for misuse or damage caused by this tool.

---

## Requirements

- Python 3.7 or newer.
- No third-party packages.
- Internet access for certificate transparency lookups and target probing.

---

## Project structure

```
reconbuddy/
├── reconbuddy.py      # the entire tool — single file
├── README.md
├── LICENSE            # MIT
└── .gitignore
```

---

## Roadmap / ideas for contributions

- [ ] Add optional JSON output for integration with other tools.
- [ ] Add a `--scope-file` flag to load authorized domains from a list.
- [ ] Improve the HTML report styling.
- [ ] Add a `--quiet` mode for use in scripts.
- [ ] Add passive DNS lookups via additional public APIs.

Contributions are welcome — please keep the zero-dependency philosophy.

---

## License

MIT. See `LICENSE`.
