# Security & Tech News Digest: Free Daily Automation

Every day, this pulls together:
- **New and updated CVEs** from the NVD for each tracked system
- **Actively exploited but not-yet-scored bugs** from CISA's KEV catalog, which catches "exploited in the wild" before NVD assigns a CVSS score
- **News and community chatter** about those systems (Google News searches plus RSS feeds from BleepingComputer, The Hacker News, Krebs on Security, and others)

...and hands the vulnerability data to a free LLM via **OpenRouter** to produce one clean report per scope:
**Summary, Affected Features / App Interoperability, Source, Actions (fix, workaround, tradeoffs)**, with a separate "News & Community Mentions" section clearly marked as unverified.

The result is published as a static dashboard (GitHub Pages or any static host). Total cost: $0/month, no credit card needed anywhere.

## What the dashboard contains

**Top: raw news rows (no LLM, no filtering).** Three rows, each with its own feed list, shown as scrollable columns by source:
- **Security** (`SECURITY_NEWS_FEEDS`)
- **DevSecOps** (`DEVSECOPS_NEWS_FEEDS`)
- **Cloud** (`CLOUD_NEWS_FEEDS`)

**Bottom: scoped vulnerability tracking.** For each scope in `SCOPES`, the script queries NVD per system, matches the CISA KEV catalog, collects matching news, and asks the LLM to format it. Currently one scope is configured: **Cloud Security** (AWS, Azure, GCP, Kubernetes, Docker, Terraform).

## How it works

```
GitHub Actions (daily cron)
  -> NVD API (CVEs per system)        \
  -> CISA KEV JSON (exploited bugs)    }-> sorted + capped in Python
  -> RSS / Google News (news)         /
  -> OpenRouter free model (one prompt per scope, formatting only)
  -> markdown -> static HTML (docs/) + markdown archive (reports/)
  -> committed back to the repo and served as a static site
```

Design decisions worth calling out:
- **Python does the thinking, the LLM only formats.** Entries are sorted (KEV-confirmed first, then CVSS descending) and capped per system before the model sees them. Early versions let the model sort and it got stuck in repetitive reasoning loops.
- **One prompt per scope.** A single combined prompt grew too large and triggered the same failure.
- **Safety nets.** Leaked reasoning is stripped, stuck-loop responses are detected (consecutive duplicate lines) and retried, and null or malformed API responses are handled.
- **Graceful degradation.** If one scope's LLM call fails, that scope shows a fallback message and everything else still publishes. The run exits non-zero so the failure is visible in Actions.
- **Standard library only.** No pip dependencies; the Markdown-to-HTML converter and RSS/Atom parser are hand-written.
- **Severity-coded cards.** CVE headers in the LLM output are parsed into colored cards (critical, high, medium, unscored) with a KEV badge.

## Setup

1. **OpenRouter key.** Create a free account at https://openrouter.ai, then create a key at https://openrouter.ai/keys. Optionally set a $0 spend limit on it.
2. **Repo.** Create a public repo containing `digest.py`, `README.md`, and `.github/workflows/daily-digest.yml`.
3. **Secrets.** Under Settings, Secrets and variables, Actions, add `OPENROUTER_API_KEY`. Optionally add `NVD_API_KEY` (free, raises the NVD rate limit).
4. **Publish.** Settings, Pages, deploy from branch `main`, folder `/docs`. A custom domain can be added there, or point Cloudflare Pages / Netlify at the `docs` folder.
5. **Test.** Run the workflow manually from the Actions tab. After that it runs daily at 12:00 UTC (edit the `cron:` line to change it).

## Adding a scope

Add an entry to `SCOPES` in `digest.py`:

```python
"Your Scope Name": {
    "targets": {
        "Friendly System Name": "NVD keywordSearch term",
    },
    "match_terms": {
        "Friendly System Name": ["lowercase", "substrings", "to match"],
    },
},
```

NVD querying, KEV matching, news matching, the prompt, and the dashboard all pick it up automatically. To add a news row, define a feed list like `CLOUD_NEWS_FEEDS` and add a tuple to `news_rows` in `main()` (plus a `--row-*` color in `PAGE_CSS`).

## Configuration

| Setting | Where | Default |
|---|---|---|
| CVE lookback | `LOOKBACK_HOURS` env | 26 |
| KEV lookback | `KEV_LOOKBACK_DAYS` env | 7 |
| News lookback | `NEWS_LOOKBACK_HOURS` env | 48 |
| Extra Security-row feeds | `CUSTOM_RSS_FEEDS` env (comma-separated URLs) | none |
| Disable all news | `ENABLE_NEWS_FEEDS=false` | enabled |
| Entries per system | `MAX_ENTRIES_PER_SYSTEM` | 10 |
| Items per news source | `MAX_ITEMS_PER_NEWS_SOURCE` | 15 |
| News mentions per system | `MAX_NEWS_ITEMS_PER_SYSTEM` | 5 |

## Data sources and reliability

| Section | Source | Reliability |
|---|---|---|
| Formal Vulnerabilities | NVD + CISA KEV | Authoritative. KEV entries are confirmed exploitation and always sort first. |
| News & Community Mentions | RSS and Google News | Unverified. The prompt forbids inventing CVE numbers from this data. |
| Raw news rows | RSS feeds | Not analyzed. Headlines exactly as published. |

## Troubleshooting

- **"OPENROUTER_API_KEY not set":** the secret name must match exactly and be under Secrets, not Variables.
- **404 or stale dashboard:** Pages can take a minute or two to redeploy; hard-refresh to bypass the cache.
- **429 from OpenRouter:** the free router has modest limits; the script retries with backoff.
- **A feed returns 429 or fails:** non-fatal, that source is skipped for the run.
- **Slow runs:** each system adds one NVD query with a 6 second pause; still well inside free Actions minutes.

## Privacy

Everything the script reads and publishes is public data (CVE records, the KEV catalog, public RSS feeds). Only the API keys are secret, and they live in repository secrets, never in the code.
