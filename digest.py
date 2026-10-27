import os
import sys
import time
import json
import html as html_mod
import re
import datetime
import email.utils
import functools
import urllib.request
import urllib.parse
import urllib.error
from typing import Optional
import xml.etree.ElementTree as ET  # nosec B405

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "openrouter/free")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

MAX_ENTRIES_PER_SYSTEM = 10
MAX_ITEMS_PER_NEWS_SOURCE = 15
MAX_NEWS_ITEMS_PER_SYSTEM = 5


SCOPES = {
    "Cloud Security": {
        "targets": {
            "AWS": "Amazon Web Services",
            "Microsoft Azure": "Microsoft Azure",
            "Google Cloud Platform": "Google Cloud Platform",
            "Kubernetes": "Kubernetes",
            "Docker": "Docker",
            "Terraform": "Terraform",
        },
        "match_terms": {
            "AWS": ["aws", "amazon web services"],
            "Microsoft Azure": ["azure"],
            "Google Cloud Platform": ["google cloud", "gcp"],
            "Kubernetes": ["kubernetes", "k8s"],
            "Docker": ["docker"],
            "Terraform": ["terraform"],
        },
    },
}


SECURITY_NEWS_FEEDS = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("SecurityWeek", "https://feeds.feedburner.com/securityweek"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("Beehiiv Newsletter", "https://rss.beehiiv.com/feeds/xgTKUmMmUm.xml"),
    ("The Register", "https://www.theregister.com/?lab_viewport=rss"),
    ("The Record", "https://therecord.media/feed"),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/"),
    ("Schneier on Security", "https://www.schneier.com/feed/atom/"),
    ("SANS Internet Storm Center", "https://isc.sans.edu/rssfeed.xml"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml"),
]


BREACH_NEWS_FEEDS = [
    ("HIPAA Journal", "https://www.hipaajournal.com/feed/"),
    ("Have I Been Pwned", "https://haveibeenpwned.com/feed/breaches/"),
    ("Ransomware.live", "https://www.ransomware.live/rss.xml"),
    ("Security Affairs", "https://securityaffairs.com/feed"),
    ("Infosecurity Magazine", "https://www.infosecurity-magazine.com/rss/news/"),
]


DEVSECOPS_NEWS_FEEDS = [
    ("Snyk Blog", "https://snyk.io/blog/feed"),
    ("GitGuardian Blog", "https://blog.gitguardian.com/rss"),
    ("OpenSSF Blog", "https://openssf.org/feed"),
    ("Sonatype Blog", "https://sonatype.com/blog/rss.xml"),
    ("Datadog Security Labs", "https://securitylabs.datadoghq.com/rss/feed.xml"),
    ("Chainguard", "https://www.chainguard.dev/unchained/rss.xml"),
    ("Docker Blog", "https://www.docker.com/blog/feed/"),
    ("GitHub Security Blog", "https://github.blog/security/feed/"),
    ("Sysdig Blog", "https://sysdig.com/feed/"),
]

CLOUD_NEWS_FEEDS = [
    ("AWS News Blog", "https://aws.amazon.com/blogs/aws/feed/"),
    ("AWS Security Blog", "https://aws.amazon.com/blogs/security/feed/"),
    ("Microsoft Azure Blog", "https://azure.microsoft.com/en-us/blog/feed/"),
    ("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Google Cloud Blog", "https://cloudblog.withgoogle.com/rss"),
    ("Cloudflare Blog", "https://blog.cloudflare.com/rss/"),
    ("Wiz Blog", "https://www.wiz.io/feed/rss.xml"),
    ("Kubernetes Blog", "https://kubernetes.io/feed.xml"),
    ("CNCF Blog", "https://www.cncf.io/feed/"),
    ("HashiCorp Blog", "https://www.hashicorp.com/blog/feed.xml"),
    ("The New Stack", "https://thenewstack.io/feed"),
]

LOOKBACK_HOURS = int(os.environ.get("LOOKBACK_HOURS", "26"))
KEV_LOOKBACK_DAYS = int(os.environ.get("KEV_LOOKBACK_DAYS", "7"))
NEWS_LOOKBACK_HOURS = int(os.environ.get("NEWS_LOOKBACK_HOURS", "48"))
ENABLE_NEWS_FEEDS = os.environ.get("ENABLE_NEWS_FEEDS", "true").lower() != "false"


def http_get(url: str, headers: dict = None, timeout: int = 30, retries: int = 2):
    headers = headers or {}
    headers.setdefault("User-Agent", "security-digest/1.0 (+https://github.com/)")
    if not url.startswith("https://"):
        print(f"  [!] Refusing non-https URL: {url}", file=sys.stderr)
        return None
    last_err = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                return resp.read()
        except Exception as e:
            last_err = e
            if attempt < retries:
                time.sleep(3 * (attempt + 1))
    print(f"  [!] GET failed after retries: {url} ({last_err})", file=sys.stderr)
    return None


def nvd_fetch(keyword: str) -> list:
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(hours=LOOKBACK_HOURS)

    params = {
        "keywordSearch": keyword,
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": "50",
    }
    url = f"{NVD_BASE}?{urllib.parse.urlencode(params)}"

    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    raw = http_get(url, headers=headers, timeout=30)
    if raw is None:
        return []

    try:
        data = json.loads(raw.decode())
    except Exception as e:
        print(f"  [!] NVD JSON parse failed for '{keyword}': {e}", file=sys.stderr)
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        descriptions = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")[:600]

        metrics = cve.get("metrics", {})
        cvss_score, cvss_severity = None, None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_score = m.get("cvssData", {}).get("baseScore")
                cvss_severity = m.get("baseSeverity") or m.get("cvssData", {}).get("baseSeverity")
                break

        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

        results.append({
            "id": cve_id,
            "description": desc_en,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "references": refs[:3],
        })

    return results


def kev_fetch() -> list:
    raw = http_get(KEV_URL, timeout=30)
    if raw is None:
        return []

    try:
        data = json.loads(raw.decode())
    except Exception as e:
        print(f"  [!] KEV JSON parse failed: {e}", file=sys.stderr)
        return []

    cutoff = datetime.date.today() - datetime.timedelta(days=KEV_LOOKBACK_DAYS)
    recent = []
    for vuln in data.get("vulnerabilities", []):
        try:
            date_added = datetime.date.fromisoformat(vuln.get("dateAdded", ""))
        except ValueError:
            continue
        if date_added >= cutoff:
            recent.append(vuln)
    return recent


def match_kev_to_scope(kev_entries: list, match_terms: dict) -> dict:
    matched = {}
    for vuln in kev_entries:
        haystack = " ".join([
            vuln.get("vendorProject", ""),
            vuln.get("product", ""),
            vuln.get("vulnerabilityName", ""),
            vuln.get("shortDescription", ""),
        ]).lower()

        for label, terms in match_terms.items():
            if any(term in haystack for term in terms):
                matched.setdefault(label, []).append({
                    "id": vuln.get("cveID"),
                    "confirmed_exploited_by_cisa_kev": True,
                    "cvss_score": None,
                    "cvss_severity": "UNSCORED — CISA-confirmed active exploitation",
                    "vendor_project": vuln.get("vendorProject"),
                    "product": vuln.get("product"),
                    "vulnerability_name": vuln.get("vulnerabilityName"),
                    "description": vuln.get("shortDescription"),
                    "date_added_to_kev": vuln.get("dateAdded"),
                    "required_action": vuln.get("requiredAction"),
                    "due_date": vuln.get("dueDate"),
                    "known_ransomware_use": vuln.get("knownRansomwareCampaignUse"),
                    "references": [f"https://nvd.nist.gov/vuln/detail/{vuln.get('cveID')}"],
                })
    return matched


def merge_kev_into_collected(collected: dict, kev_matched: dict) -> dict:
    for label, kev_items in kev_matched.items():
        existing = collected.setdefault(label, [])
        existing_ids = {e["id"] for e in existing}
        for kev_item in kev_items:
            if kev_item["id"] in existing_ids:
                for e in existing:
                    if e["id"] == kev_item["id"]:
                        e["confirmed_exploited_by_cisa_kev"] = True
                        e["kev_required_action"] = kev_item.get("required_action")
                        e["kev_due_date"] = kev_item.get("due_date")
            else:
                existing.append(kev_item)
    return collected


def sort_entries_for_report(collected: dict) -> dict:
    for label, entries in collected.items():
        entries.sort(
            key=lambda e: (
                not e.get("confirmed_exploited_by_cisa_kev", False),
                -(e.get("cvss_score") or -1),
                e.get("id", ""),
            )
        )
        if len(entries) > MAX_ENTRIES_PER_SYSTEM:
            kept = entries[:MAX_ENTRIES_PER_SYSTEM]
            dropped = len(entries) - len(kept)
            print(f"    -> {label}: capping to top {MAX_ENTRIES_PER_SYSTEM} of {len(entries)} "
                  f"by priority ({dropped} lower-severity entries omitted from this run's report)")
            collected[label] = kept
    return collected


def _parse_rss_datetime(raw: str):
    if not raw:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except (TypeError, ValueError):
        pass
    try:
        cleaned = raw.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except ValueError:
        pass
    try:
        return datetime.datetime.strptime(raw.strip(), "%a, %d %b %Y").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def parse_feed(url: str, source_label: str = None) -> list:
    raw = http_get(url, timeout=20)
    if raw is None:
        return []

    if re.search(rb"<!ENTITY", raw, re.I):
        print(f"  [!] Feed rejected (ENTITY declarations not allowed): {url}", file=sys.stderr)
        return []
    try:
        root = ET.fromstring(raw)  # nosec B314
    except ET.ParseError as e:
        print(f"  [!] RSS parse failed for {url}: {e}", file=sys.stderr)
        return []

    items = []
    source = source_label or urllib.parse.urlparse(url).netloc

    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub = item.findtext("pubDate")
        summary = (item.findtext("description") or "").strip()
        items.append({"title": title, "link": link, "published": pub, "summary": summary[:500], "source": source})

    ns = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.findall(".//atom:entry", ns):
        title = (entry.findtext("atom:title", namespaces=ns) or "").strip()
        link_el = entry.find("atom:link", ns)
        link = link_el.get("href") if link_el is not None else ""
        pub = entry.findtext("atom:updated", namespaces=ns) or entry.findtext("atom:published", namespaces=ns)
        summary = (entry.findtext("atom:summary", namespaces=ns) or "").strip()
        items.append({"title": title, "link": link, "published": pub, "summary": summary[:500], "source": source})

    return items


def fetch_feed_list(labeled_urls: list, list_name: str, include_custom: bool = False) -> list:
    if not ENABLE_NEWS_FEEDS:
        print(f"[i] ENABLE_NEWS_FEEDS=false, skipping {list_name} news collection")
        return []

    labeled_urls = list(labeled_urls)
    if include_custom:
        custom = os.environ.get("CUSTOM_RSS_FEEDS", "").strip()
        if custom:

            labeled_urls += [(None, u.strip()) for u in custom.split(",") if u.strip()]

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=NEWS_LOOKBACK_HOURS)
    all_items = []
    seen_links = set()

    for label, url in labeled_urls:
        print(f"[*] Fetching {list_name} news feed: {label or url}")
        for item in parse_feed(url, source_label=label):
            link = item.get("link")
            if not link or link in seen_links:
                continue
            pub_dt = _parse_rss_datetime(item.get("published"))
            if pub_dt and pub_dt < cutoff:
                continue
            all_items.append(item)
            seen_links.add(link)
        time.sleep(1)

    print(f"[i] {len(all_items)} total raw {list_name} news item(s) collected")
    return all_items


def group_items_by_source(items: list) -> dict:
    grouped = {}
    for item in items:
        grouped.setdefault(item["source"], []).append(item)

    for source, source_items in grouped.items():
        source_items.sort(
            key=lambda i: _parse_rss_datetime(i.get("published")) or datetime.datetime.min.replace(tzinfo=datetime.timezone.utc),
            reverse=True,
        )
        grouped[source] = source_items[:MAX_ITEMS_PER_NEWS_SOURCE]

    return grouped


def build_google_news_feeds_for_scope(scope_targets: dict) -> dict:
    feeds = {}
    for label, keyword in scope_targets.items():
        q = urllib.parse.quote(f'"{keyword}" (vulnerability OR exploit OR CVE OR security patch)')
        feeds[label] = f"https://news.google.com/rss/search?q={q}%20when:2d&hl=en-US&gl=US&ceid=US:en"
    return feeds


def match_items_to_scope(items: list, match_terms: dict) -> dict:
    matched = {}
    for item in items:
        haystack = f"{item.get('title', '')} {item.get('summary', '')}".lower()
        for label, terms in match_terms.items():
            if any(term in haystack for term in terms):
                matched.setdefault(label, []).append(item)
                break
    return matched


def collect_news_for_scope(scope_cfg: dict, general_items: list) -> dict:
    if not ENABLE_NEWS_FEEDS:
        return {}

    matched = match_items_to_scope(general_items, scope_cfg["match_terms"])
    seen_links = {item["link"] for items in matched.values() for item in items}

    google_feeds = build_google_news_feeds_for_scope(scope_cfg["targets"])
    for label, url in google_feeds.items():
        for item in parse_feed(url):
            link = item.get("link")
            if not link or link in seen_links:
                continue
            matched.setdefault(label, []).append(item)
            seen_links.add(link)
        time.sleep(1)

    for label, items in matched.items():
        if len(items) > MAX_NEWS_ITEMS_PER_SYSTEM:
            print(f"    -> {label}: capping news mentions to {MAX_NEWS_ITEMS_PER_SYSTEM} of {len(items)}")

        matched[label] = [
            {**item, "summary": (item.get("summary") or "")[:150]}
            for item in items[:MAX_NEWS_ITEMS_PER_SYSTEM]
        ]

    return matched


def collect_scope(scope_name: str, scope_cfg: dict, kev_entries: list, general_news_items: list) -> tuple:
    print(f"\n[*] === Scope: {scope_name} ===")
    collected = {}
    for label, keyword in scope_cfg["targets"].items():
        print(f"[*] Querying NVD for {label}...")
        entries = nvd_fetch(keyword)
        if entries:
            collected[label] = entries
            print(f"    -> {len(entries)} result(s)")
        else:
            print("    -> none")
        time.sleep(6)

    kev_matched = match_kev_to_scope(kev_entries, scope_cfg["match_terms"])
    total_kev_hits = sum(len(v) for v in kev_matched.values())
    print(f"    -> {total_kev_hits} KEV match(es) for this scope")
    collected = merge_kev_into_collected(collected, kev_matched)
    collected = sort_entries_for_report(collected)

    news = collect_news_for_scope(scope_cfg, general_news_items)
    total_news = sum(len(v) for v in news.values())
    print(f"    -> {total_news} scope-matched news item(s)")

    return collected, news


def collect_all() -> tuple:
    print("[*] Fetching Security news feeds (for the unfiltered Security row)...")
    general_items = fetch_feed_list(SECURITY_NEWS_FEEDS, "Security", include_custom=True)

    print("\n[*] Checking CISA KEV catalog (fetched once, matched per scope)...")
    kev_entries = kev_fetch()
    print(f"    -> {len(kev_entries)} total KEV addition(s) in the last {KEV_LOOKBACK_DAYS} day(s)")

    collected_by_scope = {}
    news_by_scope = {}
    for scope_name, scope_cfg in SCOPES.items():
        collected, news = collect_scope(scope_name, scope_cfg, kev_entries, general_items)
        collected_by_scope[scope_name] = collected
        news_by_scope[scope_name] = news

    return general_items, collected_by_scope, news_by_scope


def build_prompt_for_scope(scope_name: str, collected: dict, news: dict) -> str:
    return f"""You are a security analyst producing a daily digest for a security engineer
responsible for cloud and application infrastructure.

IMPORTANT: Output ONLY the final Markdown report. Do not think out loud, do not show your
reasoning process, do not narrate how you're analyzing or sorting the data. Go straight to
the finished report text.

Produce a report for ONE scope: "{scope_name}". Use this exact structure:

## {scope_name}

One-paragraph executive summary, highlighting the single most urgent item (a CISA KEV-confirmed
entry always outranks a merely high-CVSS entry, since it's confirmed exploitation vs. theoretical
severity).

### Formal Vulnerabilities
Skip any system with no formal vulnerability entries. For EACH entry:

#### [System Name] — [CVE ID] (CVSS [score or "UNSCORED"] [severity]) [add "🔴 ACTIVELY EXPLOITED (CISA KEV)" if confirmed_exploited_by_cisa_kev is true]
**Summary:** Plain-English explanation in 1-3 sentences -- what it is, how it's triggered, who
can exploit it (auth required? network-reachable?). If it's a KEV entry with a due_date, state it.

**Affected Features / Interoperability:** What specific feature, service, module, or component
is impacted, and what downstream functionality or integrations could break (e.g. for databases:
replication, client drivers, extensions; for cloud: IAM policies, networking, orchestration). If
the raw data doesn't say, state that plainly rather than guessing.

**Source:** List the reference URL(s).

**Actions:**
- Fix: official patched version/release, if known
- Workaround: concrete interim mitigation if no immediate patch is possible
- Tradeoff: what the workaround itself breaks or degrades. Say "No significant tradeoff" if none.

### News & Community Mentions
Only include this subsection if there's news/forum data below. A short bullet list per system:
one line per item with a 1-sentence plain-English gist, the source name, and the link. Label
this unverified chatter, separate from the Formal Vulnerabilities above.

FORMAL VULNERABILITY DATA (from NVD + CISA KEV), grouped by system. Entries within each system
are ALREADY SORTED (KEV-confirmed first, then CVSS descending) -- present them in this order,
do not re-sort. If a system has more than {MAX_ENTRIES_PER_SYSTEM} entries, only the top
{MAX_ENTRIES_PER_SYSTEM} by priority are included; say so if relevant, don't imply completeness.
{json.dumps(collected, separators=(',', ':'))}

NEWS/FORUM MENTIONS (supplementary, NOT authoritative -- do not invent CVE numbers from this
data). Capped at {MAX_NEWS_ITEMS_PER_SYSTEM} items per system.
{json.dumps(news, separators=(',', ':'))}

Do not fabricate CVE IDs, scores, version numbers, or details beyond what's given above. If data
for an entry is too sparse for a real summary, say so.
"""


def strip_leaked_reasoning(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)

    lines = text.split("\n")
    report_start_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith("## ") and any(s.lower() in line.lower() for s in SCOPES):
            report_start_idx = i
            break
    if report_start_idx is not None and report_start_idx > 0:
        text = "\n".join(lines[report_start_idx:])

    return text.strip()


def looks_like_broken_reasoning_dump(text: str, expected_entry_count: int) -> bool:
    if len(text) > max(40000, expected_entry_count * 1200):
        return True

    lines = [l.strip() for l in text.split("\n") if l.strip()]

    max_consecutive_run = 1
    current_run = 1
    for i in range(1, len(lines)):
        if lines[i] == lines[i - 1]:
            current_run += 1
            max_consecutive_run = max(max_consecutive_run, current_run)
        else:
            current_run = 1

    if max_consecutive_run >= 6:
        return True

    return False


def call_llm(prompt: str, expected_entry_count: int = 0, label: str = "") -> Optional[str]:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        print("[!] OPENROUTER_API_KEY not set", file=sys.stderr)
        return None

    tag = f" [{label}]" if label else ""

    body = {
        "model": OPENROUTER_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 8192,
        "reasoning": {"effort": "low", "exclude": True},
    }

    last_err = None
    for attempt in range(3):
        body["max_tokens"] = 8192 if attempt == 0 else 16384
        req = urllib.request.Request(
            OPENROUTER_URL,
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer": "https://github.com/",
                "X-Title": "security-digest",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=90) as resp:  # nosec B310
                data = json.loads(resp.read().decode())
            content = data["choices"][0]["message"]["content"]

            if not content or not content.strip():
                finish = data["choices"][0].get("finish_reason")
                usage = data.get("usage")
                last_err = (f"model returned empty content (finish_reason={finish}, usage={usage}, "
                            f"model={data.get('model')}); likely spent its token budget on reasoning")
                print(f"  [!]{tag} Attempt {attempt + 1}: {last_err}", file=sys.stderr)
                if attempt < 2:
                    time.sleep(10)
                    continue
                break

            content = strip_leaked_reasoning(content)

            if looks_like_broken_reasoning_dump(content, expected_entry_count):
                last_err = "response looked like a stuck reasoning loop, not a report"
                print(
                    f"  [!]{tag} Attempt {attempt + 1}: {last_err} "
                    f"(response length: {len(content)} chars, expected_entry_count: {expected_entry_count}), retrying...",
                    file=sys.stderr,
                )
                if attempt < 2:
                    time.sleep(10)
                    continue
                print(f"  [!]{tag} Gave up after 3 attempts, returning truncated content", file=sys.stderr)
                return content[:5000] + "\n\n*(Report was truncated -- the model's response looked malformed. Check the Action log.)*"

            print(f"[i]{tag} LLM response accepted ({len(content)} chars)")
            return content
        except urllib.error.HTTPError as e:
            err_body = e.read().decode() if e.fp else ""
            last_err = f"{e.code} {e.reason} {err_body}"
            if e.code in (429, 500, 502, 503) and attempt < 2:
                time.sleep(15 * (attempt + 1))
                continue
            break
        except (KeyError, IndexError) as e:

            error_detail = data.get("error") if isinstance(data, dict) else None
            raw_snippet = json.dumps(data)[:500] if isinstance(data, dict) else str(data)[:500]
            last_err = f"unexpected response shape ({e}). error field: {error_detail}. raw (truncated): {raw_snippet}"
            print(f"  [!]{tag} Attempt {attempt + 1}: {last_err}", file=sys.stderr)
            if attempt < 2:
                time.sleep(15 * (attempt + 1))
                continue
            break
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                time.sleep(15 * (attempt + 1))
                continue
            break

    print(f"[!]{tag} OpenRouter call failed after all retries: {last_err}", file=sys.stderr)
    return None


CVE_HEADER_RE = re.compile(
    r'^(?P<system>.+?)\s+—\s+(?P<cve>CVE-\d{4}-[\dNA]+)\s+\((?:CVSS\s+)?(?P<score>[\d.]+|UNSCORED)'
    r'(?:\s+(?P<sevword>[A-Za-z]+))?\)(?P<rest>.*)$'
)


def _classify_severity(score: str, sevword: str, rest_text: str) -> tuple:
    is_kev = "ACTIVELY EXPLOITED" in rest_text.upper() or "🔴" in rest_text
    if is_kev:
        return "critical", True
    if sevword and sevword.lower() in ("critical", "high", "medium", "low"):
        return sevword.lower(), False
    if score and score != "UNSCORED":
        try:
            f = float(score)
            if f >= 9.0:
                return "critical", False
            if f >= 7.0:
                return "high", False
            if f >= 4.0:
                return "medium", False
            return "low", False
        except ValueError:
            pass
    return "unscored", False


def markdown_to_html(md: str) -> str:
    lines = md.split("\n")
    out = []
    in_list = False
    in_card = False

    def inline(text: str) -> str:
        text = html_mod.escape(text)
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
        text = re.sub(r"\[([^\]]+)\]\((https?://[^\s)]+)\)", r'<a href="\2">\1</a>', text)
        text = re.sub(r'(?<!href=")(?<!>)(https?://[^\s<]+)', r'<a href="\1">\1</a>', text)
        return text

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    def close_card():
        nonlocal in_card
        if in_card:
            out.append("</div></div>")
            in_card = False

    for raw_line in lines:
        stripped = raw_line.strip()

        if stripped.startswith("#### "):
            heading_text = stripped[5:]
            m = CVE_HEADER_RE.match(heading_text)
            close_list()
            if m:
                close_card()
                system = inline(m.group("system"))
                cve = html_mod.escape(m.group("cve"))
                score = m.group("score")
                sevword = m.group("sevword")
                rest = m.group("rest") or ""
                severity, is_kev = _classify_severity(score, sevword, rest)
                score_label = f"CVSS {score}" if score != "UNSCORED" else "UNSCORED"
                if sevword and score != "UNSCORED":
                    score_label += f" · {sevword.upper()}"
                kev_badge = (
                    '<span class="badge badge-kev">Actively exploited · CISA KEV</span>'
                    if is_kev else ""
                )
                out.append(
                    f'<div class="vuln-card sev-{severity}"><div class="vuln-card-head">'
                    f'<span class="vuln-system">{system}</span>'
                    f'<span class="badge badge-cve">{cve}</span>'
                    f'<span class="badge badge-cvss sev-{severity}">{score_label}</span>'
                    f'{kev_badge}'
                    f'</div><div class="vuln-card-body">'
                )
                in_card = True
            else:
                close_card()
                out.append(f'<h4 class="mention-group">{inline(heading_text)}</h4>')
        elif stripped.startswith("### "):
            close_list()
            close_card()
            out.append(f"<h3>{inline(stripped[4:])}</h3>")
        elif stripped.startswith("## "):
            close_list()
            close_card()
            out.append(f"<h2>{inline(stripped[3:])}</h2>")
        elif stripped.startswith("# "):
            close_list()
            close_card()
            out.append(f"<h1>{inline(stripped[2:])}</h1>")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(stripped[2:])}</li>")
        elif stripped == "":
            close_list()
        else:
            close_list()
            out.append(f"<p>{inline(stripped)}</p>")

    close_list()
    close_card()
    return "\n".join(out)


PAGE_CSS = """
@font-face {
    font-family: 'Mando';
    src: local('Mando'), url("/media/mandaloretitle.ttf");
    font-display: swap;
}

:root {
    --bg: #181a1b;
    --surface: rgba(24, 26, 27, 0.6);
    --surface-2: rgba(255, 255, 255, 0.05);
    --border: rgba(255, 255, 255, 0.08);
    --text: #ffffff;
    --text-dim: rgba(255, 255, 255, 0.65);
    --text-faint: rgba(255, 255, 255, 0.45);
    --link: #cce6ff;
    --sev-critical: #d84a43;
    --sev-high: #FFA94D;
    --sev-medium: #FFD43B;
    --sev-low: #7C8B9A;
    --sev-unscored: #6B7C93;
    --row-security: #43d854;
    --row-breach: #FF8A5B;
    --row-devsecops: #B98EFF;
    --row-cloud: #5EA8FF;
    --mono: "Monaco", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
    --display: 'Mando', "Monaco", "SF Mono", Menlo, Consolas, monospace;
    --shadow-card: 0 0 5px 0 rgba(0, 0, 0, 0.7), 0 6px 20px 0 rgba(0, 0, 0, 0.7);
    --glow-col: 0 0 2.5px 0 rgba(255, 255, 255, 0.7), 0 3px 10px 0 rgba(255, 255, 255, 0.7);
}

* { box-sizing: border-box; }

html {
    margin: 0;
    padding: 0;
    background: var(--bg);
    scroll-behavior: smooth;
}
html::before {
    content: ""; position: fixed; left: 0; top: 0; width: 100%; height: 100vh; height: 100lvh;
    background-image: linear-gradient(rgba(24, 26, 27, .6), rgba(24, 26, 27, .6)), url("/media/grid2.png");
    background-position: center bottom; background-size: cover; background-repeat: no-repeat;
    z-index: -1; pointer-events: none; transform: translateZ(0);
}

@media (prefers-reduced-motion: reduce) {
    html { scroll-behavior: auto; }
    * { transition: none !important; animation: none !important; }
}

::selection {
    background: rgb(204, 230, 255);
    color: black;
}

body {
    font-family: var(--mono);
    max-width: 1760px;
    margin: 0 auto;
    padding: 0 1.25rem 4rem;
    line-height: 1.6;
    color: var(--text);
    background: transparent;
    font-size: 14px;
    overflow-x: hidden;
    overflow-x: clip;
}

.text-section, .news-column, .media-panel, .audio-card { overflow-wrap: anywhere; }

hr {
    box-shadow: 0 2px 5px 0 rgba(0, 0, 0, 0.7), 0 6px 20px 0 rgba(0, 0, 0, 0.7);
}

/* header */

.page-header {
    padding: 2.5rem 0 1.5rem;
    margin-bottom: 1rem;
    text-align: center;
    animation: slide-in-top 0.8s ease both;
}
.page-header .eyebrow {
    font-family: var(--mono);
    font-size: 0.72rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    color: var(--text-faint);
    margin: 0 0 0.5rem;
}
h1 {
    font-family: var(--display);
    font-size: 2rem;
    font-weight: normal;
    margin: 0 0 0.35rem;
    letter-spacing: 0.04em;
}
.page-header .meta { color: var(--text-dim); font-size: 0.8rem; margin: 0; }
.back-link {
    display: inline-block; margin: 1rem 0 0; color: var(--text-dim);
    font-family: var(--mono); font-size: 0.8rem; text-decoration: none;
    transition: color 0.3s;
}
.back-link:hover { color: var(--text); text-decoration: underline; }

/* nav */

.quick-nav {
    position: sticky; top: 0; z-index: 10;
    display: flex; justify-content: center; gap: 0.25rem; flex-wrap: wrap;
    background: rgba(24, 26, 27, 0.94);
    backdrop-filter: blur(6px);
    padding: 0.6rem 0;
    margin-bottom: 2rem;
    animation: fadeIn 2s ease both;
}
.quick-nav a {
    font-family: var(--mono);
    font-size: 0.8rem;
    color: white;
    text-decoration: none;
    padding: 0.25em 0.7em;
    border-radius: 0.25em;
    background: transparent;
    transition: all 0.4s ease;
}
.quick-nav a:hover { color: black; background: whitesmoke; }

/* section headers */

.row-header {
    display: flex; align-items: center; gap: 0.7rem;
    margin: 3.5rem 0 1rem; scroll-margin-top: 4.5rem;
    animation: float-in-left 0.8s ease both;
}
.row-header .dot { width: 8px; height: 8px; border-radius: 50%; flex: none; }
.row-header h2 {
    margin: 0; font-family: var(--display); font-size: 1.2rem; font-weight: normal;
    letter-spacing: 0.08em; color: var(--text); border: none; padding: 0;
}
.row-header .count { font-family: var(--mono); font-size: 0.72rem; color: var(--text-faint); }
.row-security .dot { background: var(--row-security); box-shadow: 0 0 6px var(--row-security); }
.row-breach .dot { background: var(--row-breach); box-shadow: 0 0 6px var(--row-breach); }
.row-devsecops .dot { background: var(--row-devsecops); box-shadow: 0 0 6px var(--row-devsecops); }
.row-cloud .dot { background: var(--row-cloud); box-shadow: 0 0 6px var(--row-cloud); }

/* news columns */

.news-grid-wrapper {
    overflow-x: auto; -webkit-overflow-scrolling: touch;
    margin: 0 0 1rem; padding: 0.75rem 0 1.5rem 40px;
    scrollbar-width: thin; scrollbar-color: rgba(255, 255, 255, 0.15) transparent;
    -webkit-mask-image: linear-gradient(to right, transparent 0, #000 40px, #000 calc(100% - 40px), transparent 100%);
    mask-image: linear-gradient(to right, transparent 0, #000 40px, #000 calc(100% - 40px), transparent 100%);
}
.news-grid {
    display: grid; grid-auto-flow: column; grid-auto-columns: 290px;
    gap: 1.25rem; width: max-content; padding-right: 40px;
}
.news-column {
    position: relative;
    min-width: 0; display: flex; flex-direction: column; max-height: 560px;
    background: var(--surface); border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 1em; overflow: hidden;
    box-shadow: var(--shadow-card);
    animation: float-in-left 0.8s ease both;
}
.news-column::after {
    content: ''; position: absolute; left: 0; right: 0; bottom: 0; height: 36px;
    background: linear-gradient(to bottom, rgba(24, 26, 27, 0), rgba(24, 26, 27, 0.9));
    pointer-events: none;
}
.news-column h4 {
    margin: 0; padding: 0.5rem 0.85rem; flex-shrink: 0;
    font-family: var(--display); font-size: 1rem; font-weight: normal;
    letter-spacing: 0.15em; color: var(--text-faint);
    background: var(--surface-2); border-bottom: 1px solid var(--border);
}
.news-column ul {
    list-style: none; margin: 0; padding: 0.5rem 0.85rem 2.25rem;
    flex: 1; overflow-y: auto;
    scrollbar-width: thin; scrollbar-color: rgba(255, 255, 255, 0.15) transparent;
}
.news-column ul::-webkit-scrollbar { width: 4px; }
.news-column ul::-webkit-scrollbar-track { background: transparent; }
.news-column ul::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.15); border-radius: 2px; }
.news-column li { padding: 0.6rem 0; margin: 0; border-bottom: 1px solid rgba(255, 255, 255, 0.06); }
.news-column li:last-child { border-bottom: none; }
.news-column a {
    color: rgba(255, 255, 255, 0.95); text-decoration: none;
    font-size: 0.82rem; line-height: 1.5; transition: color 0.2s;
}
.news-column a:hover { color: var(--link); }
.news-column .item-date {
    display: block; font-family: var(--mono); color: var(--text-faint);
    font-size: 0.7rem; margin-top: 0.25rem;
}

/* vulnerability tracking */

h2 {
    margin: 3.5rem 0 0.6rem; font-family: var(--display); font-size: 1.4rem;
    font-weight: normal; letter-spacing: 0.06em; color: var(--text);
    border: none; padding: 0; scroll-margin-top: 4.5rem; text-align: center;
}
h2 + p { color: var(--text-dim); margin: 0 auto 1.25rem; max-width: 68ch; }
h3 {
    margin: 2rem 0 0.9rem; font-family: var(--display); font-size: 0.95rem; font-weight: normal;
    letter-spacing: 0.15em; text-transform: uppercase; color: var(--text-faint); border: none;
}
p { margin: 0.6rem 0; }
a { color: var(--link); }
ul { padding-left: 1.3rem; margin: 0.6rem 0; }
li { margin: 0.3rem 0; }

.vuln-card {
    background: var(--surface); border: 1px solid rgba(255, 255, 255, 0.12);
    border-left: 4px solid var(--sev-unscored);
    border-radius: 1em; padding: 1rem 1.25rem; margin-bottom: 1.25rem;
    box-shadow: var(--shadow-card);
    animation: float-in-left 0.8s ease both;
}
.vuln-card.sev-critical { border-left-color: var(--sev-critical); }
.vuln-card.sev-high { border-left-color: var(--sev-high); }
.vuln-card.sev-medium { border-left-color: var(--sev-medium); }
.vuln-card.sev-low { border-left-color: var(--sev-low); }
.vuln-card-head { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem; margin-bottom: 0.7rem; }
.vuln-system { font-weight: bold; font-size: 0.95rem; color: rgba(255, 255, 255, 0.95); }
.badge {
    font-family: var(--mono); font-size: 0.72rem; padding: 0.18rem 0.55rem;
    border-radius: 0.4em; white-space: nowrap;
}
.badge-cve { background: var(--surface-2); color: var(--text-dim); border: 1px solid var(--border); }
.badge-cvss { color: #181a1b; font-weight: bold; }
.badge-cvss.sev-critical { background: var(--sev-critical); color: white; }
.badge-cvss.sev-high { background: var(--sev-high); }
.badge-cvss.sev-medium { background: var(--sev-medium); }
.badge-cvss.sev-low { background: var(--sev-low); color: white; }
.badge-cvss.sev-unscored { background: var(--surface-2); color: var(--text-dim); border: 1px solid var(--border); font-weight: normal; }
.badge-kev {
    background: rgba(216, 74, 67, 0.15); color: #ff8b85; border: 1px solid rgba(216, 74, 67, 0.5);
    text-transform: uppercase; letter-spacing: 0.04em; font-size: 0.68rem;
}
.vuln-card-body p { color: var(--text-dim); font-size: 0.82rem; line-height: 1.55; }
.vuln-card-body strong { color: rgba(255, 255, 255, 0.95); }
.vuln-card-body ul { font-size: 0.82rem; color: var(--text-dim); }
.vuln-card-body a { word-break: break-word; }
h4.mention-group {
    margin: 1.5rem 0 0.5rem; font-family: var(--display); font-size: 0.95rem; font-weight: normal;
    letter-spacing: 0.1em; color: var(--text); border: none; background: none; padding: 0;
}

/* archive */

.archive-list { list-style: none; padding: 0; display: flex; flex-wrap: wrap; justify-content: center; gap: 0.5rem; }
.archive-list li { margin: 0; }
.archive-list a {
    display: inline-block; font-family: var(--mono); font-size: 0.78rem;
    color: white; text-decoration: none; padding: 0.35rem 0.8rem;
    border: 1px solid var(--border); border-radius: 0.4em; transition: all 0.4s ease;
}
.archive-list a:hover { color: black; background: whitesmoke; border-color: whitesmoke; }

/* animations */

@keyframes slide-in-top {
    from { opacity: 0; transform: translateY(-40px); }
    to { opacity: 1; transform: translateY(0); }
}
@keyframes float-in-left {
    from { opacity: 0; transform: translateX(-40px); }
    to { opacity: 1; transform: translateX(0); }
}
@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

/* layout: news left, media panel right */

.layout { display: grid; grid-template-columns: minmax(0, 1fr) 440px; gap: 3.5rem; align-items: start; }
.news-side { min-width: 0; }
.text-section { max-width: 1180px; margin: 0 auto; }
.media-slot { align-self: stretch; }
.media-sticky { position: sticky; top: 0; height: 100vh; display: flex; align-items: center; }
.media-sticky .media-panel { max-height: calc(100vh - 2rem); overflow-y: auto; width: 100%; }
.media-panel {
    background: var(--surface); border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 1em; box-shadow: var(--shadow-card); padding: 0.9rem;
}
.media-panel h3 { margin: 0 0 0.6rem; font-family: var(--display); font-weight: normal; letter-spacing: 0.08em; font-size: 1rem; }
.media-tabs { display: flex; flex-wrap: wrap; gap: 0.4rem; margin-bottom: 0.7rem; }
.media-tab {
    font: inherit; font-size: 0.75rem; color: var(--text-dim); background: transparent; cursor: pointer;
    border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 999px; padding: 0.2rem 0.7rem;
}
.media-tab.active, .media-tab:hover { color: black; background: whitesmoke; }
.media-frame { display: none; }
.media-frame.active { display: block; }
.media-frame iframe { width: 100%; aspect-ratio: 16 / 9; border: 0; border-radius: 0.6em; background: #000; display: block; }
.media-panel .audio-heading { margin: 1.4rem 0 0.4rem; font-family: var(--display); font-weight: normal; letter-spacing: 0.08em; font-size: 1rem; }
.media-panel > h3:first-child { margin-top: 0; }
.audio-card { padding: 0.7rem 0; border-top: 1px solid rgba(255, 255, 255, 0.08); }
.audio-label { font-size: 0.7rem; color: var(--text-faint); letter-spacing: 0.08em; text-transform: uppercase; }
.audio-title { font-size: 0.8rem; line-height: 1.4; margin: 0.2rem 0; }
.audio-title a { color: var(--link); text-decoration: none; }
.audio-card .item-date { font-size: 0.7rem; color: var(--text-faint); }
.audio-card audio { width: 100%; height: 36px; margin-top: 0.4rem; }
.media-open { display: inline-block; margin-top: 0.6rem; font-size: 0.75rem; color: var(--link); }

/* responsive */

/* very wide screens: main column centered on the page, media panel in the right margin */
@media (min-width: 1900px) {
    body { max-width: none; }
    .layout { grid-template-columns: minmax(488px, 1fr) minmax(0, 1180px) minmax(488px, 1fr); gap: 0; }
    .news-side { grid-column: 2; }
    .media-slot { grid-column: 3; justify-self: end; width: 440px; }
}
@media (max-width: 1000px) {
    .layout { grid-template-columns: minmax(0, 1fr); }
    .media-slot { order: -1; align-self: auto; }
    .media-sticky { position: static; height: auto; display: block; }
    .media-sticky .media-panel { max-width: 480px; margin: 1.25rem auto 0; max-height: none; overflow: visible; }
}
@media (max-width: 760px) {
    h1 { font-size: 1.5rem; }
    .news-grid { grid-auto-columns: 260px; }
}
@media (max-width: 620px) {
    body { font-size: 13px; }
    .quick-nav { justify-content: flex-start; overflow-x: auto; flex-wrap: nowrap; }
    .vuln-card { padding: 0.9rem 1rem; box-shadow: 0 0 3px rgba(0, 0, 0, 0.5), 0 3px 10px rgba(0, 0, 0, 0.5); }
}
"""


def render_raw_news_columns_html(grouped_items: dict) -> str:
    if not grouped_items:
        return "<p><em>No news items collected this run.</em></p>"

    columns = []
    for source, items in sorted(grouped_items.items()):
        list_items = []
        for item in items:
            title = html_mod.escape(html_mod.unescape(item.get("title", "(untitled)")))
            link = html_mod.escape(item.get("link", "#"))
            pub = item.get("published") or ""
            list_items.append(
                f'<li><a href="{link}">{title}</a><span class="item-date">{html_mod.escape(pub)}</span></li>'
            )
        columns.append(
            f'<div class="news-column"><h4>{html_mod.escape(source)}</h4><ul>{"".join(list_items)}</ul></div>'
        )

    return f'<div class="news-grid-wrapper"><div class="news-grid">{"".join(columns)}</div></div>'


def _row_header(anchor_id: str, label: str, count: int, row_class: str) -> str:
    noun = "item" if count == 1 else "items"
    return (
        f'<div class="row-header {row_class}" id="{anchor_id}">'
        f'<span class="dot"></span><h2>{html_mod.escape(label)}</h2>'
        f'<span class="count">{count} {noun}</span></div>'
    )


def _count_news_items(grouped_html: str) -> int:
    return grouped_html.count('<li><a href=')


# Media panel beside the news rows. Each entry is (tab label, embed URL, "Open" link).
# The YouTube entry embeds the channel's uploads playlist, so it shows the latest
# episode and the live stream while one is running. Any https iframe embed works
# (Spotify, Apple Podcasts, Twitch, ...).
MEDIA_PANELS = [
    ("Simply Cyber",
     "https://www.youtube-nocookie.com/embed/videoseries?list=UUG-48Ki-b6W_siaUkukJOSw",
     "https://www.youtube.com/channel/UCG-48Ki-b6W_siaUkukJOSw/live"),
]


# Daily audio briefs: (label, podcast RSS feed, optional title prefix to pick one show out of a mixed feed).
AUDIO_PODCASTS = [
    ("SANS Stormcast", "https://isc.sans.edu/dailypodcast.xml", ""),
    ("Risky Bulletin", "https://risky.biz/feeds/risky-business-news/", "Risky Bulletin"),
]


def fetch_latest_episode(feed_url: str, title_prefix: str = "") -> Optional[dict]:
    raw = http_get(feed_url, timeout=20)
    if raw is None or re.search(rb"<!ENTITY", raw, re.I):
        return None
    try:
        root = ET.fromstring(raw)  # nosec B314
    except ET.ParseError:
        return None
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        enc = item.find("enclosure")
        audio = enc.get("url", "") if enc is not None else ""
        if title.startswith(title_prefix) and audio.startswith("https://"):
            return {"title": title, "audio": audio, "link": (item.findtext("link") or "").strip(),
                    "published": item.findtext("pubDate") or ""}
    return None


@functools.lru_cache(maxsize=1)
def render_audio_html() -> str:
    cards = []
    for label, feed_url, prefix in AUDIO_PODCASTS:
        print(f"[*] Fetching podcast feed: {label}")
        ep = fetch_latest_episode(feed_url, prefix)
        if not ep:
            continue
        link = ep["link"] if ep["link"].startswith("https://") else ""
        title = html_mod.escape(html_mod.unescape(ep["title"]))
        title_html = f'<a href="{html_mod.escape(link)}" target="_blank" rel="noopener">{title}</a>' if link else title
        cards.append(
            f'<div class="audio-card"><div class="audio-label">{html_mod.escape(label)}</div>'
            f'<div class="audio-title">{title_html}</div>'
            f'<div class="item-date">{html_mod.escape(ep["published"])}</div>'
            f'<audio controls preload="none" src="{html_mod.escape(ep["audio"])}"></audio></div>'
        )
    return f'<h3 class="audio-heading">Daily Audio</h3>{"".join(cards)}' if cards else ""


def render_media_panel_html() -> str:
    audio = render_audio_html()
    if not MEDIA_PANELS and not audio:
        return ""
    tabs = "".join(
        f'<button type="button" class="media-tab{" active" if i == 0 else ""}" data-i="{i}">'
        f'{html_mod.escape(label)}</button>'
        for i, (label, _, _) in enumerate(MEDIA_PANELS)
    )
    frames = "".join(
        f'<div class="media-frame{" active" if i == 0 else ""}">'
        f'<iframe src="{html_mod.escape(embed)}" title="{html_mod.escape(label)}" loading="lazy" '
        f'allow="encrypted-media; picture-in-picture; fullscreen" allowfullscreen '
        f'referrerpolicy="strict-origin-when-cross-origin"></iframe>'
        f'<a class="media-open" href="{html_mod.escape(link)}" target="_blank" rel="noopener">Open on source &rarr;</a></div>'
        for i, (label, embed, link) in enumerate(MEDIA_PANELS)
    )
    script = (
        "<script>document.querySelectorAll('.media-tab').forEach(function(b){b.addEventListener('click',function(){"
        "var i=b.dataset.i;document.querySelectorAll('.media-tab').forEach(function(x){x.classList.toggle('active',x===b)});"
        "document.querySelectorAll('.media-frame').forEach(function(f,j){f.classList.toggle('active',String(j)===i)});"
        "});});</script>"
    ) if len(MEDIA_PANELS) > 1 else ""
    video = (f'<h3>Live &amp; Latest</h3><div class="media-tabs">{tabs}</div>{frames}') if MEDIA_PANELS else ""
    return f'<aside class="media-panel">{video}{audio}</aside>{script}'


def _news_layout_html(top_html: str, news_rows: list, tail_html: str) -> str:
    return (f'<div class="layout"><div class="news-side">{top_html}{QUICK_NAV}{_news_rows_html(news_rows)}'
            f'<div class="text-section">{tail_html}</div></div>'
            f'<div class="media-slot"><div class="media-sticky">{render_media_panel_html()}</div></div></div>')


QUICK_NAV = """<nav class="quick-nav">
<a href="#security-news">Security</a>
<a href="#breach-news">Breaches</a>
<a href="#devsecops-news">DevSecOps</a>
<a href="#cloud-news">Cloud</a>
<a href="#vuln-tracking">Vulnerabilities</a>
<a href="#archive">Archive</a>
</nav>"""


def _news_rows_html(news_rows: list) -> str:
    return "\n".join(
        f"{_row_header(anchor, label, _count_news_items(row_html), css_class)}\n{row_html}"
        for anchor, label, css_class, row_html in news_rows
    )


def _fetch_news_row_html(feeds: list, name: str) -> str:
    print(f"\n[*] Fetching {name} news feeds (unfiltered {name} row)...")
    items = fetch_feed_list(feeds, name)
    return render_raw_news_columns_html(group_items_by_source(items))


def write_report_page(news_rows: list, bottom_report_md: str, date_str: str, docs_dir: str) -> str:
    reports_dir = os.path.join(docs_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    bottom_html = markdown_to_html(bottom_report_md)
    top_html = (f'<a class="back-link" href="../index.html">&larr; All reports</a>'
                f'<div class="page-header"><p class="eyebrow">Daily Digest</p>'
                f'<h1>Security Digest — {date_str}</h1></div>')
    tail_html = (f'<h2 id="vuln-tracking" style="scroll-margin-top:4.5rem;">Scoped Vulnerability Tracking</h2>'
                 f'{bottom_html}')
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Digest — {date_str}</title>
<style>{PAGE_CSS}</style>
</head>
<body>
{_news_layout_html(top_html, news_rows, tail_html)}
</body>
</html>"""

    rel_path = f"reports/{date_str}.html"
    with open(os.path.join(docs_dir, rel_path), "w") as f:
        f.write(page)
    return rel_path


def rebuild_dashboard_index(docs_dir: str, latest_date: str, news_rows: list, bottom_report_md: str):
    reports_dir = os.path.join(docs_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    existing = sorted(
        (f[:-5] for f in os.listdir(reports_dir) if f.endswith(".html")),
        reverse=True,
    )
    archive_items = "\n".join(
        f'<li><a href="reports/{d}.html">{d}</a></li>' for d in existing if d != latest_date
    )

    bottom_html = markdown_to_html(bottom_report_md)
    top_html = (f'<div class="page-header"><p class="eyebrow">Updated daily</p><h1>Security Digest</h1>'
                f'<p class="meta">Latest run: {latest_date}</p></div>')
    tail_html = (f'<h2 id="vuln-tracking" style="scroll-margin-top:4.5rem;">Scoped Vulnerability Tracking</h2>'
                 f'{bottom_html}'
                 f'<h2 id="archive" style="scroll-margin-top:4.5rem;">Archive</h2>'
                 f'<ul class="archive-list">\n{archive_items}\n</ul>')

    index = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Digest</title>
<style>{PAGE_CSS}</style>
</head>
<body>
{_news_layout_html(top_html, news_rows, tail_html)}
</body>
</html>"""

    with open(os.path.join(docs_dir, "index.html"), "w") as f:
        f.write(index)

    nojekyll_path = os.path.join(docs_dir, ".nojekyll")
    if not os.path.exists(nojekyll_path):
        open(nojekyll_path, "w").close()


def fallback_report_md(scope_name: str, collected: dict, news: dict) -> str:
    """Plain-Python report used when the free LLM can't produce one. Same markdown shape, no AI text."""
    entries = sorted(
        ((system, e) for system, items in collected.items() for e in items),
        key=lambda se: (not se[1].get("confirmed_exploited_by_cisa_kev"), -(se[1].get("cvss_score") or 0)),
    )
    kev_count = sum(1 for _, e in entries if e.get("confirmed_exploited_by_cisa_kev"))
    lines = [
        f"## {scope_name}", "",
        f"{len(entries)} vulnerability entries across {len(collected)} systems "
        f"({kev_count} confirmed exploited per CISA KEV). Entries are sorted KEV-confirmed first, then by CVSS. "
        "The written analysis was unavailable this run, so descriptions below are the raw NVD/CISA text.",
        "",
    ]
    if entries:
        lines += ["### Formal Vulnerabilities", ""]
    for system, e in entries:
        score = e.get("cvss_score")
        sev = (e.get("cvss_severity") or "").split(" ")[0].upper() if score is not None else ""
        score_txt = f"{score} {sev}".strip() if score is not None else "UNSCORED"
        kev = e.get("confirmed_exploited_by_cisa_kev")
        lines += [
            f"#### {system} — {e['id']} (CVSS {score_txt})" + (" 🔴 ACTIVELY EXPLOITED (CISA KEV)" if kev else ""),
            f"**Summary:** {(e.get('description') or 'No description provided.').strip()}", "",
            "**Source:**",
            *[f"- {r}" for r in e.get("references", [])[:3]], "",
        ]
        action = e.get("required_action") or e.get("kev_required_action")
        due = e.get("due_date") or e.get("kev_due_date")
        if action:
            lines += ["**Actions:**", f"- Fix: {action}" + (f" (CISA due date: {due})" if due else ""), ""]
    news_lines = [
        f"- **{system}:** [{(i.get('title') or '').strip()}]({i.get('link')}) ({i.get('source')})"
        for system, items in news.items() for i in items if i.get("link")
    ]
    if news_lines:
        lines += ["### News & Community Mentions", "*Unverified chatter, not authoritative.*", "", *news_lines, ""]
    return "\n".join(lines)


def main():
    general_items, collected_by_scope, news_by_scope = collect_all()

    date_str = datetime.date.today().isoformat()
    os.makedirs("reports", exist_ok=True)

    news_rows = [
        ("security-news", "Security News", "row-security",
         render_raw_news_columns_html(group_items_by_source(general_items))),
        ("breach-news", "Breaches & Incidents", "row-breach",
         _fetch_news_row_html(BREACH_NEWS_FEEDS, "Breach")),
        ("devsecops-news", "DevSecOps News", "row-devsecops",
         _fetch_news_row_html(DEVSECOPS_NEWS_FEEDS, "DevSecOps")),
        ("cloud-news", "Cloud News", "row-cloud",
         _fetch_news_row_html(CLOUD_NEWS_FEEDS, "Cloud")),
    ]

    scope_reports = []
    any_scope_had_data = False

    for scope_name in SCOPES:
        collected = collected_by_scope.get(scope_name, {})
        news = news_by_scope.get(scope_name, {})

        if not collected and not news:
            print(f"[i] {scope_name}: nothing to report this run, skipping LLM call")
            continue

        any_scope_had_data = True
        prompt = build_prompt_for_scope(scope_name, collected, news)
        total_entries = sum(len(v) for v in collected.values()) + sum(len(v) for v in news.values())

        result = call_llm(prompt, expected_entry_count=total_entries, label=scope_name)

        if result is None:
            print(f"::warning::{scope_name}: LLM report failed, published the plain-data fallback report instead")
            scope_reports.append(fallback_report_md(scope_name, collected, news))
        else:
            scope_reports.append(result)

    if not any_scope_had_data:
        bottom_md = (
            "No new CVEs, KEV entries, or scope-matched news/forum mentions found "
            "for any tracked scope in the configured lookback windows."
        )
    else:
        bottom_md = "\n\n".join(scope_reports)

    md_out_path = f"reports/{date_str}.md"
    with open(md_out_path, "w") as f:
        f.write(f"# Security Digest — {date_str}\n\n{bottom_md}")
    print(f"[i] Markdown archive written to {md_out_path}")

    docs_dir = "docs"
    write_report_page(news_rows, bottom_md, date_str, docs_dir)
    rebuild_dashboard_index(docs_dir, date_str, news_rows, bottom_md)
    print(f"[i] Dashboard updated: {docs_dir}/index.html")


if __name__ == "__main__":
    main()
