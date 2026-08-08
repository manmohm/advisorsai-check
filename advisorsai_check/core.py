"""Machine-readability checks for a public website.

WHAT THIS MEASURES, EXACTLY
    Whether the machines that answer questions about your business can READ
    your site: are AI crawlers allowed, is there a machine-readable summary,
    is the business described in structured data, is the offering findable.

WHAT THIS DOES NOT MEASURE — and no free tool can
    Whether an AI assistant actually names you when a buyer asks. That is not
    a property of your HTML; it is an observation of a live answer, and it
    takes real captures against real assistants to establish. Anyone selling a
    number for it from a page fetch is selling a guess.

    So every result here is a READABILITY signal. It is a strong predictor and
    a fixable one, which is why it is worth checking for free. It is not a
    ranking, a share, or a promise, and this module never prints it as one.

No API keys. No account. One HTTP fetch per document, nothing written back.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

USER_AGENT = "advisorsai-check/1.0 (+https://advisorsai.ai)"
TIMEOUT = 15

# The crawlers that feed the assistants a buyer actually asks. Blocking one is
# not a mistake — plenty of businesses choose it deliberately — but it should
# be a CHOICE, and most sites that block them never knew they did.
AI_CRAWLERS = (
    "GPTBot", "OAI-SearchBot", "ChatGPT-User",      # OpenAI
    "ClaudeBot", "Claude-Web", "anthropic-ai",       # Anthropic
    "PerplexityBot", "Perplexity-User",              # Perplexity
    "Google-Extended",                               # Google (Gemini grounding)
    "Applebot-Extended",                             # Apple
    "CCBot",                                         # Common Crawl
    "Bytespider", "Amazonbot", "meta-externalagent",
)


@dataclass
class Signal:
    """One checked fact. `ok` is None when the check could not be run."""
    key: str
    ok: bool | None
    detail: str
    weight: int = 1
    evidence: str = ""


@dataclass
class Report:
    url: str
    signals: list[Signal] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def scored(self) -> list[Signal]:
        return [s for s in self.signals if s.ok is not None]

    @property
    def score(self) -> int:
        """Percent of the weight that could be checked and passed.

        Unrunnable checks are excluded from BOTH sides rather than counted as
        failures. A network hiccup is not a finding about the site, and a score
        that quietly folds one in is a number that lies.
        """
        total = sum(s.weight for s in self.scored)
        if not total:
            return 0
        got = sum(s.weight for s in self.scored if s.ok)
        return round(100 * got / total)

    @property
    def unchecked(self) -> list[Signal]:
        return [s for s in self.signals if s.ok is None]


def _get(url: str) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            raw = r.read(2_000_000)
            charset = r.headers.get_content_charset() or "utf-8"
            return r.status, raw.decode(charset, "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:                                    # noqa: BLE001
        return 0, ""


def normalise(url: str) -> str:
    url = url.strip()
    if not re.match(r"(?i)^https?://", url):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc or "." not in parsed.netloc:
        raise ValueError(f"not a site address: {url}")
    return url


# ── individual checks ──────────────────────────────────────────────────────
def check_robots(base: str) -> list[Signal]:
    status, body = _get(urljoin(base, "/robots.txt"))
    if status == 0:
        return [Signal("robots", None, "robots.txt could not be fetched", 2)]
    if status == 404:
        # No robots.txt means nothing is disallowed. That is permissive, which
        # is what we are checking for, so it passes — with the reason stated.
        return [Signal("robots", True,
                       "no robots.txt, so nothing is disallowed", 2)]

    blocked: list[str] = []
    current: list[str] = []
    disallow_all = False
    for line in body.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            current = []
            continue
        field_, _, value = line.partition(":")
        field_, value = field_.strip().lower(), value.strip()
        if field_ == "user-agent":
            current.append(value)
        elif field_ == "disallow" and value == "/":
            for agent in current:
                if agent == "*":
                    disallow_all = True
                elif any(agent.lower() == c.lower() for c in AI_CRAWLERS):
                    blocked.append(agent)
    if disallow_all:
        blocked.append("* (every crawler)")
    if blocked:
        return [Signal("robots", False,
                       "robots.txt blocks: " + ", ".join(sorted(set(blocked))),
                       2, evidence="/robots.txt")]
    return [Signal("robots", True, "AI crawlers are not blocked", 2)]


def check_llms_txt(base: str) -> list[Signal]:
    status, body = _get(urljoin(base, "/llms.txt"))
    if status == 0:
        return [Signal("llms_txt", None, "/llms.txt could not be fetched", 2)]
    ok = status == 200 and len(body.strip()) > 200
    return [Signal(
        "llms_txt", ok,
        "a machine-readable summary is published at /llms.txt" if ok
        else "no /llms.txt: assistants read your marketing HTML instead of a "
             "summary you control",
        2, evidence="/llms.txt")]


def check_sitemap(base: str) -> list[Signal]:
    status, _ = _get(urljoin(base, "/sitemap.xml"))
    if status == 0:
        return [Signal("sitemap", None, "sitemap could not be fetched")]
    ok = status == 200
    return [Signal("sitemap", ok,
                   "sitemap.xml is published" if ok else "no sitemap.xml",
                   1, evidence="/sitemap.xml")]


_JSONLD = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.S | re.I)


def check_home(base: str) -> list[Signal]:
    status, html = _get(base)
    if status == 0 or not html:
        return [Signal("home", None, f"the home page could not be read "
                                     f"(HTTP {status})", 3)]
    out = [Signal("home", True, f"home page reachable (HTTP {status})", 0)]

    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
    text = re.sub(r"\s+", " ", title.group(1)).strip() if title else ""
    out.append(Signal("title", bool(text) and len(text) > 10,
                      f"page title: «{text[:70]}»" if text
                      else "no <title>: the assistant has no name for the page",
                      1))

    desc = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\'](.*?)["\']',
        html, re.S | re.I)
    dtext = re.sub(r"\s+", " ", desc.group(1)).strip() if desc else ""
    out.append(Signal("description", len(dtext) >= 50,
                      f"meta description, {len(dtext)} chars" if dtext
                      else "no meta description",
                      1))

    types: set[str] = set()
    for block in _JSONLD.findall(html):
        try:
            data = json.loads(block)
        except json.JSONDecodeError:
            out.append(Signal("jsonld_valid", False,
                              "a JSON-LD block does not parse, so machines "
                              "skip it entirely", 1))
            continue
        for node in (data.get("@graph") if isinstance(data, dict) else None) \
                or (data if isinstance(data, list) else [data]):
            if isinstance(node, dict) and node.get("@type"):
                t = node["@type"]
                types.update(t if isinstance(t, list) else [t])
    business = {"Organization", "LocalBusiness", "Corporation", "Store",
                "ProfessionalService"} & types
    out.append(Signal("structured_business", bool(business),
                      f"structured data identifies the business ({', '.join(sorted(business))})"
                      if business else
                      "no Organization/LocalBusiness structured data: nothing "
                      "states what this business IS in a form machines read",
                      2))
    offering = {"Service", "Product", "Offer", "OfferCatalog"} & types
    out.append(Signal("structured_offering", bool(offering),
                      f"structured data names what you sell ({', '.join(sorted(offering))})"
                      if offering else
                      "no Service/Product structured data: what you sell is "
                      "only in prose",
                      2))

    h1 = re.findall(r"<h1[^>]*>(.*?)</h1>", html, re.S | re.I)
    h1_text = [re.sub(r"<[^>]+>|\s+", " ", h).strip() for h in h1]
    h1_text = [h for h in h1_text if h]
    out.append(Signal("h1", len(h1_text) == 1,
                      f"one <h1>: «{h1_text[0][:60]}»" if len(h1_text) == 1
                      else f"{len(h1_text)} <h1> elements"
                           if h1_text else "no <h1>",
                      1))

    canonical = re.search(r'<link[^>]+rel=["\']canonical["\']', html, re.I)
    out.append(Signal("canonical", bool(canonical),
                      "canonical link present" if canonical
                      else "no canonical link", 1))
    return out


def run(url: str) -> Report:
    base = normalise(url)
    report = Report(url=base)
    for check in (check_home, check_robots, check_llms_txt, check_sitemap):
        try:
            report.signals.extend(check(base))
        except Exception as exc:                          # noqa: BLE001
            report.errors.append(f"{check.__name__}: {type(exc).__name__}")
    return report
