# advisorsai-check

**Does a public page expose the declared machine-readable basics that answer engines can use?**

One command. No API key, no account, no signup.

```bash
git clone https://github.com/manmohm/advisorsai-check.git
cd advisorsai-check
python -m pip install .
advisorsai-check example.com
```

## Use it from Claude or any MCP client — no install

The same bounded public-page check is available as one remote, read-only MCP
tool. You provide one public URL; it returns at most one actionable finding
with an HMAC evidence receipt that the operator can re-verify.

- [Add Advisors AI Store Readiness to Claude](https://claude.ai/customize/connectors?modal=add-custom-connector&connectorName=AdvisorsAI%20Store%20Readiness&connectorUrl=https%3A%2F%2Fadvisorsai.ai%2Fstore-readiness-mcp)
- Official MCP Registry name: `ai.advisorsai/store-readiness`
- Streamable HTTP endpoint: `https://advisorsai.ai/store-readiness-mcp`
- [Inspect the MCP implementation and its operator boundary](MCP.md)

The remote tool does not write to the submitted site, store the result, share
it, infer answer-engine rankings, or predict sales. It is new: there are no
customer case studies yet.

```
advisorsai-check  https://example.com

  ok   page title: «Example — industrial valves since 1994»
  ok   meta description, 153 chars
  MISS no Organization/LocalBusiness structured data: nothing states what this
       business IS in a form machines read
  MISS no Service/Product structured data: what you sell is only in prose
  ok   one <h1>: «Valves that survive the plant floor»
  ok   canonical link with an HTTP(S) href is present
  ok   declared robots policy allows search crawlers on /
       (training/model-use crawlers blocked by policy: GPTBot, Google-Extended)
  note no /llms.txt (informational only: it is not a web standard)
  ok   valid urlset sitemap with 24 locations

  64% of the declared public-page basics checked in this run are in place.
```

## What it checks

| Signal | Why a machine cares |
|---|---|
| `robots.txt` | The site's declared policy for autonomous search crawlers on the submitted path. User-triggered fetchers and training/model-use crawlers are reported separately and never change the score. It does not prove a crawler passes the site's firewall. |
| `llms.txt` | An experimental summary. It is reported but carries no score weight: it is not a web standard, and Google Search says it does not use it. |
| JSON-LD `Organization` | Whether anything states, in a form machines parse, what this business **is**. |
| JSON-LD `Service` / `Product` | Whether what you **sell** exists outside prose. |
| `<title>`, meta description, `<h1>`, canonical | Page fields commonly exposed to parsers. |
| `sitemap.xml` | Whether `/sitemap.xml` has valid `urlset/url/loc` or `sitemapindex/sitemap/loc` records with absolute HTTP(S) locations. |

## What it does not check

It does **not** tell you whether an assistant names you when a buyer asks.

That is not established by a page fetch. It is an observation of live answers,
and establishing it requires timestamped captures against real assistants and
comparison with peers. This tool therefore never relabels its bounded page
checks as a visibility score.

So everything here is a **public-page basic**: a fixable technical condition,
not evidence that an answer engine will cite you. Not a ranking. Not a share.
Not a promise.

## Install from source

```bash
git clone https://github.com/manmohm/advisorsai-check.git
cd advisorsai-check
python -m pip install .
advisorsai-check example.com
```

The package is not yet published to PyPI. Do not use or advertise a
`pip install advisorsai-check` command until the release exists there.
The command-line checker core supports Python 3.9+. The optional remote-server
dependencies require Python 3.10+, and the published server source is for
inspection of the official operator deployment rather than a turn-key
self-hosted promise. The package pins `html5lib==1.1` and
`webencodings==0.6.1` so
malformed HTML is interpreted with one stable HTML5 tree-construction contract
and charset labels follow the WHATWG web-encoding registry. The HTML parser and
fact extractor run in a byte-capped, time-capped child process; there is no
hand-written token or nesting estimator. Home pages must be served as
`text/html`: `application/xhtml+xml` is deliberately rejected because this
tool does not claim an XML parsing contract. Responses must also be an
uncompressed identity representation; unsupported `Content-Encoding` values
are rejected instead of being parsed as HTML bytes.

## Use it in CI

`--json` gives you the full result. Exit code `0` means every checker returned;
`1` means at least one check was unavailable or failed internally; and `2`
means the submitted address was unusable. A partial run publishes `score: null`,
reports weighted `coverage_percent`, and is never a successful process result:

```bash
set -o pipefail
advisorsai-check example.com --json | jq '.score'
```

```yaml
- name: Public-page machine basics
  run: |
    git clone --depth 1 https://github.com/manmohm/advisorsai-check.git /tmp/advisorsai-check
    python -m pip install /tmp/advisorsai-check
    result=$(advisorsai-check "$SITE" --json) || {
      status=$?
      echo "$result"
      exit "$status"
    }
    score=$(printf '%s' "$result" | jq -er '.score')
    echo "Declared public-page basics: $score%"
    [ "$score" -ge 80 ] || { echo "::warning::below 80%"; }
```

## As a library

```python
from advisorsai_check import run

report = run("example.com")
if not report.successful:
    raise RuntimeError(report.errors)
print(report.score)
for signal in report.signals:
    if signal.ok is False:
        print("fix:", signal.detail)
```

`report.successful` is false if any signal is unchecked or any checker raised
an internal error. In that state `report.score` is `None`; use
`report.coverage_percent` to describe how much of the weighted check set ran,
never as a substitute score.
The report vocabulary is closed: every run carries exactly one receipt for
`home`, `title`, `description`, `structured_business`,
`structured_offering`, `h1`, `canonical`, `robots`, `llms_txt`, and
`sitemap`, with weights fixed by the library. `jsonld_valid` is the sole
optional diagnostic and may occur at most once. Missing stages, unknown keys,
duplicates, empty receipts, or changed weights make the report unsuccessful;
they can never yield a score or 100% coverage.
The `home` receipt also pins the six page-derived rows: a checked home failure
requires checked failures for title, description, structured business,
structured offering, H1, and canonical; an unavailable home requires all six
to remain unavailable. The optional `jsonld_valid` row is accepted only as a
negative diagnostic (`false`) after a full home representation was parsed. It
can lower a score but can never act as a positive bonus. Although `home` and
`llms_txt` are zero-weight stage receipts, leaving either unchecked adds a
missing-coverage unit, so a partial run cannot display 100% coverage.
`signal.ok` is `True`, `False`, or `None`. `None` means the check could not run
— a DNS, connection, TLS, or timeout failure, for example. Such failures are
reported as unchecked (`ok: null`), never as evidence that the site failed.
They make the whole run incomplete: `report.successful` is false,
`report.score` is `None`, and `coverage_percent` shows only the weighted share
that actually ran. Status `0` is reserved for this transport/unavailable state.
An HTTP 4xx or 5xx response is different: the site did answer, so it produces a
checked result according to that signal's contract before the checker considers
the error representation's body or `Content-Type`. Thus a home-page 4xx/5xx is
a checked failure even when the body is empty or mislabeled; `robots.txt` keeps
RFC 9309's distinct 4xx/5xx semantics. A page or robots representation is full
only at exact HTTP 200: informational/accepted or partial/delta statuses such
as 202, 206, and 226 are rejected. Redirects to another origin are not followed.

## The first site we pointed it at was our own

It identified a crawler-policy mismatch between the site's intended robots
rules and the rules served at the edge. The lesson is narrower than a ranking
claim: inspect what public crawlers actually receive, not only the file in the
repository.

We had not noticed. The tool found it in one run, which is the entire argument
for running it on yours.

## Who made this

[Advisors AI](https://advisorsai.ai) measures timestamped answer-engine outputs
for a business, and builds systems the client then owns outright. This tool is the
free, honest part: the part you can verify yourself, offline, with the source
in front of you.

The paid part is the part this tool refuses to guess at — what assistants
actually say about you, with the captures to prove it, and what to change.

MIT licensed. Issues and pull requests welcome.
