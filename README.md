# advisorsai-check

**Can the AI assistants that answer your buyers' questions actually read your website?**

One command. No API key, no account, no signup.

```bash
pipx run advisorsai-check example.com
```

```
advisorsai-check  https://example.com

  ok   page title: «Example — industrial valves since 1994»
  ok   meta description, 153 chars
  MISS no Organization/LocalBusiness structured data: nothing states what this
       business IS in a form machines read
  MISS no Service/Product structured data: what you sell is only in prose
  ok   one <h1>: «Valves that survive the plant floor»
  ok   canonical link present
  MISS robots.txt blocks: ClaudeBot, GPTBot, Google-Extended
  MISS no /llms.txt: assistants read your marketing HTML instead of a summary
       you control
  ok   sitemap.xml is published

  56% of the machine-readability signals we can check from outside are in place.
```

## What it checks

| Signal | Why a machine cares |
|---|---|
| `robots.txt` | Whether GPTBot, ClaudeBot, PerplexityBot, Google-Extended and friends are allowed in at all. Plenty of sites block them by accident, through a default they never chose. |
| `llms.txt` | A short, machine-readable summary you control. Without it, an assistant builds its idea of you out of your marketing HTML. |
| JSON-LD `Organization` | Whether anything states, in a form machines parse, what this business **is**. |
| JSON-LD `Service` / `Product` | Whether what you **sell** exists outside prose. |
| `<title>`, meta description, `<h1>`, canonical | The basics an extractor reads first. |
| `sitemap.xml` | Whether the rest of the site is discoverable at all. |

## What it does not check, and why no free tool can

It does **not** tell you whether an assistant names you when a buyer asks.

That is not a property of your HTML. It is an observation of a live answer, and
establishing it takes real, timestamped captures against real assistants,
compared against your peers. Any tool that reads your page and hands back a
"visibility score" for AI answers is reporting a guess with a decimal point on it.

So everything here is a **readability** signal: a strong, fixable predictor of
whether you can be cited. Not a ranking. Not a share. Not a promise.

## Install

```bash
pip install advisorsai-check
```

Python 3.9+. Zero dependencies — standard library only, so it drops into any
environment and any CI job without pulling a tree behind it.

## Use it in CI

`--json` gives you the full result, and the exit code is `0` unless the address
itself was unusable, so you can gate on whatever threshold you choose:

```bash
advisorsai-check example.com --json | jq '.score'
```

```yaml
- name: AI readability
  run: |
    pip install advisorsai-check
    score=$(advisorsai-check "$SITE" --json | jq '.score')
    echo "AI readability: $score%"
    [ "$score" -ge 80 ] || { echo "::warning::below 80%"; }
```

## As a library

```python
from advisorsai_check import run

report = run("example.com")
print(report.score)
for signal in report.signals:
    if signal.ok is False:
        print("fix:", signal.detail)
```

`signal.ok` is `True`, `False`, or `None`. `None` means the check could not run
— a fetch failed, say. Those are excluded from the score on **both** sides
rather than counted as failures, because a network hiccup is not a finding
about your site, and a score that quietly folds one in is a number that lies.

## The first site we pointed it at was our own

It scored 85% and named one cause: Cloudflare was injecting a managed
`robots.txt` block above ours, disallowing `GPTBot`, `ClaudeBot`,
`Google-Extended` and five others — on the site of a company whose product is
being found inside AI answers. Our own `robots.txt` welcomed them. The injected
block sat above it and won.

We had not noticed. The tool found it in one run, which is the entire argument
for running it on yours.

## Who made this

[Advisors AI](https://advisorsai.ai) measures how AI answer engines see a
business, and builds systems the client then owns outright. This tool is the
free, honest part: the part you can verify yourself, offline, with the source
in front of you.

The paid part is the part this tool refuses to guess at — what assistants
actually say about you, with the captures to prove it, and what to change.

MIT licensed. Issues and pull requests welcome.
