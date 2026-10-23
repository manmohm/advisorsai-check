# MCP modes

`advisorsai_mcp` exposes the `advisorsai-check` core as a Model Context
Protocol server, so an assistant can measure one public page on request.

## Official remote tool

`advisors_store_readiness_check(url, language="ar"|"en")`

It is read-only and bounded. It takes a credential-free public HTTP(S) page,
measures ten machine-readable signals, and returns **at most one** finding:
the highest-confidence miss, the evidence you can re-check yourself, an
imperative to fix it, and the acceptance condition to re-measure against.
Private networks and non-standard web ports are rejected.

It does not measure -- and will not claim -- whether an assistant mentions a
business, answer-engine ranking or share, or sales probability.

## Local public-page basics over stdio

Install `.[mcp]` from a source checkout and run
`advisorsai-public-page-mcp` (or `python -m advisorsai_check.mcp_stdio`).
The server identifies as `advisorsai-public-page-basics`, version `1.1.0`,
and exposes exactly one local tool: `advisors_public_page_basics_check(url)`.

The only input is `url`: a nonempty string of at most 2048 characters
containing one credential-free public HTTP(S) page or domain; a missing
scheme uses HTTPS. Additional input properties are rejected. The existing
core rejects private/local/reserved/mixed DNS targets and nonstandard ports,
pins validated public addresses, and does not follow cross-origin redirects.
No alternate fetch path or proxy is added by this adapter.

The structured output is the public library report: `url: string`,
`success: boolean`, `score: integer|null`, `coverage_percent: integer`,
`unchecked_count: integer`, `signals: array`, and `errors: string[]`.
Each signal has `key: string`, `ok: boolean|null`, `detail: string`,
`weight: integer` and `evidence: string`. Numeric and completion values come
directly from `advisorsai_check.run`; no score or finding is recalculated.
Text uses the CLI's existing sanitization: terminal control channels are
removed and whitespace normalized. The normalized output URL retains its
query string; do not treat the output as query-redacted. The score is
null when the library report is incomplete. Coverage is not a replacement
score. All report fields are required and extra output properties are forbidden.

The tool's annotations are read-only, nondestructive, idempotent and
open-world. It fetches the requested public page and same-origin robots,
sitemap and llms.txt resources. Fetched detail/evidence is untrusted text.
This English-only report has no `language` parameter and no HMAC receipt,
proof capsule or one-finding remedy contract. It requires no signing key,
account or API key and never forwards the request to the official endpoint.

The official HTTP implementation in `advisorsai_mcp/` and its pinned
receipt key policy remain separate and unchanged.

For a Glama source build, install the optional SDK explicitly with build step
`uv sync --extra mcp`. Plain `uv sync` does not install this extra. The local
child command is `uv run --no-sync advisorsai-public-page-mcp`, under Glama's
managed stdio wrapper if required by its form. It has no proxy or receipt-key
environment setting. This is a proposed build configuration; Python 3.14 and
the Glama build have not been validated by this patch proposal.

## Use the official remote server

The public endpoint is
`https://advisorsai.ai/store-readiness-mcp`. It requires no account and no API
key from the requester. The implementation in this repository is published for
inspection and reproducibility of that official deployment; it is **not
advertised as a turn-key self-hosted server**.

The official service's HMAC receipts assert an Advisors AI-operated key. The
secret material is not distributed. A random 32-character value does not mint
an official receipt: it fails closed because the bundled, non-secret policy
pins the official key fingerprint. A fork operator must deliberately establish
and document a different key policy and trust boundary before minting its own
operator receipts; this release does not provide a policy generator.

The command printed by `python -m advisorsai_mcp.server` names the published
module correctly, but only an operator holding policy-matching key material can
run the receipt-producing deployment. The package, command-line checker and
optional MCP dependencies require Python 3.10 or later.

`ADVISORS_PROOF_REVOCATION_LEDGER` optionally points the official deployment at
a persistent JSONL ledger of revoked receipt ids. It defaults to
`proof-capsule-revocations.jsonl` in the working directory.

### A stated limit on revocation

**A ledger file that does not exist means nothing is treated as revoked.**
Revocation is therefore only as strong as the operator's ledger: point
`ADVISORS_PROOF_REVOCATION_LEDGER` at a real, persistent path if you rely on
it. This is not an artefact of packaging -- it is the behaviour of the
implementation this package is derived from, and it is stated here rather than
diverged from, because a public copy that quietly behaves differently from the
private original is the worse failure.

## On the receipt

The receipt is an HMAC (`entity-hmac-sha256-v2`) carrying a pinned `key_id` and
`policy_version`, not a public-key digital signature: an operator holding the
policy-accepted key re-verifies it. The active key mints receipts; both the
active key and any verification-only (`verify_only`) rotation key verify them.
It is deliberately
described as *a receipt we re-verify* rather than *signed*, because `signed`
would promise third-party verification this scheme cannot give.

## Versions

The source distribution and wheel candidate are version `1.1.0`. The remote
MCP endpoint and its immutable registry record are version `1.0.6`; the server
reports that same version. The HMAC key policy has its own rotation version,
because changing a key policy is not a package or endpoint release.

## Provenance

The modules in `advisorsai_mcp/` are generated from the maintained Advisors AI
server sources, and a parity test runs the server's own suite against the
generated tree. Report issues here; they are fixed at the maintained source and
generated again.
