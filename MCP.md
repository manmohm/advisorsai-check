# Store-readiness MCP server

`advisorsai_mcp` exposes the `advisorsai-check` core as a Model Context
Protocol server, so an assistant can measure one public page on request.

## The tool

`advisors_store_readiness_check(url, language="ar"|"en")`

It is read-only and bounded. It takes a credential-free public HTTP(S) page,
measures ten machine-readable signals, and returns **at most one** finding:
the highest-confidence miss, the evidence you can re-check yourself, an
imperative to fix it, and the acceptance condition to re-measure against.
Private networks and non-standard web ports are rejected.

It does not measure -- and will not claim -- whether an assistant mentions a
business, answer-engine ranking or share, or sales probability.

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
run the receipt-producing deployment. The optional MCP dependencies require
Python 3.10 or later; the command-line checker core continues to support Python
3.9 or later.

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
