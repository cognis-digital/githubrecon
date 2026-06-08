# Demo 01 — basic scan

You run security/forensics for **ACME Labs** and you own these repos. You pulled a
GitHub API export of the org's footprint (repos + contributors + a sample of
tracked files) and want to know what credentials have leaked into source.

> Defensive use only: run GITHUBRECON against exports of accounts/orgs you own or
> are authorized to analyze. Secrets in the report are masked; rotate any exposed
> credential immediately.

## Input

`export.json` — a GitHub API-shaped export for the `acme-labs` org with three repos:

- `payments-api` (public) — a committed `.env` and a `config.py` with real-looking
  tokens (Stripe live key, AWS secret, GitHub PAT, Slack token). One value is an
  obvious placeholder (`your_api_key_here`) that the tool should *not* flag.
- `legacy-site` (public, last pushed 2023) — a committed SSH private key, and it is
  stale (>365d) so it also raises a footprint hygiene note.
- `internal-tools` (private) — clean.

## Run it

```sh
# Human-readable table (default)
python -m githubrecon scan demos/01-basic/export.json

# JSON for pipelines
python -m githubrecon scan demos/01-basic/export.json --format json

# Self-contained shareable HTML report (the tool's UI)
python -m githubrecon scan demos/01-basic/export.json --format html -o report.html
```

## What to expect

- Critical/high findings for the Stripe live key, AWS secret, GitHub PAT, Slack
  token, the SSH private key, and the committed `.env` / `id_rsa` files.
- The placeholder `your_api_key_here` is suppressed (no false positive).
- A footprint summary: 3 repos (1 private), contributors `alice-dev`, `bob-ops`,
  `carol-legacy`, plus discovered emails.
- A stale-public-repo INFO note for `legacy-site` (last push 2023).
- Exit code `1` because findings exist. Use `--fail-on critical` to gate CI on the
  worst class only.
