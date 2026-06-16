# Changelog

All notable changes to AIVA are documented here.

## [2.0.0]

A major upgrade focused on deeper coverage, smarter scoring, and CI/reporting integration.

### Added
- **Multi-turn / conversational probes.** Attacks that build across turns (rule
  injection, override-after-priming, privilege escalation, jailbreak crescendo). The
  target adapter now supports full conversation history.
- **Expanded probe library** (now ~35 built-in probes, up from 19):
  - Prompt injection: zero-width/unicode smuggling, homoglyph override, multilingual
    injection, ChatML/special-token injection, code-block payloads.
  - System-prompt leakage: configuration-summary leak.
  - Sensitive disclosure: internal-infrastructure disclosure.
  - Improper output handling: SSRF-URL, SQL-statement, and template-injection emission
    (in addition to XSS/active-content and markdown/link injection).
  - Excessive agency: multi-turn privilege escalation.
  - Jailbreak: format-lock + refusal-suppression, and a multi-turn crescendo.
  - Unbounded consumption: large-input handling.
  - Misinformation: fabricated-citation check.
- **Risk scoring**: a 0–100 risk score, an A–F letter grade, and a **guardrail-robustness**
  metric (% of injection/jailbreak probes blocked) per target, plus an aggregate summary.
- **Baseline diff** (`--baseline prior.json`): flags findings as **NEW** / **EXISTING** and
  reports which previous findings are now **FIXED** — ideal for CI regression gating.
- **New report formats**: **SARIF** (`--sarif`, for the GitHub code-scanning / Security tab)
  and **Markdown** (`--md`, for issues/PRs), alongside the existing JSON and HTML.
- **Streaming (SSE) support** (`--stream`) for endpoints that only return server-sent /
  newline-delimited streaming responses.
- **Expanded secret/PII detection**: GitHub, Slack, Google, Stripe, and Anthropic key
  formats, plus an **entropy-based generic secret finder**.
- **Audit log** (`--log-file`): a JSONL record of every request/response for evidence.
- **Bounded concurrency** (`--concurrency N`) to speed up probing (default 1, stays gentle).
- **Config files** (`--config aiva.json`) to provide defaults for any option.
- Expanded infrastructure recon: more serving-framework fingerprints and exposed-endpoint
  checks (`/api/ps`, `/metrics`, `/v1/internal/model/info`, …) and more CVE reference notes.
- Quality-of-life: `--version`, `--quiet`, an end-of-run aggregate summary, and a new
  `output` detector (markup + SSRF + SQL + template) usable from `--probes-file`.

### Changed
- The `active` detector is superseded by `output` (still accepted as an alias for BYO probes).
- Banner now reports the version and is rendered at a uniform width.

### Safety
- All built-in probes remain **benign** (canary-based); AIVA ships **no harmful payloads**.
  Sensitive content categories remain bring-your-own via `--probes-file`.

## [1.0.0]
- Initial release: OWASP LLM Top 10 probing (19 probes), OpenAI/Ollama/raw adapters,
  infrastructure recon with NVD CVE correlation, AI-judge option, JSON/HTML reports,
  console output, and the `aiva` command.
